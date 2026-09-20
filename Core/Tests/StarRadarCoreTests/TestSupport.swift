import Foundation
@testable import StarRadarCore

/// 手工拼一个 TGCP 帧，用来喂给中间人会话。
/// 布局严格按 [TGCP] 里的偏移：magic(2) + 未知(4) + command(2) + gate(1) + sequence(4)
/// + header_len(4) + body_len(4) [+ RawDH 扩展] + body
func makeTGCPFrame(
    command: UInt16,
    gate: UInt8 = 0,
    sequence: UInt32 = 1,
    dhPublic: [UInt8]? = nil,
    body: [UInt8] = []
) -> [UInt8] {
    var header: [UInt8] = TGCP.magic
    header.append(contentsOf: [UInt8](repeating: 0, count: 4))
    ByteCoding.appendUInt16BE(command, to: &header)
    header.append(gate)
    ByteCoding.appendUInt32BE(sequence, to: &header)
    ByteCoding.appendUInt32BE(0, to: &header) // header_len 占位
    ByteCoding.appendUInt32BE(0, to: &header) // body_len 占位
    if let dhPublic {
        header.append(TGCP.rawDHType)
        ByteCoding.appendUInt16BE(UInt16(dhPublic.count), to: &header)
        header.append(contentsOf: dhPublic)
    }
    ByteCoding.writeUInt32BE(UInt32(header.count), into: &header, at: TGCP.headerLengthOffset)
    ByteCoding.writeUInt32BE(UInt32(body.count), into: &header, at: TGCP.bodyLengthOffset)
    return header + body
}

func splitFrames(_ bytes: [UInt8]) throws -> [TGCPFrame] {
    try TGCPFramer().feed(bytes)
}

func singleFrame(_ bytes: [UInt8]) throws -> TGCPFrame {
    let frames = try splitFrames(bytes)
    guard frames.count == 1 else {
        throw TestFailure("期望恰好 1 帧，实际 \(frames.count)")
    }
    return frames[0]
}

struct TestFailure: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}
