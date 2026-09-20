import Foundation

public enum TGCPError: Error, CustomStringConvertible {
    case magicMismatch(offset: Int)
    case invalidHeaderLength(Int)
    case invalidFrameLength(Int)
    case dhExtensionTooShort(Int)
    case unexpectedDHType(UInt8)
    case invalidPublicLength(Int)
    case publicExceedsHeader

    public var description: String {
        switch self {
        case .magicMismatch(let offset): return "TGCP 魔数不匹配，流偏移 \(offset)"
        case .invalidHeaderLength(let value): return "TGCP 头长度非法：\(value)"
        case .invalidFrameLength(let value): return "TGCP 帧长度非法：\(value)"
        case .dhExtensionTooShort(let size): return "DH 头扩展不足 3 字节：\(size)"
        case .unexpectedDHType(let kind): return "DH 类型 \(kind)，期望 RawDH 类型 3"
        case .invalidPublicLength(let size): return "DH 公钥长度非法：\(size)"
        case .publicExceedsHeader: return "DH 公钥越过头部边界"
        }
    }
}

/// TGCP 分帧常量与头扩展读写。
///
/// 头布局来自原实现各 property 的字段偏移（逐个反汇编核对过）：
///
/// ```
///  0 .. 2   magic        ASCII "3f"
///  2 .. 6   未知         原实现未使用
///  6 .. 8   command      UInt16 大端
///  8 .. 9   gate         UInt8
///  9 .. 13  sequence     UInt32 大端
/// 13 .. 17  header_len   UInt32 大端，含扩展在内的总头长
/// 17 .. 21  body_len     UInt32 大端
/// 21 ..     ext          RawDH 扩展
/// ```
public enum TGCP {
    /// 原实现写作 `b'3f'`，即 ASCII 的两个字节，不是 0x3f
    public static let magic: [UInt8] = [0x33, 0x66]

    public static let fixedHeaderSize = 21
    public static let commandOffset = 6
    public static let gateOffset = 8
    public static let sequenceOffset = 9
    public static let headerLengthOffset = 13
    public static let bodyLengthOffset = 17
    public static let extensionOffset = 21

    public static let maxHeaderLength = 65_536
    public static let maxFrameLength = 4_194_304

    public static let rawDHType: UInt8 = 3
    public static let publicBytesMax = 64

    public static let commandClientHello: UInt16 = 0x1001
    public static let commandServerHello: UInt16 = 0x1002
    /// 登录后下发战斗材料的指令（原实现里判的是 16403）
    public static let commandMaterial: UInt16 = 0x4013

    /// 原生 AES 固定 IV：0x00 … 0x0f
    public static let nativeIV: [UInt8] = (0..<16).map { UInt8($0) }

    /// 明文尾标，紧跟在填充字节之前
    public static let trailerMarker: [UInt8] = Array("tsf4g".utf8)
    /// 尾标 5 字节 + 填充计数字节
    public static let trailerSize = 6

    public static func commandName(_ command: UInt16) -> String {
        String(format: "0x%04x", command)
    }
}

/// 一个完整的 TGCP 帧：定长头 + 扩展、以及报文体
public struct TGCPFrame {
    public let header: [UInt8]
    public let body: [UInt8]
    /// 该帧在整条流里的起始偏移，仅用于日志定位
    public let streamOffset: Int

    public init(header: [UInt8], body: [UInt8], streamOffset: Int) {
        self.header = header
        self.body = body
        self.streamOffset = streamOffset
    }

    public var command: UInt16 { ByteCoding.readUInt16BE(header, TGCP.commandOffset) }
    public var gate: UInt8 { ByteCoding.readUInt8(header, TGCP.gateOffset) }
    public var sequence: UInt32 { ByteCoding.readUInt32BE(header, TGCP.sequenceOffset) }
    public var headerLength: Int { header.count }
    public var bodyLength: Int { body.count }
    public var commandText: String { TGCP.commandName(command) }

    /// 头扩展（RawDH 部分）
    public var ext: [UInt8] {
        header.count > TGCP.extensionOffset ? Array(header[TGCP.extensionOffset...]) : []
    }

    /// 重新打包。只换报文体的场合，头里的 body_len 会被回写。
    public func packed(header newHeader: [UInt8]? = nil, body newBody: [UInt8]? = nil) -> [UInt8] {
        var out = newHeader ?? header
        let payload = newBody ?? body
        ByteCoding.writeUInt32BE(UInt32(payload.count), into: &out, at: TGCP.bodyLengthOffset)
        out.append(contentsOf: payload)
        return out
    }

    /// 换掉报文体但仍保持帧结构，头里的 body_len 同步回写。
    /// 中间人重加密后要拿到「一个改过 body 的帧」而不是裸字节，故与 `packed` 区分开。
    public func replacingBody(_ newBody: [UInt8]) -> TGCPFrame {
        var newHeader = header
        ByteCoding.writeUInt32BE(UInt32(newBody.count), into: &newHeader, at: TGCP.bodyLengthOffset)
        return TGCPFrame(header: newHeader, body: newBody, streamOffset: streamOffset)
    }
}

/// DH 公钥在头里的位置与取值
public struct TGCPDHField {
    public let value: BigUInt
    /// 公钥字节在头里的区间，替换时需要
    public let range: Range<Int>
}

extension TGCP {
    /// 解析头扩展里的 RawDH 公钥
    public static func parseDHPublic(header: [UInt8]) throws -> TGCPDHField {
        let ext = header.count > extensionOffset ? Array(header[extensionOffset...]) : []
        guard ext.count >= 3 else {
            throw TGCPError.dhExtensionTooShort(ext.count)
        }
        let kind = ext[0]
        guard kind == rawDHType else {
            throw TGCPError.unexpectedDHType(kind)
        }
        let publicLength = Int(ByteCoding.readUInt16BE(ext, 1))
        guard publicLength >= 1, publicLength <= publicBytesMax else {
            throw TGCPError.invalidPublicLength(publicLength)
        }
        let begin = extensionOffset + 3
        let end = begin + publicLength
        guard end <= header.count else {
            throw TGCPError.publicExceedsHeader
        }
        return TGCPDHField(
            value: BigUInt(bigEndianBytes: Array(header[begin..<end])),
            range: begin..<end
        )
    }

    /// 用 `replacement` 替换头里的公钥，并回写头长。对应原实现的 `replace_dh_public`。
    public static func replacingDHPublic(header: [UInt8], with replacement: [UInt8]) throws -> [UInt8] {
        let field = try parseDHPublic(header: header)
        guard replacement.count >= 1, replacement.count <= publicBytesMax else {
            throw TGCPError.invalidPublicLength(replacement.count)
        }
        var out = header
        ByteCoding.writeUInt16BE(UInt16(replacement.count), into: &out, at: extensionOffset + 1)
        out.replaceSubrange(field.range, with: replacement)
        ByteCoding.writeUInt32BE(UInt32(out.count), into: &out, at: headerLengthOffset)
        return out
    }
}

/// 增量分帧器。喂多少字节都行，返回这次能拼出的完整帧。
public final class TGCPFramer {
    private var buffer: [UInt8] = []
    public private(set) var streamOffset = 0

    public init() {}

    public var pendingBytes: Int { buffer.count }

    public func feed(_ data: [UInt8]) throws -> [TGCPFrame] {
        guard !data.isEmpty else { return [] }
        buffer.append(contentsOf: data)

        var frames: [TGCPFrame] = []
        while true {
            guard buffer.count >= TGCP.fixedHeaderSize else { break }
            guard Array(buffer[0..<2]) == TGCP.magic else {
                throw TGCPError.magicMismatch(offset: streamOffset)
            }
            let headerLength = Int(ByteCoding.readUInt32BE(buffer, TGCP.headerLengthOffset))
            let bodyLength = Int(ByteCoding.readUInt32BE(buffer, TGCP.bodyLengthOffset))
            guard headerLength >= TGCP.fixedHeaderSize, headerLength <= TGCP.maxHeaderLength else {
                throw TGCPError.invalidHeaderLength(headerLength)
            }
            let total = headerLength + bodyLength
            guard total <= TGCP.maxFrameLength else {
                throw TGCPError.invalidFrameLength(total)
            }
            guard buffer.count >= total else { break }

            frames.append(TGCPFrame(
                header: Array(buffer[0..<headerLength]),
                body: Array(buffer[headerLength..<total]),
                streamOffset: streamOffset
            ))
            buffer.removeFirst(total)
            streamOffset += total
        }
        return frames
    }
}

/// LZ4 解压（原生报文体里可能是 raw LZ4 块）。
/// 对应原实现的 `maybe_decompress_lz4`：失败不抛错，只表示「不是 LZ4」。
public enum LZ4Payload {
    public static let maxDecompressedSize = 4_194_304

    /// 返回 `(解压结果, 说明)`，说明取值沿用原实现：
    /// 成功为 `lz4.block`，失败为 `lz4 failed: …`。原实现还有「lz4 模块缺失」一态，
    /// Swift 侧走系统 Compression 框架，不存在这一态。
    ///
    /// 说明文字会被写进压缩事件日志（`result` 字段），所以要带上失败原因。
    public static func decompress(_ data: [UInt8]) -> (data: [UInt8]?, note: String) {
        guard !data.isEmpty else { return (nil, "lz4 failed: empty input") }
        do {
            return (try LZ4Block.decompress(data, maxSize: maxDecompressedSize), "lz4.block")
        } catch {
            return (nil, "lz4 failed: \(error)")
        }
    }

    public static func decompressIfNeeded(_ data: [UInt8]) -> [UInt8]? {
        decompress(data).data
    }
}
