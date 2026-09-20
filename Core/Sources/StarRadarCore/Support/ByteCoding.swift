import Foundation

/// 大端读写辅助。越界一律返回 0 而不是崩溃 —— 这里的输入全部来自网络，
/// 调用方必须先校验长度，这里只做兜底。
enum ByteCoding {
    @inline(__always)
    static func readUInt8(_ bytes: [UInt8], _ offset: Int) -> UInt8 {
        guard offset >= 0, offset < bytes.count else { return 0 }
        return bytes[offset]
    }

    @inline(__always)
    static func readUInt16BE(_ bytes: [UInt8], _ offset: Int) -> UInt16 {
        guard offset >= 0, offset + 2 <= bytes.count else { return 0 }
        return (UInt16(bytes[offset]) << 8) | UInt16(bytes[offset + 1])
    }

    @inline(__always)
    static func readUInt32BE(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        guard offset >= 0, offset + 4 <= bytes.count else { return 0 }
        return (UInt32(bytes[offset]) << 24)
            | (UInt32(bytes[offset + 1]) << 16)
            | (UInt32(bytes[offset + 2]) << 8)
            | UInt32(bytes[offset + 3])
    }

    @inline(__always)
    static func writeUInt16BE(_ value: UInt16, into bytes: inout [UInt8], at offset: Int) {
        guard offset >= 0, offset + 2 <= bytes.count else { return }
        bytes[offset] = UInt8(truncatingIfNeeded: value >> 8)
        bytes[offset + 1] = UInt8(truncatingIfNeeded: value)
    }

    @inline(__always)
    static func writeUInt32BE(_ value: UInt32, into bytes: inout [UInt8], at offset: Int) {
        guard offset >= 0, offset + 4 <= bytes.count else { return }
        bytes[offset] = UInt8(truncatingIfNeeded: value >> 24)
        bytes[offset + 1] = UInt8(truncatingIfNeeded: value >> 16)
        bytes[offset + 2] = UInt8(truncatingIfNeeded: value >> 8)
        bytes[offset + 3] = UInt8(truncatingIfNeeded: value)
    }

    @inline(__always)
    static func appendUInt16BE(_ value: UInt16, to bytes: inout [UInt8]) {
        bytes.append(UInt8(truncatingIfNeeded: value >> 8))
        bytes.append(UInt8(truncatingIfNeeded: value))
    }

    @inline(__always)
    static func appendUInt32BE(_ value: UInt32, to bytes: inout [UInt8]) {
        bytes.append(UInt8(truncatingIfNeeded: value >> 24))
        bytes.append(UInt8(truncatingIfNeeded: value >> 16))
        bytes.append(UInt8(truncatingIfNeeded: value >> 8))
        bytes.append(UInt8(truncatingIfNeeded: value))
    }

    /// 去掉前导零；全零时保留一个字节。对应原实现的 `minimal_be`。
    static func minimalBigEndian(_ bytes: [UInt8]) -> [UInt8] {
        var index = 0
        while index + 1 < bytes.count && bytes[index] == 0 {
            index += 1
        }
        return Array(bytes[index...])
    }

    static func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }
}
