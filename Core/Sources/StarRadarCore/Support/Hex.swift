import Foundation

/// 十六进制编解码。
///
/// 与 `ByteCoding.hex` 的区别：那个是内部的日志助手，只接受 `[UInt8]`；
/// 这里要能吃 `SHA256Digest`、`HMAC<SHA256>.MAC` 这类 CryptoKit 的字节序列，
/// 所以 `encode` 收 `Sequence<UInt8>`。全部按 ASCII 处理 —— Unicode 里
/// 全角 Ａ-Ｆ 也带 Hex_Digit 属性，`Character.isHexDigit` 会把它们当合法字符，
/// 从而放过一批「看着像 hex 其实不是」的输入，解密端必然对不上。
enum Hex {
    /// 小写十六进制。
    static func encode<Bytes: Sequence>(_ bytes: Bytes) -> String where Bytes.Element == UInt8 {
        var out = ""
        out.reserveCapacity(bytes.underestimatedCount * 2)
        for byte in bytes {
            out.append(digit(byte >> 4))
            out.append(digit(byte & 0x0F))
        }
        return out
    }

    /// 严格 ASCII hex。长度为奇数、或含任何非 `[0-9a-fA-F]` 字符即失败。
    static func decode(_ text: String) -> [UInt8]? {
        let bytes = Array(text.utf8)
        guard bytes.count % 2 == 0 else { return nil }
        var out: [UInt8] = []
        out.reserveCapacity(bytes.count / 2)
        var index = 0
        while index < bytes.count {
            guard let high = value(of: bytes[index]),
                  let low = value(of: bytes[index + 1]) else { return nil }
            out.append((high << 4) | low)
            index += 2
        }
        return out
    }

    /// 单个 ASCII 字符转数值，仅接受 `0-9a-fA-F`。
    static func value(of byte: UInt8) -> UInt8? {
        switch byte {
        case 0x30...0x39: return byte - 0x30          // '0'-'9'
        case 0x61...0x66: return byte - 0x61 + 10     // 'a'-'f'
        case 0x41...0x46: return byte - 0x41 + 10     // 'A'-'F'
        default: return nil
        }
    }

    private static func digit(_ value: UInt8) -> Character {
        Character(UnicodeScalar(value < 10 ? 0x30 + value : 0x61 + value - 10))
    }
}
