import CryptoKit
import Foundation

/// 从明文里捞出来的 128 字节候选密钥。
///
/// 注意语义：**候选不等于可用**。原实现的 CandidateStore 特意不声明算法，
/// 必须由下游用真实 UDP 战斗包验证通过后才能真正拿来解密。
public struct MaterialCandidate: Equatable {
    public let digest: String
    public let material: [UInt8]
    public let layer: String
    public let offset: Int
}

/// 明文层次 + base64 候选扫描，对应原实现的 `inspection_layers` 与 `BASE64_RUN`。
public enum MaterialExtractor {
    /// 战斗密钥 material 固定 128 字节
    public static let materialLength = 128
    /// 原实现对明文长度设了上限才尝试解压
    public static let inspectionLimit = 524_288

    /// 与原实现完全一致的模式：前后不能邻接 base64 字符，长度 160…220，最多 2 个填充符
    private static let pattern = "(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{160,220}={0,2})(?![A-Za-z0-9+/=])"
    private static let regex = try? NSRegularExpression(pattern: pattern)

    /// 待检视的层次：原文，以及原文本身是 raw LZ4 块时解压出来的内容
    public static func layers(_ plain: [UInt8]) -> [(data: [UInt8], name: String)] {
        var out: [(data: [UInt8], name: String)] = [(plain, "plain")]
        if plain.isEmpty || plain.count > inspectionLimit { return out }
        guard let expanded = LZ4Payload.decompressIfNeeded(plain), expanded != plain else {
            return out
        }
        out.append((expanded, "lz4"))
        return out
    }

    public static func candidates(in plain: [UInt8]) -> [MaterialCandidate] {
        guard let regex else { return [] }
        var out: [MaterialCandidate] = []
        for layer in layers(plain) {
            // base64 字母表全是 ASCII，非 ASCII 字节会被替换成 U+FFFD，
            // 正好起到「分隔符」的作用，划分边界与按字节正则一致。
            let text = String(decoding: layer.data, as: UTF8.self)
            let full = NSRange(text.startIndex..<text.endIndex, in: text)
            for match in regex.matches(in: text, range: full) {
                guard let range = Range(match.range(at: 1), in: text) else { continue }
                guard let decoded = Data(base64Encoded: String(text[range])) else { continue }
                guard decoded.count == materialLength else { continue }
                let digest = SHA256.hash(data: decoded)
                    .map { String(format: "%02x", $0) }
                    .joined()
                out.append(MaterialCandidate(
                    digest: digest,
                    material: [UInt8](decoded),
                    layer: layer.name,
                    offset: text.distance(from: text.startIndex, to: range.lowerBound)
                ))
            }
        }
        return out
    }
}
