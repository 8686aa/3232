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
    /// 命中处在所在层里的**字节**偏移
    public let offset: Int
    /// 命中处前后各 `contextRadius` 字节的上下文，原实现随候选一起交给下游。
    /// 材料往往夹在半截 protobuf 里，只给 128 字节没法判断它属于哪条指令字段。
    public let context: [UInt8]
}

/// 明文层次 + base64 候选扫描，对应原实现的 `inspection_layers` 与 `BASE64_RUN`。
public enum MaterialExtractor {
    /// 战斗密钥 material 固定 128 字节
    public static let materialLength = 128
    /// 原实现对明文长度设了上限才尝试解压
    public static let inspectionLimit = 524_288
    /// 候选上下文的半径，与原实现一致
    public static let contextRadius = 2048

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
            // 按 Latin-1 解码：每个字节恰好落成一个 UTF-16 单元，于是 NSRange 的偏移就是**字节**偏移
            // —— 原实现是在 bytes 上跑正则，给的也是字节偏移。
            // 之前用 UTF-8 解码，非 ASCII 字节被折成单个 U+FFFD，偏移量会偏小。
            guard let text = String(data: Data(layer.data), encoding: .isoLatin1) else { continue }
            let full = NSRange(location: 0, length: text.utf16.count)
            for match in regex.matches(in: text, range: full) {
                let hit = match.range(at: 1)
                guard hit.location != NSNotFound else { continue }
                let end = hit.location + hit.length
                guard let decoded = Data(base64Encoded: Data(layer.data[hit.location..<end])) else {
                    continue
                }
                guard decoded.count == materialLength else { continue }
                let digest = SHA256.hash(data: decoded)
                    .map { String(format: "%02x", $0) }
                    .joined()
                let begin = max(0, hit.location - contextRadius)
                let stop = min(layer.data.count, end + contextRadius)
                out.append(MaterialCandidate(
                    digest: digest,
                    material: [UInt8](decoded),
                    layer: layer.name,
                    offset: hit.location,
                    context: Array(layer.data[begin..<stop])
                ))
            }
        }
        return out
    }
}
