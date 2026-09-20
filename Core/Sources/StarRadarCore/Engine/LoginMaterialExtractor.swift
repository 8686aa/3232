import CryptoKit
import Foundation

/// 登录材料里的**未验证**候选，逐字段对应原实现 `login_materials.LoginMaterial`
/// 的 `kind / field_path / payload` 三件套。
///
/// 「提取到」不等于「能用」：登录报文里任何名字像密钥的字段都会被抓出来，
/// 但只有拿真实战斗包验证过的那条才会被当作 UDP key 使用 —— 字段名不是证据。
public enum LoginMaterialKind: String, Equatable {
    /// 一组 DH 参数（模数 + 两种方法号），对应 `install_udp_keys` 的入参来源
    case udpAccessParameters = "udp-access-parameters"
    /// 名字像密钥、长度也像密钥的字段
    case namedKeyCandidate = "named-key-candidate"
}

public struct LoginMaterialRecord: Equatable {
    public let kind: LoginMaterialKind
    /// 形如 `$.accessInfo.encryptionKey` 的字段路径，已按原实现截断到 512 字符
    public let path: String
    public let payload: [UInt8]

    public init(kind: LoginMaterialKind, path: String, payload: [UInt8]) {
        self.kind = kind
        self.path = path
        self.payload = payload
    }

    public var fingerprint: String { Hex.encode(SHA256.hash(data: Data(payload))) }
}

/// 从登录明文里捞出「可能有用」的字段。
///
/// 原实现是纯字节扫描 + 内嵌 JSON 解析，判据全部是长度与字符集，不看字段语义，
/// 也就是说这里**故意**会产出假阳性 —— 真正的裁定交给后续的 UDP 验证与
/// `CandidateStore`。几个必须原样保留的细节：
///
/// - 全局限额：文档 512 KB、最多 256 次试探、JSON 节点预算 4096、嵌套深度 16；
/// - 最多留 32 条记录，按 `(kind, sha256(payload))` 去重，**先到先得**；
/// - 只有 `str` 且 `lstrip()` 后以 `{`/`[` 开头才当内嵌 JSON 再递归（对应
///   `accessInfo` 这种「JSON 装在字符串里」的写法）；
/// - 字段名先 `lower()` 再去掉 `_` 才跟 `KEY_NAMES` 比，所以 `udp_key` / `UDPKey`
///   都算命中。
public enum LoginMaterialExtractor {
    /// 单个文档上限
    public static let maxDocument = 524288
    /// 记录条数上限
    public static let maxRecords = 32
    /// 试探内嵌 JSON 的次数上限
    public static let maxAttempts = 256
    /// 遍历节点预算
    public static let nodeBudget = 4096
    /// 嵌套深度上限
    public static let maxDepth = 16
    /// 单个字符串字段的长度上限
    public static let maxFieldLength = 2048
    /// 字段路径截断长度
    public static let maxPathLength = 512

    public static let keyNames: Set<String> = [
        "encryptionkey", "encryptkey", "udpkey", "battlekey",
        "sessionkey", "aeskey", "xteakey", "key",
    ]

    /// 判据里参与「同现」的三个参数名，顺序即 `int` 取值顺序
    public static let parameters = ["user_id_key", "dwUdpKeyMethod", "dwUdpEncMethod"]

    /// 合法密钥长度。128 字节那条才是 RawDH 战斗材料。
    static let keyLengths: Set<Int> = [16, 24, 32, 64, 128, 256, 512]

    /// 返回 `(kind, path, payload)`，绝不把字段名当证明。
    public static func extractFields(_ data: [UInt8]) -> [LoginMaterialRecord] {
        guard data.count <= maxDocument else { return [] }
        // 与原实现的 errors='replace' 对齐：非法序列整体换成 U+FFFD，
        // 后面的「找 `{` / `[`」只关心 ASCII 花括号，替换不会让它错位
        let text = String(decoding: data, as: UTF8.self)
        let bytes = Array(text.utf8)

        let scanner = Scanner()
        var offset = 0
        var attempts = 0
        while offset < bytes.count, attempts < maxAttempts, scanner.budget > 0 {
            guard let brace = nextDocumentStart(in: bytes, from: offset) else { break }
            offset = brace
            attempts += 1
            if let parsed = JSONParser.parseValue(in: bytes, from: offset) {
                scanner.walk(parsed.value, path: "$", depth: 0)
                offset = parsed.end
            } else {
                // 解不动就往后挪一格再找下一个花括号
                offset += 1
            }
        }
        return scanner.records
    }

    /// 第一个 `{` 或 `[` 的字节偏移。UTF-8 里这两个字符永远是单字节，
    /// 所以按字节找与按字符找落在同一处。
    private static func nextDocumentStart(in bytes: [UInt8], from offset: Int) -> Int? {
        var index = offset
        while index < bytes.count {
            let byte = bytes[index]
            if byte == UInt8(ascii: "{") || byte == UInt8(ascii: "[") { return index }
            index += 1
        }
        return nil
    }

    // MARK: - 字段取值

    /// 名字像密钥的字段转字节。字符串先试「纯 hex 块」再试 base64；
    /// 数组要求每个元素都是**真整数**（`type(x) is int`，布尔不算）且落在 0…255。
    static func keyBytes(_ value: JSONValue) -> [UInt8]? {
        switch value {
        case .string(let text):
            guard text.count <= maxFieldLength else { return nil }
            let decoded: [UInt8]
            if isHexBlock(text, minBytes: 16, maxBytes: 512) {
                guard let hex = Hex.decode(text) else { return nil }
                decoded = hex
            } else if let base64 = base64Decoded(text) {
                decoded = base64
            } else {
                return nil
            }
            return keyLengths.contains(decoded.count) ? decoded : nil

        case .array(let elements):
            guard keyLengths.contains(elements.count) else { return nil }
            var out: [UInt8] = []
            out.reserveCapacity(elements.count)
            for element in elements {
                guard case .number(let number) = element, number.isIntegral,
                      let byte = number.int64Value, (0...255).contains(byte) else { return nil }
                out.append(UInt8(byte))
            }
            return out

        default:
            return nil
        }
    }

    /// `(?:[0-9a-fA-F]{2}){minBytes,maxBytes}` —— 两侧判据的下界不同，
    /// 密钥字段是 `{16,512}`，模数是 `{32,512}`，别合并成一个常量。
    private static func isHexBlock(_ text: String, minBytes: Int, maxBytes: Int) -> Bool {
        let count = text.count
        guard count % 2 == 0 else { return false }
        guard (minBytes...maxBytes).contains(count / 2) else { return false }
        return text.utf8.allSatisfy { Hex.value(of: $0) != nil }
    }

    /// 对应 `base64.b64decode(value, validate=True)`：先挡非法字符，
    /// 再补 `=` 到位（Python 的 b64decode 会自动补，Swift 的不会）。
    private static func base64Decoded(_ text: String) -> [UInt8]? {
        guard text.utf8.allSatisfy({ isBase64Byte($0) }) else { return nil }
        var padded = text
        let remainder = padded.count % 4
        if remainder != 0 {
            padded += String(repeating: "=", count: 4 - remainder)
        }
        guard let data = Data(base64Encoded: padded) else { return nil }
        return [UInt8](data)
    }

    private static func isBase64Byte(_ byte: UInt8) -> Bool {
        switch byte {
        case 0x41...0x5A, 0x61...0x7A, 0x30...0x39: return true
        case UInt8(ascii: "+"), UInt8(ascii: "/"), UInt8(ascii: "="): return true
        default: return false
        }
    }

    /// `int(modulus, 16) > 5 and int(modulus, 16) % 2`，用字符串判，避免为了
    /// 两个小判据引一套大整数（模数最长 512 hex，远超 64 位）。
    static func isUsableModulus(_ text: String) -> Bool {
        guard isHexBlock(text, minBytes: 32, maxBytes: 512),
              let bytes = Hex.decode(text) else { return false }
        var index = 0
        while index < bytes.count - 1 && bytes[index] == 0 { index += 1 }
        guard bytes.count - index > 1 || bytes[index] > 5 else { return false }
        return bytes[bytes.count - 1] & 1 == 1
    }

    /// `[A-Za-z_][A-Za-z0-9_]{0,63}`，长度 1…64
    static func isIdentifier(_ text: String) -> Bool {
        let bytes = Array(text.utf8)
        guard bytes.count >= 1, bytes.count <= 64 else { return false }
        guard isIdentifierHead(bytes[0]) else { return false }
        return bytes.dropFirst().allSatisfy { isIdentifierHead($0) || isDigit($0) }
    }

    private static func isIdentifierHead(_ byte: UInt8) -> Bool {
        byte == UInt8(ascii: "_") || isASCIILetter(byte)
    }

    private static func isASCIILetter(_ byte: UInt8) -> Bool {
        (byte >= 0x41 && byte <= 0x5A) || (byte >= 0x61 && byte <= 0x7A)
    }

    private static func isDigit(_ byte: UInt8) -> Bool {
        byte >= 0x30 && byte <= 0x39
    }

    /// `json.dumps(fields, sort_keys=True)` 的字节结果。
    ///
    /// 这串字节会参与记录的 sha256 去重，所以必须逐字节一致：Python 默认分隔符
    /// 带空格（`", "` 与 `": "`），键按码点升序，于是顺序恒为
    /// `dwUdpEncMethod, dwUdpKeyMethod, user_id_key`。
    static func parameterPayload(modulus: String, methods: [String]) -> [UInt8] {
        let entries: [(String, String)] = [
            ("dwUdpEncMethod", methods[1]),
            ("dwUdpKeyMethod", methods[0]),
            ("user_id_key", "\"\(modulus)\""),
        ].sorted { $0.0 < $1.0 }
        let body = entries.map { "\"\($0.0)\": \($0.1)" }.joined(separator: ", ")
        return Array("{\(body)}".utf8)
    }
}

/// 遍历状态。原实现用闭包共享 `records` / `identities` / `budget`，
/// 这里收成一个类，语义相同。
private final class Scanner {
    private(set) var records: [LoginMaterialRecord] = []
    private var identities: Set<String> = []
    private(set) var budget = LoginMaterialExtractor.nodeBudget

    func add(kind: LoginMaterialKind, path: String, payload: [UInt8]) {
        let identity = "\(kind.rawValue):\(Hex.encode(SHA256.hash(data: Data(payload))))"
        guard !identities.contains(identity),
              records.count < LoginMaterialExtractor.maxRecords else { return }
        identities.insert(identity)
        let trimmed = String(path.prefix(LoginMaterialExtractor.maxPathLength))
        records.append(LoginMaterialRecord(kind: kind, path: trimmed, payload: payload))
    }

    func walk(_ value: JSONValue, path: String, depth: Int) {
        budget -= 1
        guard budget >= 0, depth <= LoginMaterialExtractor.maxDepth else { return }

        switch value {
        case .object(let members):
            acceptAccessParameters(members, path: path)
            for member in members {
                guard budget > 0 else { return }
                let label = LoginMaterialExtractor.isIdentifier(member.key) ? member.key : "<field>"
                let childPath = path + "." + label
                let normalized = member.key.lowercased()
                    .replacingOccurrences(of: "_", with: "")
                if LoginMaterialExtractor.keyNames.contains(normalized),
                   let material = LoginMaterialExtractor.keyBytes(member.value) {
                    add(kind: .namedKeyCandidate, path: childPath, payload: material)
                }
                walk(member.value, path: childPath, depth: depth + 1)
            }

        case .array(let elements):
            for (index, element) in elements.enumerated() {
                guard budget > 0 else { return }
                walk(element, path: "\(path)[\(index)]", depth: depth + 1)
            }

        case .string(let text):
            guard text.count <= LoginMaterialExtractor.maxDocument,
                  let first = text.drop(while: { $0.isWhitespace }).first,
                  first == "{" || first == "[" else { return }
            // 解不动就当没有，不往外抛
            if let document = JSONParser.parse(text) {
                walk(document, path: path + ".json", depth: depth + 1)
            }

        default:
            return
        }
    }

    /// 三个参数齐全才算一组，全部判据过了才记一条。
    private func acceptAccessParameters(_ members: [JSONMember], path: String) {
        var lookup: [String: JSONValue] = [:]
        for member in members { lookup[member.key] = member.value }

        let parameters = LoginMaterialExtractor.parameters
        guard let modulusValue = lookup[parameters[0]],
              let modulus = modulusValue.stringValue else { return }

        var methodRaw: [String] = []
        for name in parameters.dropFirst() {
            guard let value = lookup[name], case .number(let number) = value,
                  number.isIntegral else { return }
            methodRaw.append(number.raw)
        }

        guard LoginMaterialExtractor.isUsableModulus(modulus) else { return }
        let payload = LoginMaterialExtractor.parameterPayload(
            modulus: modulus.lowercased(),
            methods: methodRaw
        )
        add(kind: .udpAccessParameters, path: path, payload: payload)
    }
}
