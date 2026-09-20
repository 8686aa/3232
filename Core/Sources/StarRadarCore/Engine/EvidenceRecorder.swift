import CryptoKit
import Foundation
import Security

/// 证据文件的错误。每个 case 对应原实现里一条 `ValueError` / `RuntimeError`。
public enum EvidenceError: Error, Equatable, CustomStringConvertible {
    case invalidLimitsOrRoom
    case invalidServerAddress
    case protectionSelfCheckFailed
    case existingRecording
    case invalidProtectedSourceContext
    case materialOutOfBounds
    case invalidPCAPRecord
    case invalidProtectedFormat
    case invalidCandidateEvidence
    case keychainFailure(OSStatus)
    case invalidMasterKeyLength
    case fileOperationFailed(String)

    public var description: String {
        switch self {
        case .invalidLimitsOrRoom: return "房间号或证据上限非法"
        case .invalidServerAddress: return "证据记录的服务端地址不是合法 IPv4"
        case .protectionSelfCheckFailed: return "证据保护自检失败（主密钥解不开自己刚封的数据）"
        case .existingRecording: return "该目录下已有录制（udp.pcap 存在）"
        case .invalidProtectedSourceContext: return "受保护的上下文非法"
        case .materialOutOfBounds: return "材料超出受保护证据的大小上限"
        case .invalidPCAPRecord: return "PCAP 记录非法"
        case .invalidProtectedFormat: return "受保护证据格式非法"
        case .invalidCandidateEvidence: return "候选证据内容非法"
        case .keychainFailure(let status): return "钥匙串操作失败（OSStatus \(status)）"
        case .invalidMasterKeyLength: return "主密钥长度必须是 32 字节"
        case .fileOperationFailed(let reason): return "文件操作失败：\(reason)"
        }
    }
}

/// 证据保护层：iOS 上没有 DPAPI，改用钥匙串里的主密钥 + AES-256-GCM。
///
/// 对应关系：
/// - `CryptProtectData` 的「当前账号可解」→ `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`
///   的钥匙串条目（不参与 iCloud/备份迁移，等价于 DPAPI 的账号绑定）；
/// - DPAPI 的随机 IV → GCM 的随机 12 字节 nonce（`SealedBox.combined` 自带前缀）；
/// - DPAPI 的完整性校验 → GCM 的 16 字节 tag。
///
/// 原实现的 `CryptProtectData` 只传了描述串、没传 entropy，所以这里也不需要额外的 salt。
public struct EvidenceProtector {
    /// 主密钥长度，AES-256
    public static let masterKeyLength = 32
    /// 钥匙串条目的 service，对应原实现的描述串
    public static let keychainService = "com.starradar.evidence"
    /// 钥匙串条目的 account，沿用原实现 `CryptProtectData` 的 description
    public static let keychainAccount = "HM158 RawDH candidate"

    private let masterKey: SymmetricKey

    /// 从钥匙串取主密钥（没有就现场生成一个）。
    public init() throws {
        // `try` 必须盖住整个委托调用，写在参数里不够
        try self.init(masterKeyData: EvidenceProtector.loadOrCreateMasterKey())
    }

    /// 用给定主密钥构造，测试专用。
    public init(masterKeyData: Data) throws {
        guard masterKeyData.count == Self.masterKeyLength else {
            throw EvidenceError.invalidMasterKeyLength
        }
        self.masterKey = SymmetricKey(data: masterKeyData)
    }

    public func protect(_ plaintext: [UInt8]) throws -> [UInt8] {
        guard let combined = try AES.GCM.seal(Data(plaintext), using: masterKey).combined else {
            throw EvidenceError.fileOperationFailed("GCM 未产出 combined 数据")
        }
        return [UInt8](combined)
    }

    public func unprotect(_ sealed: [UInt8]) throws -> [UInt8] {
        do {
            let box = try AES.GCM.SealedBox(combined: Data(sealed))
            return [UInt8](try AES.GCM.open(box, using: masterKey))
        } catch {
            throw EvidenceError.invalidProtectedFormat
        }
    }

    /// 取钥匙串里的 32 字节主密钥，不存在则生成并写入。
    public static func loadOrCreateMasterKey() throws -> Data {
        if let existing = try loadMasterKey() { return existing }
        let fresh = try randomBytes(masterKeyLength)
        try storeMasterKey(fresh)
        // 并发写入时会有人先落库，回读一次保证两边拿到同一把
        return try loadMasterKey() ?? fresh
    }

    static func randomBytes(_ count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        guard status == errSecSuccess else { throw EvidenceError.keychainFailure(status) }
        return Data(bytes)
    }

    private static func loadMasterKey() throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let data = item as? Data, data.count == masterKeyLength else {
                throw EvidenceError.invalidMasterKeyLength
            }
            return data
        case errSecItemNotFound:
            return nil
        default:
            throw EvidenceError.keychainFailure(status)
        }
    }

    private static func storeMasterKey(_ data: Data) throws {
        let attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecValueData as String: data,
            // 和 DPAPI 的「当前账号」语义对齐：只在本机、首次解锁后可用，不随备份迁移
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess || status == errSecDuplicateItem else {
            throw EvidenceError.keychainFailure(status)
        }
    }
}

/// `record_material` 的入参：登录材料**在抓到时**的完整信封。
///
/// 抽取器只产出 `(kind, path, payload)` 三件套，会话、指令、序号、UDP 目标
/// 都是抓包侧补上的 —— 原实现里这些字段同属 `LoginMaterial`，这里拆成两半，
/// 因为抽字段那一步根本拿不到会话信息。
public struct EvidenceMaterial: Equatable {
    public let session: String
    public let upstream: Endpoint
    public let command: Int
    public let sequence: Int
    public let kind: LoginMaterialKind
    public let fieldPath: String
    public let payload: [UInt8]
    public let udpTargets: [Endpoint]

    public init(
        session: String,
        upstream: Endpoint,
        command: Int,
        sequence: Int,
        kind: LoginMaterialKind,
        fieldPath: String,
        payload: [UInt8],
        udpTargets: [Endpoint] = []
    ) {
        self.session = session
        self.upstream = upstream
        self.command = command
        self.sequence = sequence
        self.kind = kind
        self.fieldPath = fieldPath
        self.payload = payload
        self.udpTargets = udpTargets
    }

    public var fingerprint: String { Hex.encode(SHA256.hash(data: Data(payload))) }
}

/// 读回来的候选证据（`read_candidate` 的返回）。
public struct CandidateEvidence: Equatable {
    public let schema: Int
    public let server: String
    public let room: Int
    public let generation: String
    public let observedMs: Int
    public let session: String
    public let upstream: Endpoint
    public let command: Int
    public let sequence: Int
    public let layer: String
    public let offset: Int
    public let material: [UInt8]
    public let sha256: String
    public let verifiedUDPKey: Bool
    public let sourceContext: [UInt8]?
    public let contextStart: Int?
}

/// 本地配对证据：账号保护下的候选材料 + 有界原始 IP PCAP。
///
/// 原实现把「证据」分成两条互不相干的线：
/// - **候选材料**（`HM158DP1`，一条一文件）—— 128 字节 RawDH 材料，逐条落盘；
/// - **UDP 报文**（`udp.pcap`）—— 原始 IP 记录，用来事后复现解密；
/// 另加 `summary.json` / `decoder-status.json` 两个汇总。
///
/// 关键语义（照抄原实现，不要「优化」）：
/// - 每条记录上限 64 条，重复记录返回 `true`（幂等），超限返回 `false`；
/// - 文件内容 = 8 字节 magic + 保护后的 JSON，先写 `.tmp` 再替换，避免半截文件；
/// - 单条材料 `payload` 只允许 1…8192 字节；
/// - PCAP 有 `maxBytes` 上限，超出只计数不落盘；
/// - **任何一条记录里都不允许出现「已验证」的断言**，`verified_udp_key` 恒为 `false`。
///
/// 本类不做线程同步：原实现只在单个抓包线程里调用，Swift 侧也应当串行使用。
public final class EvidenceRecorder {
    public static let candidateMagic = "HM158DP1"
    public static let materialMagic = "HM158MT1"
    public static let maxRecords = 64
    public static let maxContextBytes = 8192
    public static let maxMaterialBytes = 8192
    public static let defaultMaxBytes = 67_108_864
    public static let defaultServer = "123.99.198.158"
    /// PCAP 全局头之后的起始偏移
    public static let pcapHeaderBytes = 24
    public static let pcapSnaplen = 65535
    /// LINKTYPE_RAW：链路层不封，直接存 IP 包
    public static let pcapNetwork = 101
    /// 读回时允许的最大文件长度
    public static let readLimit = 65536
    public static let candidatePrefix = "candidate-"
    public static let materialPrefix = "material-"
    public static let protectedExtension = "dpapi"
    public static let temporaryExtension = "tmp"
    /// 自检探针，与原实现同一串
    static let probe: [UInt8] = Array("HM158-evidence-check".utf8)

    public let root: URL
    public let room: Int
    public let server: String
    public let generation: String
    public let maxBytes: Int
    public let startedMs: Int

    public private(set) var size = pcapHeaderBytes
    public private(set) var packets = 0
    public private(set) var overLimit = 0

    private let protector: EvidenceProtector
    private let pcap: FileHandle
    private var identities: Set<String> = []
    private var materialIdentities: Set<String> = []

    /// - Parameters:
    ///   - protector: 只给测试注入固定主密钥用；生产留 `nil`，走钥匙串。
    public init(
        root: URL,
        room: Int,
        maxBytes: Int = EvidenceRecorder.defaultMaxBytes,
        server: String = EvidenceRecorder.defaultServer,
        protector: EvidenceProtector? = nil
    ) throws {
        guard (1...40).contains(room), maxBytes >= EvidenceRecorder.pcapHeaderBytes else {
            throw EvidenceError.invalidLimitsOrRoom
        }
        // 对应 `str(IPv4Address(server))`：既是校验也是规范化
        guard let raw = SOCKS5Address.ipv4Bytes(server),
              let canonical = SOCKS5Address.ipv4Text(raw) else {
            throw EvidenceError.invalidServerAddress
        }
        let resolved = try protector ?? EvidenceProtector()
        guard try resolved.unprotect(resolved.protect(Self.probe)) == Self.probe else {
            throw EvidenceError.protectionSelfCheckFailed
        }

        self.root = root
        self.room = room
        self.server = canonical
        self.maxBytes = maxBytes
        self.generation = Hex.encode(try EvidenceProtector.randomBytes(16))
        self.protector = resolved
        self.startedMs = Self.nowMs()

        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let pcapURL = root.appendingPathComponent("udp.pcap")
        guard !FileManager.default.fileExists(atPath: pcapURL.path) else {
            throw EvidenceError.existingRecording
        }
        // 原实现是 open('xb')：存在就报错，这里用 withoutOverwriting 取同一语义
        try Data(Self.pcapHeader).write(to: pcapURL, options: .withoutOverwriting)
        let handle = try FileHandle(forWritingTo: pcapURL)
        // 新句柄的偏移是 0，直接写会盖掉全局头
        try handle.seekToEnd()
        self.pcap = handle
    }

    // MARK: - 候选

    /// 落一条 128 字节候选。重复返回 `true`（幂等），超过 64 条返回 `false`。
    @discardableResult
    public func record(_ candidate: KeyCandidate) throws -> Bool {
        let identity = Self.digestHex("\(candidate.session):\(candidate.fingerprint)")
        if identities.contains(identity) { return true }
        if identities.count >= Self.maxRecords { return false }

        var row: [String: Any] = [
            "schema": 1,
            "server": server,
            "room": room,
            "generation": generation,
            "observed_ms": Self.nowMs(),
            "session": candidate.session,
            "upstream": [candidate.upstream.host, candidate.upstream.port],
            "command": candidate.command,
            "sequence": candidate.sequence,
            "layer": candidate.layer,
            "offset": candidate.offset,
            "material_b64": Data(candidate.material).base64EncodedString(),
            "sha256": candidate.fingerprint,
            "verified_udp_key": false,
        ]
        if !candidate.sourceContext.isEmpty {
            guard candidate.sourceContext.count <= Self.maxContextBytes,
                  candidate.contextStart >= 0 else {
                throw EvidenceError.invalidProtectedSourceContext
            }
            row["source_context_b64"] = Data(candidate.sourceContext).base64EncodedString()
            row["context_start"] = candidate.contextStart
        }

        try write(
            magic: Self.candidateMagic,
            payload: try Self.encodeJSON(row),
            name: Self.candidatePrefix + identity + "." + Self.protectedExtension
        )
        identities.insert(identity)
        return true
    }

    /// 落一条登录材料。判据与候选那条一致，只是多带 `kind` 一起进指纹。
    @discardableResult
    public func recordMaterial(_ material: EvidenceMaterial) throws -> Bool {
        let identity = Self.digestHex("\(material.session):\(material.kind.rawValue):\(material.fingerprint)")
        if materialIdentities.contains(identity) { return true }
        if materialIdentities.count >= Self.maxRecords { return false }
        guard (1...Self.maxMaterialBytes).contains(material.payload.count) else {
            throw EvidenceError.materialOutOfBounds
        }

        let row: [String: Any] = [
            "schema": 1,
            "server": server,
            "room": room,
            "generation": generation,
            "session": material.session,
            "upstream": [material.upstream.host, material.upstream.port],
            "observed_ms": Self.nowMs(),
            "command": material.command,
            "sequence": material.sequence,
            "kind": material.kind.rawValue,
            "field_path": material.fieldPath,
            "udp_targets": material.udpTargets.map { [$0.host, $0.port] },
            "payload_b64": Data(material.payload).base64EncodedString(),
            "sha256": material.fingerprint,
            "verified_udp_key": false,
        ]

        try write(
            magic: Self.materialMagic,
            payload: try Self.encodeJSON(row),
            name: Self.materialPrefix + identity + "." + Self.protectedExtension
        )
        materialIdentities.insert(identity)
        return true
    }

    /// 读回一条候选证据，校验 magic / 长度 / schema / sha256。
    /// 对应原实现的模块级 `read_candidate`。
    public static func readCandidate(
        at url: URL,
        protector: EvidenceProtector? = nil
    ) throws -> CandidateEvidence {
        let data = try [UInt8](Data(contentsOf: url))
        let magic = Array(candidateMagic.utf8)
        guard data.starts(with: magic), data.count <= readLimit else {
            throw EvidenceError.invalidProtectedFormat
        }
        let plain = try (protector ?? EvidenceProtector()).unprotect(Array(data[magic.count...]))
        guard let object = try JSONSerialization.jsonObject(with: Data(plain)) as? [String: Any],
              let materialText = object["material_b64"] as? String,
              let material = Data(base64Encoded: materialText) else {
            throw EvidenceError.invalidProtectedFormat
        }
        guard (object["schema"] as? NSNumber)?.intValue == 1,
              material.count == 128,
              Hex.encode(SHA256.hash(data: material)) == object["sha256"] as? String else {
            throw EvidenceError.invalidCandidateEvidence
        }

        func int(_ key: String) -> Int? { (object[key] as? NSNumber)?.intValue }
        func pair(_ key: String) -> Endpoint? {
            guard let list = object[key] as? [Any], list.count == 2,
                  let host = list[0] as? String, let port = list[1] as? NSNumber else { return nil }
            return Endpoint(host: host, port: port.intValue)
        }
        guard let schema = int("schema"), let room = int("room"), let observedMs = int("observed_ms"),
              let command = int("command"), let sequence = int("sequence"), let offset = int("offset"),
              let upstream = pair("upstream"), let server = object["server"] as? String,
              let generation = object["generation"] as? String,
              let session = object["session"] as? String,
              let layer = object["layer"] as? String,
              let sha256 = object["sha256"] as? String else {
            throw EvidenceError.invalidCandidateEvidence
        }
        let context = (object["source_context_b64"] as? String).flatMap { Data(base64Encoded: $0) }
        return CandidateEvidence(
            schema: schema,
            server: server,
            room: room,
            generation: generation,
            observedMs: observedMs,
            session: session,
            upstream: upstream,
            command: command,
            sequence: sequence,
            layer: layer,
            offset: offset,
            material: [UInt8](material),
            sha256: sha256,
            verifiedUDPKey: (object["verified_udp_key"] as? Bool) ?? false,
            sourceContext: context.map { [UInt8]($0) },
            contextStart: int("context_start")
        )
    }

    // MARK: - UDP 报文

    /// 落一包原始 IP 报文。超过 `maxBytes` 只累加 `overLimit`，不抛异常。
    public func writeUDP(timestampMicros: Int, packet: [UInt8]) throws {
        // 0 <= ts < 2^32 秒，且包长落在 [20, 65535]
        guard timestampMicros >= 0, timestampMicros < 4_294_967_296_000_000 else {
            throw EvidenceError.invalidPCAPRecord
        }
        guard (20...Self.pcapSnaplen).contains(packet.count) else {
            throw EvidenceError.invalidPCAPRecord
        }
        guard size + 16 + packet.count <= maxBytes else {
            overLimit += 1
            return
        }

        let seconds = timestampMicros / 1_000_000
        let micros = timestampMicros % 1_000_000
        var record: [UInt8] = []
        for value in [seconds, micros, packet.count, packet.count] {
            record.append(contentsOf: Self.uint32LE(UInt32(value)))
        }
        try pcap.write(contentsOf: Data(record + packet))
        size += 16 + packet.count
        packets += 1
    }

    // MARK: - 汇总与收尾

    /// 解码器自述状态，原样落成 `decoder-status.json`
    public func recordDecoderStatus(_ value: [String: Any]) throws {
        try Self.writeJSON(value, to: root.appendingPathComponent("decoder-status.json"))
    }

    public func close(captureDrops: Int = 0) throws {
        try? pcap.close()
        let report: [String: Any] = [
            "server": server,
            "room": room,
            "generation": generation,
            "started_ms": startedMs,
            "ended_ms": Self.nowMs(),
            "candidate_count": identities.count,
            "udp_packets": packets,
            "structured_material_count": materialIdentities.count,
            "pcap_bytes": size,
            "capture_queue_drops": captureDrops,
            "file_limit_drops": overLimit,
            "verified_udp_keys": 0,
            // 原实现这里写的是 'Windows DPAPI current account'，iOS 侧如实写实际实现
            "protection": "iOS Keychain after-first-unlock + AES-256-GCM",
        ]
        try Self.writeJSON(report, to: root.appendingPathComponent("summary.json"))
    }

    // MARK: - 内部

    /// 先写 `.tmp` 再改名，避免留下半截文件 —— 原实现的 `with_suffix('.tmp')` + `replace`
    private func write(magic: String, payload: [UInt8], name: String) throws {
        let path = root.appendingPathComponent(name)
        let temporary = path.deletingPathExtension()
            .appendingPathExtension(Self.temporaryExtension)
        let bytes = Array(magic.utf8) + (try protector.protect(payload))
        try Data(bytes).write(to: temporary, options: .withoutOverwriting)
        if FileManager.default.fileExists(atPath: path.path) {
            try FileManager.default.removeItem(at: path)
        }
        try FileManager.default.moveItem(at: temporary, to: path)
    }

    static func encodeJSON(_ object: [String: Any]) throws -> [UInt8] {
        [UInt8](try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]))
    }

    static func writeJSON(_ object: [String: Any], to url: URL) throws {
        let data = try JSONSerialization.data(
            withJSONObject: object,
            options: [.prettyPrinted, .sortedKeys]
        )
        try Data(data + Array("\n".utf8)).write(to: url)
    }

    static func digestHex(_ text: String) -> String {
        Hex.encode(SHA256.hash(data: Data(text.utf8)))
    }

    static func nowMs() -> Int { Int(Date().timeIntervalSince1970 * 1000) }

    static func uint32LE(_ value: UInt32) -> [UInt8] {
        [
            UInt8(truncatingIfNeeded: value),
            UInt8(truncatingIfNeeded: value >> 8),
            UInt8(truncatingIfNeeded: value >> 16),
            UInt8(truncatingIfNeeded: value >> 24),
        ]
    }

    /// pcap 全局头：小端 magic + 2.4 + 无时区/无分组修正 + 65535 + LINKTYPE_RAW
    static let pcapHeader: [UInt8] = {
        var out: [UInt8] = []
        out.append(contentsOf: uint32LE(0xA1B2_C3D4))
        out.append(contentsOf: [2, 0, 4, 0])
        out.append(contentsOf: uint32LE(0))
        out.append(contentsOf: uint32LE(0))
        out.append(contentsOf: uint32LE(UInt32(pcapSnaplen)))
        out.append(contentsOf: uint32LE(UInt32(pcapNetwork)))
        return out
    }()
}
