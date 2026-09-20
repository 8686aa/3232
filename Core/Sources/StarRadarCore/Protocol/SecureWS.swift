import CryptoKit
import Foundation

public enum SecureWSError: Error, CustomStringConvertible {
    case invalidAPIKey
    case invalidNonce(String)
    case notJSON(String)
    case protocolVersionMismatch
    case notEnvelope(String)
    case invalidSequence(expected: UInt64, received: UInt64)
    case invalidBase64
    case sealedTooShort
    case frameAuthenticationFailed
    case handshakeAlreadyDone
    case serverProofRejected
    case plaintextTooLarge

    public var description: String {
        switch self {
        case .invalidAPIKey: return "房间 Key 需为 32 位十六进制"
        case .invalidNonce(let what): return "\(what) 需为 64 位 hex"
        case .notJSON(let what): return "\(what) 不是合法 JSON"
        case .protocolVersionMismatch: return "协议版本不一致"
        case .notEnvelope(let type): return "不是加密信封（type=\(type)）"
        case .invalidSequence(let expected, let received):
            return "seq 不连续（期望 \(expected)，收到 \(received)）"
        case .invalidBase64: return "密文 base64 非法"
        case .sealedTooShort: return "密文过短"
        case .frameAuthenticationFailed: return "帧认证失败"
        case .handshakeAlreadyDone: return "握手已完成"
        case .serverProofRejected: return "服务端握手证明不通过"
        case .plaintextTooLarge: return "单帧明文过大"
        }
    }
}

/// StarRadarSecureWS v1 —— 上报通道的双向加密，与转发器 `WsMirrorServer.cs` 对称实现。
///
/// 握手三步：① 明文 `secure_hello`（带 api_key 与 32 字节 nonce）→
/// ② 明文 `secure_challenge`（带服务端 nonce 与 proof）→
/// ③ 加密 `secure_finish`（客户端 proof）→ ④ 加密 `secure_ok`。
/// 明文只出现在 ①② 两条，之后一切消息都在 `enc` 信封里。
///
/// `api_key` 只是预共享密钥（IKM），既不当 AES 密钥，也不进密文；
/// 常量改动必须与 C# 服务端同步。
public enum SecureWS {
    public static let version = 1

    /// 帧方向。写进 AAD：上行帧被原样反射回来也解不开。
    public static let dirC2S = 1
    public static let dirS2C = 2

    public static let helloType = "secure_hello"
    public static let challengeType = "secure_challenge"
    public static let finishType = "secure_finish"
    public static let okType = "secure_ok"
    public static let errorType = "error"
    public static let envelopeType = "enc"

    static let hkdfInfo = Data("StarRadarSecureWS/v1".utf8)
    static let roomIDPrefix = Data("StarRadarRoomKeyV1\u{0}".utf8)
    static let transcriptPrefix = "StarRadarSecureWS1"
    static let frameMagic: [UInt8] = Array("SRW1".utf8)

    public static let nonceBytes = 32
    public static let tagSize = 16
    public static let apiKeyChars = 32
    /// 一批 40 条 IP 报文最大也就几十 KB，4 MB 只是防呆上限
    public static let maxPlaintext = 4 * 1024 * 1024

    // MARK: - 房间 Key

    /// 归一化房间 Key：32 位小写 hex。
    ///
    /// 逐个 UTF-8 字节判 hex，不用 `Character.isHexDigit`：Unicode 里全角
    /// `Ａ-Ｆ`／`０-９` 也带 Hex_Digit 属性，会被它放过去，而服务端按 ASCII
    /// 解，派生出的密钥必然对不上。`utf8.count == 32` 顺带挡住多字节字符。
    public static func normalizeAPIKey(_ apiKey: String) throws -> String {
        let key = apiKey.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard key.utf8.count == apiKeyChars,
              key.utf8.allSatisfy({ Hex.value(of: $0) != nil }) else {
            throw SecureWSError.invalidAPIKey
        }
        return key
    }

    /// 房间标识：api_key 的 SHA-256，进握手 transcript，避免 api_key 落日志。
    public static func roomID(_ apiKey: String) -> String {
        let key = apiKey.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return Hex.encode(SHA256.hash(data: roomIDPrefix + Data(key.utf8)))
    }

    // MARK: - 密钥派生

    public struct SessionKeys: Equatable {
        public let c2sKey: [UInt8]
        public let s2cKey: [UInt8]
        public let c2sIV: [UInt8]
        public let s2cIV: [UInt8]
        public let proofKey: [UInt8]
    }

    /// HKDF-SHA256(ikm=api_key, salt=client_nonce‖server_nonce, info=固定串) → 104 字节分五段。
    public static func deriveKeys(
        apiKey: String,
        clientNonce: [UInt8],
        serverNonce: [UInt8]
    ) throws -> SessionKeys {
        let key = try normalizeAPIKey(apiKey)
        guard clientNonce.count == nonceBytes else {
            throw SecureWSError.invalidNonce("客户端 nonce")
        }
        guard serverNonce.count == nonceBytes else {
            throw SecureWSError.invalidNonce("服务端 nonce")
        }
        let material = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: Data(key.utf8)),
            salt: Data(clientNonce + serverNonce),
            info: hkdfInfo,
            outputByteCount: 104
        )
        let bytes = [UInt8](material)
        return SessionKeys(
            c2sKey: Array(bytes[0..<32]),
            s2cKey: Array(bytes[32..<64]),
            c2sIV: Array(bytes[64..<68]),
            s2cIV: Array(bytes[68..<72]),
            proofKey: Array(bytes[72..<104])
        )
    }

    public static func buildTranscript(
        room: String,
        clientNonce: [UInt8],
        serverNonce: [UInt8]
    ) -> String {
        "\(transcriptPrefix)|\(room)|\(Hex.encode(clientNonce))|\(Hex.encode(serverNonce))"
    }

    /// 握手证明：HMAC-SHA256(proof_key, "<side>|<transcript>")，小写 hex。
    public static func buildProof(
        keys: SessionKeys,
        transcript: String,
        side: String
    ) -> String {
        let message = Data(side.utf8) + Data("|".utf8) + Data(transcript.utf8)
        let mac = HMAC<SHA256>.authenticationCode(
            for: message,
            using: SymmetricKey(data: Data(keys.proofKey))
        )
        return Hex.encode(mac)
    }

    /// 32 字节随机 nonce。
    public static func newNonce() -> [UInt8] {
        var generator = SystemRandomNumberGenerator()
        return (0..<nonceBytes).map { _ in UInt8.random(in: 0...255, using: &generator) }
    }

    public static func decodeNonce(_ value: String?, name: String) throws -> [UInt8] {
        guard let text = value, text.count == nonceBytes * 2 else {
            throw SecureWSError.invalidNonce(name)
        }
        guard let bytes = Hex.decode(text) else {
            throw SecureWSError.invalidNonce(name)
        }
        return bytes
    }

    // MARK: - 帧参数

    /// `nonce = iv(4B) ‖ be_u64(seq)`，共 12 字节。
    static func frameNonce(iv: [UInt8], seq: UInt64) -> [UInt8] {
        var out = iv
        out.append(contentsOf: bigEndian(seq))
        return out
    }

    /// `aad = b'SRW1' ‖ [VERSION, DIR] ‖ be_u64(seq)`，共 14 字节。
    static func frameAAD(direction: Int, seq: UInt64) -> Data {
        var out = frameMagic
        out.append(UInt8(version))
        out.append(UInt8(direction))
        out.append(contentsOf: bigEndian(seq))
        return Data(out)
    }

    static func bigEndian(_ value: UInt64) -> [UInt8] {
        (0..<8).reversed().map { UInt8(truncatingIfNeeded: value >> ($0 * 8)) }
    }

    /// 定长比较，避免按字节短路泄漏 proof 的前缀。
    static func constantTimeEquals(_ lhs: String, _ rhs: String) -> Bool {
        let a = Array(lhs.utf8)
        let b = Array(rhs.utf8)
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for index in a.indices { diff |= a[index] ^ b[index] }
        return diff == 0
    }
}

/// 一个方向的加密通道。收发两侧各建一个，方向由各自的出站方向推出。
public final class SecureChannel {
    public let keys: SecureWS.SessionKeys
    public let outboundDir: Int
    private let inboundDir: Int
    private var sendSeq: UInt64 = 0
    private var recvSeq: UInt64 = 0

    public init(keys: SecureWS.SessionKeys, outboundDir: Int) throws {
        guard outboundDir == SecureWS.dirC2S || outboundDir == SecureWS.dirS2C else {
            throw SecureWSError.notEnvelope("出站方向 \(outboundDir) 非法")
        }
        self.keys = keys
        self.outboundDir = outboundDir
        self.inboundDir = outboundDir == SecureWS.dirC2S ? SecureWS.dirS2C : SecureWS.dirC2S
    }

    public var sentCount: UInt64 { sendSeq }
    public var receivedCount: UInt64 { recvSeq }

    private func material(_ direction: Int) -> (key: [UInt8], iv: [UInt8]) {
        direction == SecureWS.dirC2S
            ? (keys.c2sKey, keys.c2sIV)
            : (keys.s2cKey, keys.s2cIV)
    }

    /// 加密一条消息，返回可直接发送的 `enc` 信封 JSON 文本。
    public func encrypt(_ plaintext: [UInt8]) throws -> String {
        guard plaintext.count <= SecureWS.maxPlaintext else {
            throw SecureWSError.plaintextTooLarge
        }
        let seq = sendSeq + 1
        let (key, iv) = material(outboundDir)
        let box = try AES.GCM.seal(
            Data(plaintext),
            using: SymmetricKey(data: Data(key)),
            nonce: try AES.GCM.Nonce(data: Data(SecureWS.frameNonce(iv: iv, seq: seq))),
            authenticating: SecureWS.frameAAD(direction: outboundDir, seq: seq)
        )
        sendSeq = seq
        let sealed = [UInt8](box.ciphertext) + [UInt8](box.tag)
        return "{\"type\":\"enc\",\"v\":\(SecureWS.version),\"seq\":\(seq),"
            + "\"d\":\"\(sealed.base64EncodedString())\"}"
    }

    public func encrypt(_ plaintext: String) throws -> String {
        try encrypt(Array(plaintext.utf8))
    }

    /// 校验信封、方向与 seq，返回明文字节。任何异常都是 `SecureWSError`。
    public func decrypt(_ envelope: String) throws -> [UInt8] {
        guard let object = JSONValue.parseObject(envelope) else {
            throw SecureWSError.notJSON("信封")
        }
        guard object["type"]?.stringValue == SecureWS.envelopeType else {
            throw SecureWSError.notEnvelope(object["type"]?.stringValue ?? "缺失")
        }
        guard let version = object["v"]?.intValue, version == SecureWS.version else {
            throw SecureWSError.protocolVersionMismatch
        }
        // seq 校验必须先于解密：否则 InvalidTag 无法区分「seq 错了」和「被篡改」
        guard let seq = object["seq"]?.uint64Value, seq > 0 else {
            throw SecureWSError.invalidSequence(expected: recvSeq + 1, received: 0)
        }
        guard seq == recvSeq + 1 else {
            throw SecureWSError.invalidSequence(expected: recvSeq + 1, received: seq)
        }
        guard let encoded = object["d"]?.stringValue,
              let sealed = Data(base64Encoded: encoded), !sealed.isEmpty else {
            throw SecureWSError.invalidBase64
        }
        guard sealed.count > SecureWS.tagSize else { throw SecureWSError.sealedTooShort }

        let (key, iv) = material(inboundDir)
        let ciphertext = sealed.prefix(sealed.count - SecureWS.tagSize)
        let tag = sealed.suffix(SecureWS.tagSize)
        let box = try AES.GCM.SealedBox(
            nonce: try AES.GCM.Nonce(data: Data(SecureWS.frameNonce(iv: iv, seq: seq))),
            ciphertext: ciphertext,
            tag: tag
        )
        let plain: Data
        do {
            plain = try AES.GCM.open(
                box,
                using: SymmetricKey(data: Data(key)),
                authenticating: SecureWS.frameAAD(direction: inboundDir, seq: seq)
            )
        } catch {
            throw SecureWSError.frameAuthenticationFailed
        }
        recvSeq = seq
        return [UInt8](plain)
    }

    /// 解密并解析成 JSON 对象。
    public func decryptObject(_ envelope: String) throws -> [String: JSONValue] {
        let plain = try decrypt(envelope)
        guard let text = String(bytes: plain, encoding: .utf8),
              let object = JSONValue.parseObject(text) else {
            throw SecureWSError.notJSON("明文")
        }
        return object
    }
}

/// 客户端侧握手：`hello()` 发出去，`acceptChallenge()` 收回来。
public final class SecureClientHandshake {
    public let apiKey: String
    public let clientNonce: [UInt8]
    private var done = false

    public init(apiKey: String, clientNonce: [UInt8]? = nil) throws {
        self.apiKey = try SecureWS.normalizeAPIKey(apiKey)
        let nonce = clientNonce ?? SecureWS.newNonce()
        guard nonce.count == SecureWS.nonceBytes else {
            throw SecureWSError.invalidNonce("客户端 nonce")
        }
        self.clientNonce = nonce
    }

    /// 明文首帧。api_key 是预共享密钥，服务端要靠它派生会话密钥。
    public func hello() -> String {
        "{\"type\":\"\(SecureWS.helloType)\",\"v\":\(SecureWS.version),"
            + "\"api_key\":\"\(apiKey)\",\"nonce\":\"\(Hex.encode(clientNonce))\"}"
    }

    /// 校验服务端 `secure_challenge`，返回（通道，finish 明文）。
    /// finish 必须由调用方用返回的通道加密后再发 —— 服务端也只认加密的 finish。
    public func acceptChallenge(_ text: String) throws -> (channel: SecureChannel, finish: String) {
        guard !done else { throw SecureWSError.handshakeAlreadyDone }
        guard let object = JSONValue.parseObject(text) else {
            throw SecureWSError.notJSON("secure_challenge")
        }
        guard object["type"]?.stringValue == SecureWS.challengeType else {
            throw SecureWSError.notEnvelope(object["type"]?.stringValue ?? "缺失")
        }
        guard let version = object["v"]?.intValue, version == SecureWS.version else {
            throw SecureWSError.protocolVersionMismatch
        }
        let serverNonce = try SecureWS.decodeNonce(object["nonce"]?.stringValue, name: "服务端 nonce")

        let keys = try SecureWS.deriveKeys(
            apiKey: apiKey,
            clientNonce: clientNonce,
            serverNonce: serverNonce
        )
        let transcript = SecureWS.buildTranscript(
            room: SecureWS.roomID(apiKey),
            clientNonce: clientNonce,
            serverNonce: serverNonce
        )
        let expected = SecureWS.buildProof(keys: keys, transcript: transcript, side: "server")
        guard let supplied = object["proof"]?.stringValue,
              SecureWS.constantTimeEquals(supplied.lowercased(), expected) else {
            throw SecureWSError.serverProofRejected
        }

        done = true
        let finish = "{\"type\":\"\(SecureWS.finishType)\",\"v\":\(SecureWS.version),"
            + "\"proof\":\"\(SecureWS.buildProof(keys: keys, transcript: transcript, side: "client"))\"}"
        return (try SecureChannel(keys: keys, outboundDir: SecureWS.dirC2S), finish)
    }
}
