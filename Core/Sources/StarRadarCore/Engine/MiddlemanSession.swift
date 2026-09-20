import Foundation

public enum MiddlemanError: Error, CustomStringConvertible {
    case unexpectedClientHello
    case serverHelloOutOfOrder
    case handshakeIncomplete(String)
    case invalidPeerPublic

    public var description: String {
        switch self {
        case .unexpectedClientHello: return "重复或非预期的 ClientHello"
        case .serverHelloOutOfOrder: return "ServerHello 顺序错误"
        case .handshakeIncomplete(let what): return "RawDH 握手未完成：\(what)"
        case .invalidPeerPublic: return "对端 DH 公钥非法"
        }
    }
}

/// 单条 TCP 连接的 TGCP + RawDH 中间人会话。
///
/// 与原实现 [dfm_rawdh_proxy.Session] 一一对应：
/// - 两侧各自生成一份 DH：`clientSide` 的公钥回给客户端（冒充服务端），
///   `serverSide` 的公钥发给服务端（冒充客户端）。
/// - `clientKey = DH(client 公钥, clientSide 私钥)`，`serverKey = DH(server 公钥, serverSide 私钥)`。
/// - c2s 用 clientKey 解、serverKey 重加密；s2c 反过来。
///
/// 只做协议，不碰网络，方便单测。
public final class MiddlemanSession {
    public enum Direction: Equatable {
        case clientToServer
        case serverToClient

        public var label: String { self == .clientToServer ? "c2s" : "s2c" }
    }

    /// 解出来的应用层明文，交给上层去提取候选密钥
    public var onPlaintext: ((Direction, TGCPFrame, [UInt8]) -> Void)?
    public var onLog: ((String) -> Void)?

    /// 首包不是 TGCP 流时整体退化为原样转发
    public private(set) var isFraming = true
    public private(set) var sawClientHello = false
    public private(set) var sawServerHello = false

    /// 两侧密钥都拿到手才算握手完成
    public var isReady: Bool { clientKey != nil && serverKey != nil }

    private let counter: StatsCounter
    private let clientSide = RawDHSide.create()
    private let serverSide = RawDHSide.create()
    private let clientFramer = TGCPFramer()
    private let serverFramer = TGCPFramer()
    private var clientPublic: BigUInt?
    private var serverPublic: BigUInt?
    private var clientKey: [UInt8]?
    private var serverKey: [UInt8]?
    private var framingDecided = false

    /// 只由引擎内部创建（`StatsCounter` 不对外暴露）
    init(counter: StatsCounter) {
        self.counter = counter
    }

    // MARK: - 主入口

    /// 吃一段原始字节，吐出发给对端的字节。未凑齐的尾部留在分帧器里。
    public func process(_ data: [UInt8], direction: Direction) throws -> [UInt8] {
        guard !data.isEmpty else { return [] }
        guard decideFraming(data) else { return data }

        let framer = direction == .clientToServer ? clientFramer : serverFramer
        let frames = try framer.feed(data)
        guard !frames.isEmpty else { return [] }

        var out: [UInt8] = []
        out.reserveCapacity(data.count)
        for frame in frames {
            out.append(contentsOf: try translate(frame, direction))
        }
        return out
    }

    /// 用首包判断这条连接到底是不是 TGCP
    private func decideFraming(_ data: [UInt8]) -> Bool {
        if framingDecided { return isFraming }
        // 只有 1 个字节时先不下结论，让分帧器继续缓冲
        guard data.count >= TGCP.magic.count else { return true }
        framingDecided = true
        isFraming = Array(data[0..<TGCP.magic.count]) == TGCP.magic
        if !isFraming {
            onLog?("首包不是 TGCP 流，本连接退化为原样转发")
        }
        return isFraming
    }

    private func translate(_ frame: TGCPFrame, _ direction: Direction) throws -> [UInt8] {
        if direction == .clientToServer && frame.command == TGCP.commandClientHello {
            return try handleClientHello(frame).packed()
        }
        if direction == .serverToClient && frame.command == TGCP.commandServerHello {
            return try handleServerHello(frame).packed()
        }
        return try translateApplication(frame, direction).packed()
    }

    // MARK: - 握手

    private func handleClientHello(_ frame: TGCPFrame) throws -> TGCPFrame {
        // ClientHello 必须是这条连接的第一帧，且不带报文体
        guard clientPublic == nil, serverPublic == nil, frame.body.isEmpty else {
            throw MiddlemanError.unexpectedClientHello
        }
        let field = try TGCP.parseDHPublic(header: frame.header)
        guard let key = clientSide.deriveKey(peerPublic: field.value) else {
            throw MiddlemanError.invalidPeerPublic
        }
        clientPublic = field.value
        clientKey = key
        sawClientHello = true
        counter.update { $0.clientHelloSeen += 1 }

        // 把客户端的公钥换成我们自己的，服务端以为在和我们握手
        let header = try TGCP.replacingDHPublic(header: frame.header, with: serverSide.publicBytes)
        onLog?("ClientHello：已替换 DH 公钥，clientKey 就绪")
        return TGCPFrame(header: header, body: frame.body, streamOffset: frame.streamOffset)
    }

    private func handleServerHello(_ frame: TGCPFrame) throws -> TGCPFrame {
        guard clientPublic != nil, serverPublic == nil else {
            throw MiddlemanError.serverHelloOutOfOrder
        }
        let field = try TGCP.parseDHPublic(header: frame.header)
        guard let key = serverSide.deriveKey(peerPublic: field.value) else {
            throw MiddlemanError.invalidPeerPublic
        }
        serverPublic = field.value
        serverKey = key
        sawServerHello = true
        counter.update { $0.serverHelloSeen += 1 }

        let header = try TGCP.replacingDHPublic(header: frame.header, with: clientSide.publicBytes)
        var body = frame.body
        // ServerHello 自带一段密文体时，就地用 serverKey 解、clientKey 重加密
        if !body.isEmpty, frame.gate != 0 {
            guard let clientKey else { throw MiddlemanError.handshakeIncomplete("clientKey") }
            body = try NativeAES.translate(body: body, source: key, destination: clientKey).cipher
            counter.update { $0.translatedFrames += 1 }
        }
        onLog?("ServerHello：已替换 DH 公钥，serverKey 就绪")
        return TGCPFrame(header: header, body: body, streamOffset: frame.streamOffset)
    }

    // MARK: - 应用数据

    private func translateApplication(_ frame: TGCPFrame, _ direction: Direction) throws -> TGCPFrame {
        guard serverPublic != nil else {
            throw MiddlemanError.handshakeIncomplete("尚未收到 ServerHello")
        }
        guard !frame.body.isEmpty else { return frame }
        // s2c 且 gate=0 是明文直通（原实现同样放行）
        if direction == .serverToClient && frame.gate == 0 {
            onPlaintext?(direction, frame, frame.body)
            return frame
        }

        let source = direction == .clientToServer ? clientKey : serverKey
        let destination = direction == .clientToServer ? serverKey : clientKey
        guard let source, let destination else {
            throw MiddlemanError.handshakeIncomplete("密钥不全")
        }

        let result = try NativeAES.translate(body: frame.body, source: source, destination: destination)
        counter.update { $0.translatedFrames += 1 }
        onPlaintext?(direction, frame, result.plain)
        return frame.packed(body: result.cipher)
    }
}
