import Foundation
import Network

/// 上层收到的事件
public enum ChannelEvent {
    case data([UInt8])
    case closed
    case failed(Error)
}

/// 已完成 SOCKS5 协商、移交给上层的客户端 TCP 通道。
///
/// 注意 `pending`：协商过程中可能一次读到「请求 + 应用数据」，
/// 请求之后的字节属于上游流量，必须在开始转发时最先送出去，不能丢。
public final class SOCKS5ClientConnection {
    public let request: SOCKS5Message.Request
    public let peerDescription: String
    public internal(set) var pending: [UInt8]

    private let connection: NWConnection
    private var isClosed = false

    init(
        connection: NWConnection,
        request: SOCKS5Message.Request,
        peer: String,
        pending: [UInt8]
    ) {
        self.connection = connection
        self.request = request
        self.peerDescription = peer
        self.pending = pending
    }

    public var isUDPAssociate: Bool { request.command == .udpAssociate }

    public func sendReply(_ reply: SOCKS5.Reply, boundAddress: SOCKS5Address) {
        send(SOCKS5Message.encodeReply(reply, address: boundAddress))
    }

    public func send(_ data: [UInt8], completion: ((Error?) -> Void)? = nil) {
        guard !isClosed, !data.isEmpty else {
            completion?(nil)
            return
        }
        connection.send(content: Data(data), completion: .contentProcessed { error in
            completion?(error)
        })
    }

    /// 每调用一次收一批，调用方自己循环。
    public func receive(onEvent: @escaping (ChannelEvent) -> Void) {
        guard !isClosed else {
            onEvent(.closed)
            return
        }
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let error {
                self.close()
                onEvent(.failed(error))
                return
            }
            if let data, !data.isEmpty {
                onEvent(.data([UInt8](data)))
            }
            if isComplete {
                self.close()
                onEvent(.closed)
            }
        }
    }

    public func close() {
        guard !isClosed else { return }
        isClosed = true
        connection.cancel()
    }
}

public enum SOCKS5ServerError: Error, CustomStringConvertible {
    case invalidPort(UInt16)

    public var description: String {
        switch self {
        case .invalidPort(let port): return "监听端口非法：\(port)"
        }
    }
}

/// SOCKS5 服务端。
///
/// 只负责协商：版本/方法选择、解析请求、按命令把通道移交给上层。
/// 回复报文（CONNECT 的成败、UDP ASSOCIATE 的中继地址）统一由上层发 ——
/// 只有上层知道上游是否连得上、以及该对外公布哪个可达地址。
public final class SOCKS5Server {
    public struct Options {
        public var port: UInt16
        public init(port: UInt16 = 1080) {
            self.port = port
        }
    }

    public var onConnect: ((SOCKS5Message.Request, SOCKS5ClientConnection) -> Void)?
    public var onUDPAssociate: ((SOCKS5UDPRelay, SOCKS5ClientConnection) -> Void)?
    public var onLog: ((String) -> Void)?
    public var onError: ((Error) -> Void)?

    public private(set) var tcpPort: UInt16?
    public private(set) var udpRelay: SOCKS5UDPRelay?

    private let options: Options
    private let queue: DispatchQueue
    private var listener: NWListener?
    private var negotiators: [ObjectIdentifier: TCPNegotiator] = [:]

    public init(options: Options = Options(), queue: DispatchQueue? = nil) {
        self.options = options
        self.queue = queue ?? DispatchQueue(label: "starradar.socks5.server")
    }

    deinit {
        stop()
    }

    public func start() throws {
        guard let port = NWEndpoint.Port(rawValue: options.port) else {
            throw SOCKS5ServerError.invalidPort(options.port)
        }
        let parameters = NWParameters.tcp
        parameters.allowLocalEndpointReuse = true
        // 要接受局域网内另一台设备接入，不能只收本机回环
        parameters.acceptLocalOnly = false

        let listener = try NWListener(using: parameters, on: port)
        listener.newConnectionHandler = { [weak self] connection in
            self?.accept(connection)
        }
        listener.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.tcpPort = listener.port?.rawValue
                self.onLog?("SOCKS5 TCP 监听就绪，端口 \(self.tcpPort.map(String.init) ?? "?")")
            case .failed(let error):
                self.onError?(error)
            case .cancelled:
                self.onLog?("SOCKS5 TCP 监听已取消")
            default:
                break
            }
        }
        self.listener = listener
        listener.start(queue: queue)

        // UDP ASSOCIATE 的中继端口：优先与 TCP 同号（TCP/UDP 命名空间独立，可以并存），
        // 失败退回临时端口 —— 回复里会把实际端口告诉客户端，客户端以回复为准。
        let relay = SOCKS5UDPRelay(preferredPort: options.port, queue: queue)
        relay.onLog = { [weak self] message in self?.onLog?(message) }
        try relay.start()
        self.udpRelay = relay
    }

    public func stop() {
        listener?.cancel()
        listener = nil
        udpRelay?.stop()
        udpRelay = nil
        // 先摘表再关：cancel 会回调 onRelease 改 negotiators，边遍历边改会崩
        let active = Array(negotiators.values)
        negotiators.removeAll()
        for negotiator in active { negotiator.close() }
        tcpPort = nil
    }

    private func accept(_ connection: NWConnection) {
        let negotiator = TCPNegotiator(connection: connection, queue: queue)
        // 用值类型 key 而不是对象本身，避免闭包强引用造成 negotiator 自持有
        let key = ObjectIdentifier(negotiator)

        negotiator.onLog = { [weak self] message in self?.onLog?(message) }
        negotiator.onRelease = { [weak self] in
            self?.negotiators.removeValue(forKey: key)
        }
        negotiator.onFailure = { [weak self] error in
            self?.onError?(error)
        }
        negotiator.onHandOverConnect = { [weak self] request, client in
            self?.onConnect?(request, client)
        }
        negotiator.onHandOverUDP = { [weak self] client in
            guard let self else { return }
            guard let relay = self.udpRelay else {
                client.sendReply(.generalFailure, boundAddress: SOCKS5Address(ipv4: "0.0.0.0", port: 0)!)
                client.close()
                return
            }
            self.onUDPAssociate?(relay, client)
        }

        negotiators[key] = negotiator
        negotiator.start()
    }
}

/// 单条 TCP 连接的 SOCKS5 协商状态机
private final class TCPNegotiator {
    enum Stage {
        case greeting
        case request
        case handedOver
    }

    var onLog: ((String) -> Void)?
    var onFailure: ((Error) -> Void)?
    var onRelease: (() -> Void)?
    var onHandOverConnect: ((SOCKS5Message.Request, SOCKS5ClientConnection) -> Void)?
    var onHandOverUDP: ((SOCKS5ClientConnection) -> Void)?

    private let connection: NWConnection
    private let queue: DispatchQueue
    private var buffer: [UInt8] = []
    private var stage: Stage = .greeting
    private var peer = "unknown"
    private var released = false

    init(connection: NWConnection, queue: DispatchQueue) {
        self.connection = connection
        self.queue = queue
    }

    func start() {
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.peer = Self.describe(self.connection.endpoint)
                self.onLog?("客户端接入 \(self.peer)")
                self.pump()
            case .failed(let error), .waiting(let error):
                self.fail(error)
            case .cancelled:
                self.release()
            default:
                break
            }
        }
        connection.start(queue: queue)
    }

    func close() {
        connection.cancel()
        release()
    }

    private func release() {
        guard !released else { return }
        released = true
        onRelease?()
    }

    private func fail(_ error: Error) {
        guard !released else { return }
        connection.cancel()
        release()
        onFailure?(error)
    }

    private func pump() {
        guard !released else { return }
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] data, _, isComplete, error in
            guard let self, !self.released else { return }
            if let error {
                self.fail(error)
                return
            }
            if let data, !data.isEmpty {
                self.buffer.append(contentsOf: data)
                do {
                    try self.advance()
                } catch {
                    self.onLog?("协商失败（\(self.peer)）：\(error)")
                    self.fail(error)
                    return
                }
                // 已移交：这条连接归上层，协商器不再继续读取
                if self.stage == .handedOver { return }
            }
            if isComplete {
                self.close()
                return
            }
            self.pump()
        }
    }

    private func advance() throws {
        switch stage {
        case .greeting:
            guard let greeting = try SOCKS5Message.parseGreeting(buffer) else { return }
            guard greeting.offersNoAuth else {
                onLog?("客户端 \(peer) 不支持免认证，拒绝")
                sendAndClose(SOCKS5Message.encodeMethodSelection(.noneAcceptable))
                return
            }
            // 必须把握手前缀从缓冲区切掉：否则下一阶段会把「05 01 00」当请求头解析，
            // 撞上真正的 ATYP 字节后报「地址类型不支持」。客户端把请求跟握手挤在同一个包时尤其明显。
            buffer.removeFirst(2 + greeting.methods.count)
            stage = .request
            send(SOCKS5Message.encodeMethodSelection(.noAuth))

        case .request:
            guard let request = try SOCKS5Message.parseRequest(buffer) else { return }
            let pending = Array(buffer[request.consumedBytes...])
            let client = SOCKS5ClientConnection(
                connection: connection,
                request: request,
                peer: peer,
                pending: pending
            )
            stage = .handedOver
            release() // 连接生命周期交给上层，协商器从服务端表里摘掉

            switch request.command {
            case .connect:
                onLog?("CONNECT \(request.address.hostPort) ← \(peer)")
                onHandOverConnect?(request, client)
            case .udpAssociate:
                onLog?("UDP ASSOCIATE ← \(peer)")
                onHandOverUDP?(client)
            case .bind:
                onLog?("暂不支持 BIND ← \(peer)")
                client.sendReply(.commandNotSupported, boundAddress: SOCKS5Address(ipv4: "0.0.0.0", port: 0)!)
                client.close()
            }

        case .handedOver:
            break
        }
    }

    private func send(_ bytes: [UInt8]) {
        connection.send(content: Data(bytes), completion: .contentProcessed { _ in })
    }

    private func sendAndClose(_ bytes: [UInt8]) {
        connection.send(content: Data(bytes), completion: .contentProcessed { [weak self] _ in
            self?.close()
        })
    }

    private static func describe(_ endpoint: NWEndpoint) -> String {
        switch endpoint {
        case .hostPort(let host, let port):
            return "\(host):\(port)"
        default:
            return "\(endpoint)"
        }
    }
}
