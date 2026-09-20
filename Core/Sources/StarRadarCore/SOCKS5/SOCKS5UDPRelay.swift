import Foundation
import Network

/// SOCKS5 UDP ASSOCIATE 的客户端侧中继。
///
/// 职责边界：这里只管「客户端 ↔ 本机中继」这一段 ——
/// 把客户端发来的 SOCKS5 UDP 报文剥头后交给上层，以及把上游回包封装后送回客户端。
/// 上游那一侧（按目标建连、按 flow 记账、解密）由引擎负责，因为那部分需要协议知识。
public final class SOCKS5UDPRelay {
    public typealias DatagramHandler = (_ source: SOCKS5Address, _ datagram: SOCKS5Message.Datagram) -> Void

    public var onDatagram: DatagramHandler?
    public var onLog: ((String) -> Void)?
    public var onError: ((Error) -> Void)?

    public private(set) var port: UInt16?
    public var clientCount: Int { clients.count }

    private let preferredPort: UInt16
    private let queue: DispatchQueue
    private let maxClients = 64
    private var listener: NWListener?
    /// 客户端 UDP 端点 → 连接；回包时按目标地址找回对应客户端
    private var clients: [String: NWConnection] = [:]
    private var clientOrder: [String] = []
    private var lastClientKey: String?

    init(preferredPort: UInt16, queue: DispatchQueue) {
        self.preferredPort = preferredPort
        self.queue = queue
    }

    deinit {
        stop()
    }

    func start() throws {
        // 优先与 TCP 同号（TCP/UDP 命名空间独立，可以并存）
        if preferredPort != 0, let port = NWEndpoint.Port(rawValue: preferredPort) {
            try bind(port: port, fallbackToEphemeral: true)
        } else {
            try bind(port: nil, fallbackToEphemeral: false)
        }
    }

    /// 绑监听器。
    ///
    /// `NWListener(using:on:)` 对「端口被占」**不抛错**，只在 stateUpdateHandler 里异步报
    /// `.failed` —— 所以「同号占不到就退临时端口」必须等状态回调，用 `try?` 判空是永远走不到的。
    private func bind(port: NWEndpoint.Port?, fallbackToEphemeral: Bool) throws {
        let listener = try makeListener(on: port)
        listener.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.port = self.listener?.port?.rawValue ?? port?.rawValue
                self.onLog?("UDP 中继就绪，端口 \(self.port.map(String.init) ?? "?")")
            case .failed(let error):
                guard fallbackToEphemeral else {
                    self.onError?(error)
                    return
                }
                self.onLog?("UDP 中继绑定 \(self.preferredPort) 失败："
                    + "\(describeNetworkError(error))，改用临时端口")
                // 先摘表再取消：重绑失败时要留下干净的「没有中继」状态，而不是一个已死的监听器
                let failed = self.listener
                self.listener = nil
                self.port = nil
                failed?.cancel()
                do {
                    try self.bind(port: nil, fallbackToEphemeral: false)
                } catch {
                    self.onError?(error)
                }
            default:
                break
            }
        }
        self.listener = listener
        listener.start(queue: queue)
    }

    private func makeListener(on port: NWEndpoint.Port?) throws -> NWListener {
        let parameters = NWParameters.udp
        parameters.allowLocalEndpointReuse = true
        let listener: NWListener
        if let port {
            listener = try NWListener(using: parameters, on: port)
        } else {
            listener = try NWListener(using: parameters)
        }
        listener.newConnectionHandler = { [weak self] connection in
            self?.accept(connection)
        }
        return listener
    }

    func stop() {
        listener?.cancel()
        listener = nil
        // 同理：cancel 会触发 stateUpdateHandler → dropClient 改 clients，必须先摘表
        let active = Array(clients.values)
        clients.removeAll()
        clientOrder.removeAll()
        lastClientKey = nil
        for connection in active { connection.cancel() }
        port = nil
    }

    private func accept(_ connection: NWConnection) {
        let key = Self.describe(connection.endpoint)
        if clients[key] == nil {
            if clientOrder.count >= maxClients, let oldest = clientOrder.first {
                clients[oldest]?.cancel()
                clients.removeValue(forKey: oldest)
                clientOrder.removeFirst()
            }
            clients[key] = connection
            clientOrder.append(key)
        }
        lastClientKey = key

        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .failed, .cancelled:
                self?.dropClient(key)
            default:
                break
            }
        }
        connection.start(queue: queue)
        pump(connection, key: key)
    }

    private func dropClient(_ key: String) {
        clients.removeValue(forKey: key)
        clientOrder.removeAll { $0 == key }
        if lastClientKey == key { lastClientKey = clientOrder.last }
    }

    private func pump(_ connection: NWConnection, key: String) {
        connection.receiveMessage { [weak self] data, _, _, error in
            guard let self else { return }
            if let error {
                self.onError?(error)
                self.dropClient(key)
                return
            }
            if let data, !data.isEmpty {
                let bytes = [UInt8](data)
                let source = Self.address(from: connection.endpoint)
                do {
                    if let datagram = try SOCKS5Message.parseDatagram(bytes), let source {
                        self.onDatagram?(source, datagram)
                    }
                } catch {
                    // 单个数据报格式错误不该拖垮整条关联，记录后丢弃
                    self.onLog?("UDP 数据报丢弃：\(error)")
                }
            }
            self.pump(connection, key: key)
        }
    }

    /// 把上游回包封装成 SOCKS5 UDP 报文送回客户端
    public func sendToClient(payload: [UInt8], from: SOCKS5Address, to: SOCKS5Address) {
        guard !payload.isEmpty else { return }
        guard let key = resolveClientKey(for: to), let connection = clients[key] else {
            onLog?("找不到客户端 \(to.hostPort)，回包丢弃")
            return
        }
        let encoded = SOCKS5Message.encodeDatagram(
            SOCKS5Message.Datagram(address: from, payload: payload)
        )
        connection.send(content: Data(encoded), completion: .contentProcessed { _ in })
    }

    private func resolveClientKey(for target: SOCKS5Address) -> String? {
        // 优先按客户端在 UDP 报文里声明的源地址精确匹配
        for (key, connection) in clients {
            guard let address = Self.address(from: connection.endpoint) else { continue }
            if address.host == target.host && address.port == target.port {
                return key
            }
        }
        // 兜底：只有一路客户端时直接用（单设备场景的常态）
        if clients.count == 1 { return clients.keys.first }
        return lastClientKey
    }

    private static func address(from endpoint: NWEndpoint) -> SOCKS5Address? {
        guard case let .hostPort(host, port) = endpoint else { return nil }
        let numericPort = port.rawValue
        switch host {
        case .ipv4:
            return SOCKS5Address(ipv4: "\(host)", port: numericPort)
        case .ipv6:
            return SOCKS5Address(ipv6: "\(host)", port: numericPort)
        case .name(let name, _):
            return SOCKS5Address(domain: name, port: numericPort)
        @unknown default:
            return nil
        }
    }

    private static func describe(_ endpoint: NWEndpoint) -> String {
        if case let .hostPort(host, port) = endpoint {
            return "\(host):\(port)"
        }
        return "\(endpoint)"
    }
}
