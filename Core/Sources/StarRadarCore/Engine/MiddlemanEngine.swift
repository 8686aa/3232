import Darwin
import Foundation
import Network

/// 中间人引擎：接管 SOCKS5 通道并按需做 TGCP/RawDH 翻译。
///
/// ```
/// 游戏机(小火箭) ── SOCKS5 ──▶ SOCKS5Server ──▶ MiddlemanEngine ──▶ 真实上游
///                                   │                  │
///                              UDP 中继 ◀── UDPFlow ───┘
/// ```
public final class MiddlemanEngine {
    public var config: EngineConfig
    public let log = EventLog()

    /// 已捞到的 128 字节候选密钥（去重，只留最近若干个）
    public private(set) var candidates: [MaterialCandidate] = []
    public let maxCandidates = 32

    private let counter = StatsCounter()
    private let queue = DispatchQueue(label: "starradar.engine")
    private var server: SOCKS5Server?
    private var relays: [ObjectIdentifier: TCPRelay] = [:]
    private var udpFlows: [String: UDPFlow] = [:]
    private var candidateDigests: Set<String> = []
    private var sweepTimer: DispatchSourceTimer?

    public init(config: EngineConfig = EngineConfig()) {
        self.config = config
    }

    public var isRunning: Bool { server != nil }
    public var tcpPort: UInt16? { server?.tcpPort }
    public var udpPort: UInt16? { server?.udpRelay?.port }

    public func stats() -> EngineStats { counter.snapshot() }

    // MARK: - 生命周期

    public func start() throws {
        guard server == nil else { return }

        let server = SOCKS5Server(options: .init(port: config.listenPort), queue: queue)
        server.onLog = { [weak self] message in self?.log.write(message) }
        server.onError = { [weak self] error in
            self?.counter.record(error: error)
            self?.log.write("SOCKS5 错误：\(describeNetworkError(error))")
        }
        server.onConnect = { [weak self] request, client in
            self?.accept(request: request, client: client)
        }
        server.onUDPAssociate = { [weak self] relay, client in
            self?.acceptUDP(relay: relay, client: client)
        }
        try server.start()
        self.server = server

        let intercepts = config.interceptPorts.sorted().map(String.init).joined(separator: ",")
        log.write("引擎启动：TCP \(server.tcpPort.map(String.init) ?? "?")，"
            + "UDP \(server.udpRelay?.port.map(String.init) ?? "?")，拦截端口 [\(intercepts)]")
        startSweep()
    }

    public func stop() {
        sweepTimer?.cancel()
        sweepTimer = nil
        // 先摘表再关：close/cancel 会回调 onRelease 改这两个字典
        let activeRelays = Array(relays.values)
        relays.removeAll()
        for relay in activeRelays { relay.close() }
        let activeFlows = Array(udpFlows.values)
        udpFlows.removeAll()
        for flow in activeFlows { flow.cancel() }
        server?.stop()
        server = nil
        log.write("引擎已停止")
    }

    // MARK: - TCP

    private func accept(request: SOCKS5Message.Request, client: SOCKS5ClientConnection) {
        counter.update { $0.connectAccepted += 1 }
        let intercept = config.interceptPorts.contains(request.address.port)
        if intercept {
            counter.update { $0.middlemanSessions += 1 }
        } else {
            counter.update { $0.relaySessions += 1 }
        }

        let relay = TCPRelay(
            client: client,
            target: request.address,
            session: intercept ? MiddlemanSession(counter: counter) : nil,
            queue: queue,
            counter: counter,
            onPlaintext: { [weak self] direction, frame, plain in
                self?.inspect(direction: direction, frame: frame, plain: plain)
            }
        )
        let key = ObjectIdentifier(relay)
        relay.onLog = { [weak self] message in self?.log.write(message) }
        relay.onRelease = { [weak self] in self?.relays.removeValue(forKey: key) }
        relays[key] = relay
        relay.start()
    }

    private func inspect(direction: MiddlemanSession.Direction, frame: TGCPFrame, plain: [UInt8]) {
        // 只有服务端下发的材料指令里才可能夹带密钥
        guard direction == .serverToClient, frame.command == TGCP.commandMaterial else { return }
        for candidate in MaterialExtractor.candidates(in: plain) {
            guard !candidateDigests.contains(candidate.digest) else { continue }
            candidateDigests.insert(candidate.digest)
            candidates.append(candidate)
            if candidates.count > maxCandidates { candidates.removeFirst() }
            counter.update { $0.cryptoCandidates = self.candidateDigests.count }
            log.write("候选密钥：\(candidate.material.count) 字节，层次 \(candidate.layer)，"
                + "偏移 \(candidate.offset)，sha256 \(candidate.digest.prefix(12))…（待验证）")
        }
    }

    // MARK: - UDP

    private func acceptUDP(relay: SOCKS5UDPRelay, client: SOCKS5ClientConnection) {
        counter.update { $0.udpAssociateAccepted += 1 }
        let host = config.advertisedHost ?? LocalAddress.primaryIPv4() ?? "0.0.0.0"
        guard let bound = SOCKS5Address(ipv4: host, port: relay.port ?? 0) else {
            client.sendReply(.generalFailure, boundAddress: SOCKS5Address(ipv4: "0.0.0.0", port: 0)!)
            client.close()
            return
        }
        client.sendReply(.succeeded, boundAddress: bound)
        log.write("UDP ASSOCIATE 已接受，中继地址 \(bound.hostPort)")

        relay.onDatagram = { [weak self, weak relay] source, datagram in
            guard let self, let relay else { return }
            self.forwardUDP(source: source, datagram: datagram, relay: relay)
        }
        // 控制连接要一直挂着，关掉就等于撤销关联
        holdUDPControlConnection(client)
    }

    private func holdUDPControlConnection(_ client: SOCKS5ClientConnection) {
        client.receive { [weak self] event in
            switch event {
            case .data:
                self?.holdUDPControlConnection(client)
            case .closed, .failed:
                self?.log.write("UDP 控制连接已关闭 \(client.peerDescription)")
            }
        }
    }

    private func forwardUDP(
        source: SOCKS5Address,
        datagram: SOCKS5Message.Datagram,
        relay: SOCKS5UDPRelay
    ) {
        guard !datagram.payload.isEmpty else { return }
        guard let flow = udpFlow(target: datagram.address, client: source, relay: relay) else {
            log.write("UDP 目标地址非法，丢弃：\(datagram.address.hostPort)")
            return
        }
        flow.touch(client: source)
        counter.update { $0.udpDatagramsToUpstream += 1 }
        flow.send(datagram.payload)
    }

    private func udpFlow(
        target: SOCKS5Address,
        client: SOCKS5Address,
        relay: SOCKS5UDPRelay
    ) -> UDPFlow? {
        let key = target.hostPort
        if let existing = udpFlows[key] { return existing }
        guard let flow = UDPFlow(
            target: target,
            client: client,
            queue: queue,
            relay: relay,
            counter: counter,
            onLog: { [weak self] message in self?.log.write(message) }
        ) else {
            return nil
        }
        udpFlows[key] = flow
        updateUDPFlowCount()
        return flow
    }

    private func updateUDPFlowCount() {
        counter.update { $0.udpFlows = self.udpFlows.count }
    }

    private func startSweep() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 15, repeating: 15)
        timer.setEventHandler { [weak self] in self?.sweepUDPFlows() }
        timer.resume()
        sweepTimer = timer
    }

    private func sweepUDPFlows() {
        let deadline = Date().addingTimeInterval(-config.udpIdleTimeout)
        var changed = false
        for key in udpFlows.filter({ $0.value.lastActivity < deadline }).map(\.key) {
            udpFlows.removeValue(forKey: key)?.cancel()
            changed = true
        }
        while udpFlows.count > config.maxUDPFlows,
              let oldest = udpFlows.min(by: { $0.value.lastActivity < $1.value.lastActivity }) {
            udpFlows.removeValue(forKey: oldest.key)?.cancel()
            changed = true
        }
        if changed { updateUDPFlowCount() }
    }
}

// MARK: - TCP 转发

/// 一条 CONNECT 的上游侧管线：交给 SOCKS5 客户端一个成败回复，然后双向搬运。
/// 命中拦截端口时插入 `MiddlemanSession`，其余情况原样转发。
private final class TCPRelay {
    private let client: SOCKS5ClientConnection
    private let target: SOCKS5Address
    private let session: MiddlemanSession?
    private let queue: DispatchQueue
    private let counter: StatsCounter

    var onLog: ((String) -> Void)?
    var onRelease: (() -> Void)?

    private var upstream: NWConnection?
    private var released = false
    private var ready = false
    private var clientFinished = false
    private var upstreamFinished = false

    init(
        client: SOCKS5ClientConnection,
        target: SOCKS5Address,
        session: MiddlemanSession?,
        queue: DispatchQueue,
        counter: StatsCounter,
        onPlaintext: @escaping (MiddlemanSession.Direction, TGCPFrame, [UInt8]) -> Void
    ) {
        self.client = client
        self.target = target
        self.session = session
        self.queue = queue
        self.counter = counter
        session?.onPlaintext = onPlaintext
    }

    func start() {
        guard let port = NWEndpoint.Port(rawValue: target.port), target.port != 0 else {
            reject(.addressTypeNotSupported, "目标端口非法 \(target.port)")
            return
        }
        // 默认 0 表示不超时，SYN 一直没人应答时要等内核重传耗尽（约 75 秒）才报
        // ETIMEDOUT，客户端那边早就超时重试了。压到 15 秒，让失败带着目标地址早点落到日志。
        let tcpOptions = NWProtocolTCP.Options()
        tcpOptions.connectionTimeout = 15
        let parameters = NWParameters(tls: nil, tcp: tcpOptions)
        parameters.allowLocalEndpointReuse = true
        let connection = NWConnection(
            to: .hostPort(host: NWEndpoint.Host(target.host), port: port),
            using: parameters
        )
        upstream = connection
        if let session {
            session.onLog = { [weak self] message in self?.onLog?(message) }
            onLog?("中间人会话开始 → \(target.hostPort)")
        } else {
            onLog?("纯转发 → \(target.hostPort)")
        }

        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.handleReady()
            case .waiting(let error):
                // 建连前等路径：快速失败让客户端重试，比挂住等超时体验好；
                // 建连后是链路抖动，不能冒充失败回复去掐断活着的连接
                if self.ready {
                    self.onLog?("上游链路抖动：\(describeNetworkError(error))")
                } else {
                    self.reject(Self.reply(for: error), describeNetworkError(error))
                }
            case .failed(let error):
                if self.ready {
                    self.counter.record(error: error)
                    self.onLog?("上游连接中断：\(describeNetworkError(error))")
                    self.close()
                } else {
                    self.reject(Self.reply(for: error), describeNetworkError(error))
                }
            case .cancelled:
                self.close()
            default:
                break
            }
        }
        connection.start(queue: queue)
    }

    func close() {
        guard !released else { return }
        released = true
        client.close()
        upstream?.cancel()
        upstream = nil
        onRelease?()
    }

    // MARK: 上游就绪

    private func handleReady() {
        guard !released else { return }
        ready = true
        // 回复必须先发，且要排在缓存的请求后数据之前
        client.sendReply(.succeeded, boundAddress: boundAddress())
        let pending = client.pending
        client.pending = []
        if !pending.isEmpty {
            forward(pending, direction: .clientToServer)
        }
        pumpClient()
        pumpUpstream()
    }

    private func boundAddress() -> SOCKS5Address {
        if let endpoint = upstream?.currentPath?.localEndpoint,
           case let .hostPort(host, port) = endpoint,
           let address = SOCKS5Address(host: "\(host)", port: port.rawValue) {
            return address
        }
        return SOCKS5Address(ipv4: "0.0.0.0", port: 0)!
    }

    // MARK: 双向搬运

    private func pumpClient() {
        guard !released, !clientFinished else { return }
        client.receive { [weak self] event in
            guard let self else { return }
            switch event {
            case .data(let bytes):
                self.forward(bytes, direction: .clientToServer)
            case .closed:
                self.clientFinished = true
                self.close()
            case .failed(let error):
                self.counter.record(error: error)
                self.onLog?("客户端通道异常：\(describeNetworkError(error))")
                self.clientFinished = true
                self.close()
            }
            self.pumpClient()
        }
    }

    private func pumpUpstream() {
        guard !released, !upstreamFinished, let upstream else { return }
        upstream.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) {
            [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                self.forward([UInt8](data), direction: .serverToClient)
            }
            if let error {
                self.counter.record(error: error)
                self.onLog?("上游通道异常：\(describeNetworkError(error))")
                self.upstreamFinished = true
                self.close()
                return
            }
            if isComplete {
                self.upstreamFinished = true
                self.close()
                return
            }
            self.pumpUpstream()
        }
    }

    private func forward(_ data: [UInt8], direction: MiddlemanSession.Direction) {
        guard !data.isEmpty, !released else { return }
        var payload = data
        if let session {
            do {
                payload = try session.process(data, direction: direction)
            } catch {
                counter.update { $0.translateFailures += 1 }
                counter.record(error: error)
                onLog?("协议翻译失败（\(direction.label)）：\(error)")
                close()
                return
            }
        }
        guard !payload.isEmpty else { return }

        switch direction {
        case .clientToServer:
            upstream?.send(content: Data(payload), completion: .contentProcessed { _ in })
        case .serverToClient:
            client.send(payload)
        }
    }

    // MARK: 失败回复

    private func reject(_ reply: SOCKS5.Reply, _ reason: String) {
        guard !released else { return }
        onLog?("上游不可达（\(target.hostPort)）：\(reason)")
        counter.update { $0.lastError = reason }
        // 等回复真正写出去再关，否则客户端只会看到连接被重置
        client.send(
            SOCKS5Message.encodeReply(reply, address: SOCKS5Address(ipv4: "0.0.0.0", port: 0)!)
        ) { [weak self] _ in
            self?.close()
        }
    }

    private static func reply(for error: NWError) -> SOCKS5.Reply {
        guard case let .posix(code) = error else { return .generalFailure }
        switch code {
        case .ECONNREFUSED: return .connectionRefused
        case .ENETUNREACH, .ENETDOWN: return .networkUnreachable
        case .EHOSTUNREACH, .EHOSTDOWN: return .hostUnreachable
        case .EACCES, .EPERM: return .connectionNotAllowed
        default: return .generalFailure
        }
    }
}

// MARK: - UDP flow

/// 一条 UDP 目标流：对上游是一个 connected UDP 套接字，回包封装后送回客户端。
private final class UDPFlow {
    let target: SOCKS5Address
    private(set) var lastActivity = Date()

    private let connection: NWConnection
    private let counter: StatsCounter
    private let relay: SOCKS5UDPRelay
    private let onLog: (String) -> Void
    private var client: SOCKS5Address
    private var cancelled = false

    init?(
        target: SOCKS5Address,
        client: SOCKS5Address,
        queue: DispatchQueue,
        relay: SOCKS5UDPRelay,
        counter: StatsCounter,
        onLog: @escaping (String) -> Void
    ) {
        guard let port = NWEndpoint.Port(rawValue: target.port), target.port != 0 else { return nil }
        let parameters = NWParameters.udp
        parameters.allowLocalEndpointReuse = true
        self.target = target
        self.client = client
        self.relay = relay
        self.counter = counter
        self.onLog = onLog
        self.connection = NWConnection(
            to: .hostPort(host: NWEndpoint.Host(target.host), port: port),
            using: parameters
        )
        connection.stateUpdateHandler = { [weak self] state in
            if case .failed(let error) = state {
                self?.onLog("UDP 上游 \(target.hostPort) 失败：\(error)")
            }
        }
        connection.start(queue: queue)
        pump()
    }

    func touch(client: SOCKS5Address) {
        self.client = client
        lastActivity = Date()
    }

    func send(_ payload: [UInt8]) {
        guard !cancelled else { return }
        lastActivity = Date()
        connection.send(content: Data(payload), completion: .contentProcessed { _ in })
    }

    func cancel() {
        guard !cancelled else { return }
        cancelled = true
        connection.cancel()
    }

    private func pump() {
        guard !cancelled else { return }
        connection.receiveMessage { [weak self] data, _, _, error in
            guard let self, !self.cancelled else { return }
            if let error {
                self.onLog("UDP 上游 \(self.target.hostPort) 读取失败：\(error)")
                return
            }
            if let data, !data.isEmpty {
                self.lastActivity = Date()
                self.counter.update { $0.udpDatagramsFromUpstream += 1 }
                self.relay.sendToClient(
                    payload: [UInt8](data),
                    from: self.target,
                    to: self.client
                )
            }
            self.pump()
        }
    }
}

// MARK: - 本机地址探测

/// UDP ASSOCIATE 要告诉客户端「往哪个地址发 UDP」。
/// 这里只做尽力而为的探测，探测不准时用 `EngineConfig.advertisedHost` 手工指定。
enum LocalAddress {
    static func primaryIPv4() -> String? {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return nil }
        defer { freeifaddrs(head) }

        var candidates: [(name: String, address: String)] = []
        var pointer: UnsafeMutablePointer<ifaddrs>? = first
        while let current = pointer {
            pointer = current.pointee.ifa_next
            let flags = Int32(current.pointee.ifa_flags)
            guard flags & IFF_UP != 0, flags & IFF_LOOPBACK == 0 else { continue }
            guard let raw = current.pointee.ifa_addr,
                  raw.pointee.sa_family == sa_family_t(AF_INET) else { continue }
            var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let result = getnameinfo(
                raw,
                socklen_t(raw.pointee.sa_len),
                &buffer,
                socklen_t(buffer.count),
                nil,
                0,
                NI_NUMERICHOST
            )
            guard result == 0 else { continue }
            candidates.append((String(cString: current.pointee.ifa_name), String(cString: buffer)))
        }

        // 优先 Wi-Fi（en0），其次排除蜂窝/隧道接口
        if let wifi = candidates.first(where: { $0.name == "en0" }) { return wifi.address }
        return candidates.first {
            !$0.name.hasPrefix("pdp") && !$0.name.hasPrefix("utun")
        }?.address
    }
}
