import Foundation
import Network

/// `NWConnection` + `NWProtocolWebSocket` 的通道实现。
///
/// 为什么不用 `URLSessionWebSocketTask`：它的 `send` 回调只代表「交给了会话」，
/// 不代表帧已经落到 socket，而本模块判定半开连接**就靠写超时**。
/// `NWConnection` 的 `.contentProcessed` 与取消语义正好对上这一点。
final class WebSocketTransport: ReporterTransport {
    var onOpen: (() -> Void)?
    var onText: ((String) -> Void)?
    var onClose: ((String) -> Void)?

    private let queue: DispatchQueue
    private let writeTimeout: TimeInterval
    private let dialTimeout: Int
    private let keepaliveIdle: Int

    private var connection: NWConnection?
    private var opened = false
    private var closed = false

    init(
        queue: DispatchQueue,
        writeTimeout: TimeInterval,
        dialTimeout: TimeInterval,
        keepaliveIdleSeconds: Int = 2
    ) {
        self.queue = queue
        self.writeTimeout = writeTimeout
        self.dialTimeout = Int(max(1, dialTimeout.rounded(.up)))
        self.keepaliveIdle = max(1, keepaliveIdleSeconds)
    }

    func connect(host: String, port: UInt16) {
        guard !closed, connection == nil else { return }
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            finish("端口 \(port) 非法")
            return
        }

        let tcp = NWProtocolTCP.Options()
        // 半开连接在 TCP 层面也要能被发现：2s 一次 keepalive 探测
        tcp.enableKeepalive = true
        tcp.keepaliveIdle = keepaliveIdle
        tcp.connectionTimeout = dialTimeout

        let ws = NWProtocolWebSocket.Options()
        // 服务端主动 ping 时自动回 pong，不必走业务层
        ws.autoReplyPing = true

        let parameters = NWParameters(tls: nil, tcp: tcp)
        parameters.defaultProtocolStack.applicationProtocols.insert(ws, at: 0)

        let connection = NWConnection(
            to: .hostPort(host: NWEndpoint.Host(host), port: nwPort),
            using: parameters
        )
        self.connection = connection
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                guard !self.opened, !self.closed else { return }
                self.opened = true
                self.receive()
                self.onOpen?()
            case .failed(let error):
                self.finish(describeNetworkError(error))
            case .cancelled:
                self.finish("连接已取消")
            default:
                // .waiting 交给上报端的拨号超时与写超时裁决：底层自己会重试，
                // 因为一次路径抖动就掐断反而更难连上
                break
            }
        }
        connection.start(queue: queue)
    }

    func send(_ text: String, completion: @escaping (Bool) -> Void) {
        guard let connection, opened, !closed else {
            completion(false)
            return
        }

        // 写超时与写成功赛跑：谁先到谁说了算，两边都在本队列上跑，不需要额外加锁
        var settled = false
        let deadline = DispatchWorkItem { [weak self] in
            guard !settled else { return }
            settled = true
            self?.finish("写超时 \(Int(self?.writeTimeout ?? 0))s")
            completion(false)
        }
        queue.asyncAfter(deadline: .now() + writeTimeout, execute: deadline)

        let metadata = NWProtocolWebSocket.Metadata(opcode: .text)
        let context = NWConnection.ContentContext(identifier: "starradar.text", metadata: [metadata])
        connection.send(
            content: Data(text.utf8),
            contentContext: context,
            isComplete: true,
            completion: .contentProcessed { [weak self] error in
                deadline.cancel()
                guard !settled else { return }
                settled = true
                if let error {
                    self?.finish(describeNetworkError(error))
                    completion(false)
                } else {
                    completion(true)
                }
            }
        )
    }

    func close() {
        finish("本地关闭")
    }

    // MARK: - 内部

    private func receive() {
        guard let connection, opened, !closed else { return }
        connection.receiveMessage { [weak self] data, context, _, error in
            guard let self, !self.closed else { return }

            if let metadata = context?.protocolMetadata(definition: NWProtocolWebSocket.definition)
                as? NWProtocolWebSocket.Metadata {
                switch metadata.opcode {
                case .close:
                    self.finish("对端关闭连接")
                    return
                case .ping, .pong:
                    // 控制帧不上业务层：ping 已由 autoReplyPing 回掉，pong 是回执
                    self.receive()
                    return
                default:
                    break
                }
            }

            if let error {
                self.finish(describeNetworkError(error))
                return
            }
            if let data, !data.isEmpty, let text = String(data: data, encoding: .utf8) {
                self.onText?(text)
            }
            self.receive()
        }
    }

    private func finish(_ reason: String) {
        guard !closed else { return }
        closed = true
        opened = false
        if let connection {
            connection.stateUpdateHandler = nil
            connection.cancel()
        }
        connection = nil
        onClose?(reason)
    }
}
