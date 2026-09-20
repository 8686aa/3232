import CryptoKit
import Foundation
import Network

/// 手写的 WebSocket 客户端，架在裸 TCP `NWConnection` 上。
///
/// 为什么不用 `NWProtocolWebSocket`：真机实测，对**非 TLS 的 `ws://`** 建链时
/// 它会先完成 TCP 三次握手，然后一个字节都不发就把连接掐掉，对外报
/// `ECONNABORTED(53)`；服务端只看到一个连上就断的 TCP。Apple 的示例清一色
/// 是 `wss://`，非 TLS 这条路径没人走过。
///
/// 裸 TCP 在本 App 里是有实证可用的 —— 中间人转发走的就是它 —— 所以这里自己
/// 完成一次 HTTP/1.1 升级握手与帧编解码。副产品是把握手响应原文明明白白地
/// 写进日志：被拒时能看到 HTTP 状态码，而不是只能看到一句「拨号超时」。
///
/// 为什么不用 `URLSessionWebSocketTask`：它的 `send` 回调只代表「交给了会话」，
/// 不代表帧已经落到 socket，而本模块判定半开连接**就靠写超时**。
final class WebSocketTransport: ReporterTransport {
    var onOpen: (() -> Void)?
    var onText: ((String) -> Void)?
    var onClose: ((String) -> Void)?

    private let queue: DispatchQueue
    private let writeTimeout: TimeInterval
    private let dialTimeout: Int
    private let diagnostics: ((String) -> Void)?

    private var connection: NWConnection?
    private var host = ""
    private var port: UInt16 = 0
    private var opened = false
    private var closed = false

    /// 升级请求里那个随机 key，校验 `Sec-WebSocket-Accept` 要用
    private var handshakeKey = ""
    private var handshakeDone = false
    private var responseBuffer = Data()
    private var decoder = WebSocketFrameDecoder()

    init(
        queue: DispatchQueue,
        writeTimeout: TimeInterval,
        dialTimeout: TimeInterval,
        diagnostics: ((String) -> Void)? = nil
    ) {
        self.queue = queue
        self.writeTimeout = writeTimeout
        self.dialTimeout = Int(max(1, dialTimeout.rounded(.up)))
        self.diagnostics = diagnostics
    }

    func connect(host: String, port: UInt16) {
        guard !closed, connection == nil else { return }
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            finish("端口 \(port) 非法")
            return
        }

        let tcp = NWProtocolTCP.Options()
        tcp.connectionTimeout = dialTimeout

        // 协议栈里只有 TCP：升级握手与帧编解码都在本文件里做。
        // 刻意与中间人转发那条已跑通的连接保持同一套参数（只设 connectionTimeout）：
        // 半开连接由 5s 心跳 + 写超时发现，不需要再叠一层 TCP keepalive，
        // 免得在这里留一个和实测失败路径长得很像的变量。
        let parameters = NWParameters(tls: nil, tcp: tcp)
        let connection = NWConnection(
            to: .hostPort(host: NWEndpoint.Host(host), port: nwPort),
            using: parameters
        )
        self.connection = connection
        self.host = host
        self.port = port
        diagnostics?("拨号 \(host):\(port)")

        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                // 这里只是 TCP 通了，升级握手成没成得看下面响应
                guard !self.closed, !self.handshakeDone else { return }
                self.diagnostics?("TCP 已连通，发升级请求")
                self.startHandshake()
            case .failed(let error):
                self.diagnostics?("链路失败：\(describeNetworkError(error))")
                self.finish(describeNetworkError(error))
            case .cancelled:
                self.finish("连接已取消")
            case .waiting(let error):
                // 没路由 / 被系统策略拦下时 iOS 会一直挂在 waiting 重试，
                // 对外表现就是「拨号超时」—— 把真因透出来，否则只能瞎猜
                self.diagnostics?("链路受阻：\(describeNetworkError(error))")
            case .setup:
                self.diagnostics?("开始建链")
            case .preparing:
                self.diagnostics?("TCP 握手中")
            default:
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
        write(WebSocketFrameEncoder.encode(opcode: .text, payload: [UInt8](text.utf8)), on: connection, completion: completion)
    }

    func close() {
        finish("本地关闭")
    }

    // MARK: - 升级握手

    private func startHandshake() {
        guard let connection, !closed, !handshakeDone, handshakeKey.isEmpty else { return }
        handshakeKey = WebSocketHandshake.makeKey()
        let request = WebSocketHandshake.request(host: host, port: port, key: handshakeKey)
        // 这里不设写超时：整段建链时间由上报端的拨号看门狗兜住，
        // 中途失败也能从下面的 reason 里看出卡在握手哪一步
        connection.send(content: request, isComplete: true, completion: .contentProcessed { [weak self] error in
            guard let self, !self.closed else { return }
            if let error {
                self.finish("发升级请求失败：\(describeNetworkError(error))")
                return
            }
            self.pump()
        })
    }

    private func consumeHandshake(_ data: Data) {
        responseBuffer.append(data)
        // 上限兜住「对端一直不结束响应头」这种情况
        guard let response = WebSocketHandshake.parse(responseBuffer) else {
            if responseBuffer.count > 16 * 1024 {
                finish("握手响应超过 16KB 仍未结束")
            }
            return
        }
        // 响应头之后紧跟的字节可能已经是业务帧，不能丢
        let leftover = [UInt8](responseBuffer.dropFirst(response.consumed))
        responseBuffer.removeAll()

        guard response.status == 101 else {
            finish("握手被拒：HTTP \(response.status)")
            return
        }
        guard let accept = response.accept, accept == WebSocketHandshake.accept(for: handshakeKey) else {
            finish("握手响应缺少合法的 Sec-WebSocket-Accept")
            return
        }

        handshakeDone = true
        opened = true
        diagnostics?("链路就绪（HTTP 101）")
        if !leftover.isEmpty {
            for event in decoder.append(leftover) {
                handle(event)
            }
        }
        guard !closed else { return }
        onOpen?()
    }

    // MARK: - 读循环

    private func pump() {
        guard let connection, !closed else { return }
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) {
            [weak self] data, _, isComplete, error in
            guard let self, !self.closed else { return }

            if let data, !data.isEmpty {
                if self.handshakeDone {
                    for event in self.decoder.append([UInt8](data)) {
                        self.handle(event)
                        if self.closed { return }
                    }
                } else {
                    self.consumeHandshake(data)
                    if self.closed { return }
                }
            }

            if let error {
                self.finish(self.handshakeDone
                    ? describeNetworkError(error)
                    : "握手期间链路异常：\(describeNetworkError(error))")
                return
            }
            if isComplete {
                self.finish(self.handshakeDone ? "对端关闭连接" : "握手期间对端关闭连接")
                return
            }
            self.pump()
        }
    }

    private func handle(_ event: WebSocketFrameDecoder.Event) {
        switch event {
        case .text(let text):
            onText?(text)
        case .binary(let count):
            // 上报协议全是文本帧，二进制帧说明对端不是我们要的东西
            diagnostics?("收到二进制帧 \(count) 字节，忽略")
        case .ping(let payload):
            // 服务端 ping 必须回 pong，载荷原样带回
            guard let connection, opened, !closed else { return }
            write(WebSocketFrameEncoder.encode(opcode: .pong, payload: payload), on: connection, completion: { _ in })
        case .pong:
            break
        case .close(let code):
            finish(code.map { "对端关闭连接（code \($0)）" } ?? "对端关闭连接")
        }
    }

    // MARK: - 内部

    /// 写一帧。写超时与写成功赛跑：谁先到谁说了算，两边都在本队列上跑，不需要额外加锁
    private func write(
        _ frame: [UInt8],
        on connection: NWConnection,
        completion: @escaping (Bool) -> Void
    ) {
        var settled = false
        let deadline = DispatchWorkItem { [weak self] in
            guard !settled else { return }
            settled = true
            self?.finish("写超时 \(Int(self?.writeTimeout ?? 0))s")
            completion(false)
        }
        queue.asyncAfter(deadline: .now() + writeTimeout, execute: deadline)

        connection.send(content: Data(frame), isComplete: true, completion: .contentProcessed { [weak self] error in
            deadline.cancel()
            guard !settled else { return }
            settled = true
            if let error {
                self?.finish(describeNetworkError(error))
                completion(false)
            } else {
                completion(true)
            }
        })
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

// MARK: - 握手

/// RFC 6455 的 HTTP/1.1 升级握手。抽成无状态工具，单测可以直接对着
/// 规范里的黄金向量验算 `Sec-WebSocket-Accept`。
enum WebSocketHandshake {
    static let guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    static func makeKey() -> String {
        var bytes = [UInt8](repeating: 0, count: 16)
        for index in bytes.indices {
            bytes[index] = UInt8.random(in: .min ... .max)
        }
        return Data(bytes).base64EncodedString()
    }

    static func accept(for key: String) -> String {
        let digest = Insecure.SHA1.hash(data: Data((key + guid).utf8))
        return Data(digest).base64EncodedString()
    }

    static func request(host: String, port: UInt16, key: String) -> Data {
        Data((
            "GET / HTTP/1.1\r\n"
                + "Host: \(host):\(port)\r\n"
                + "Upgrade: websocket\r\n"
                + "Connection: Upgrade\r\n"
                + "Sec-WebSocket-Key: \(key)\r\n"
                + "Sec-WebSocket-Version: 13\r\n"
                + "\r\n"
        ).utf8)
    }

    struct Response {
        var status: Int
        var accept: String?
        /// 响应头连同结尾空行占用的字节数，其后的字节已经是业务帧
        var consumed: Int
    }

    /// 收全了返回解析结果，没收全返回 nil（外层继续等下一段）
    static func parse(_ buffer: Data) -> Response? {
        guard let terminator = buffer.range(of: Data("\r\n\r\n".utf8)) else { return nil }
        let head = String(decoding: buffer[buffer.startIndex..<terminator.lowerBound], as: UTF8.self)
        let lines = head.components(separatedBy: "\r\n")
        let status = Int(lines.first?.split(separator: " ").dropFirst().first ?? "") ?? 0

        var accept: String?
        for line in lines.dropFirst() {
            let parts = line.split(separator: ":", maxSplits: 1)
            guard parts.count == 2,
                  parts[0].trimmingCharacters(in: .whitespaces).lowercased() == "sec-websocket-accept"
            else { continue }
            accept = parts[1].trimmingCharacters(in: .whitespaces)
        }

        return Response(
            status: status,
            accept: accept,
            consumed: buffer.distance(from: buffer.startIndex, to: terminator.upperBound)
        )
    }
}

// MARK: - 帧

enum WebSocketFrameEncoder {
    /// 客户端发的帧必须加掩码，RFC 6455 §5.3；服务端不加也接受
    enum Opcode: UInt8 {
        case continuation = 0x0
        case text = 0x1
        case binary = 0x2
        case close = 0x8
        case ping = 0x9
        case pong = 0xA
    }

    static func encode(opcode: Opcode, payload: [UInt8]) -> [UInt8] {
        var frame: [UInt8] = [0x80 | opcode.rawValue]
        let mask = (0..<4).map { _ in UInt8.random(in: .min ... .max) }
        let length = payload.count

        if length < 126 {
            frame.append(0x80 | UInt8(length))
        } else if length <= 0xFFFF {
            frame.append(0x80 | 126)
            frame.append(UInt8((length >> 8) & 0xFF))
            frame.append(UInt8(length & 0xFF))
        } else {
            frame.append(0x80 | 127)
            for shift in stride(from: 56, through: 0, by: -8) {
                frame.append(UInt8((length >> shift) & 0xFF))
            }
        }

        frame.append(contentsOf: mask)
        frame.reserveCapacity(frame.count + length)
        for (index, byte) in payload.enumerated() {
            frame.append(byte ^ mask[index % 4])
        }
        return frame
    }
}

/// 流式解帧：`append` 可以喂半帧，内部攒够再吐事件。
struct WebSocketFrameDecoder {
    enum Event: Equatable {
        case text(String)
        case binary(Int)
        case ping([UInt8])
        case pong
        case close(UInt16?)
    }

    /// 单帧上限，防对端用超长长度字段把内存吃满
    private static let maxPayload = 8 * 1024 * 1024

    private var buffer: [UInt8] = []
    private var fragmentOpcode: UInt8 = 0
    private var fragmentPayload: [UInt8] = []

    mutating func append(_ bytes: [UInt8]) -> [Event] {
        buffer.append(contentsOf: bytes)
        var events: [Event] = []
        while let frame = next() {
            switch frame.opcode {
            case WebSocketFrameEncoder.Opcode.continuation.rawValue:
                // 没有起始帧的续帧，按规范丢弃
                guard fragmentOpcode != 0 else { break }
                fragmentPayload.append(contentsOf: frame.payload)
                if frame.fin {
                    events.append(emit(opcode: fragmentOpcode, payload: fragmentPayload))
                    fragmentOpcode = 0
                    fragmentPayload = []
                }
            case WebSocketFrameEncoder.Opcode.text.rawValue, WebSocketFrameEncoder.Opcode.binary.rawValue:
                if frame.fin {
                    events.append(emit(opcode: frame.opcode, payload: frame.payload))
                } else {
                    fragmentOpcode = frame.opcode
                    fragmentPayload = frame.payload
                }
            case WebSocketFrameEncoder.Opcode.ping.rawValue:
                events.append(.ping(frame.payload))
            case WebSocketFrameEncoder.Opcode.pong.rawValue:
                events.append(.pong)
            case WebSocketFrameEncoder.Opcode.close.rawValue:
                let code = frame.payload.count >= 2
                    ? UInt16(frame.payload[0]) << 8 | UInt16(frame.payload[1])
                    : nil
                events.append(.close(code))
            default:
                break
            }
        }
        return events
    }

    private func emit(opcode: UInt8, payload: [UInt8]) -> Event {
        opcode == WebSocketFrameEncoder.Opcode.text.rawValue
            ? .text(String(decoding: payload, as: UTF8.self))
            : .binary(payload.count)
    }

    private mutating func next() -> (fin: Bool, opcode: UInt8, payload: [UInt8])? {
        guard buffer.count >= 2 else { return nil }
        let fin = buffer[0] & 0x80 != 0
        let opcode = buffer[0] & 0x0F
        let masked = buffer[1] & 0x80 != 0
        var length = Int(buffer[1] & 0x7F)
        var cursor = 2

        if length == 126 {
            guard buffer.count >= cursor + 2 else { return nil }
            length = Int(buffer[cursor]) << 8 | Int(buffer[cursor + 1])
            cursor += 2
        } else if length == 127 {
            guard buffer.count >= cursor + 8 else { return nil }
            var value = 0
            for index in 0..<8 {
                value = value << 8 | Int(buffer[cursor + index])
            }
            length = value
            cursor += 8
        }

        guard length <= Self.maxPayload else {
            // 长度离谱，缓冲丢掉，让上层去重连
            buffer.removeAll()
            return nil
        }

        var mask: [UInt8] = []
        if masked {
            guard buffer.count >= cursor + 4 else { return nil }
            mask = Array(buffer[cursor..<(cursor + 4)])
            cursor += 4
        }
        guard buffer.count >= cursor + length else { return nil }

        var payload = Array(buffer[cursor..<(cursor + length)])
        if masked {
            for index in payload.indices {
                payload[index] ^= mask[index % 4]
            }
        }
        buffer.removeFirst(cursor + length)
        return (fin, opcode, payload)
    }
}
