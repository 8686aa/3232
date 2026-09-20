import CryptoKit
import Foundation

/// 上报节点地址规范化。原实现 `normalizeNodeURL`：只填 IP 就补默认端口 1082。
public struct NodeAddress: Equatable {
    /// 转发器默认端口
    public static let defaultPort: UInt16 = 1082

    public let host: String
    public let port: UInt16

    /// 接受 `123.99.198.158`、`123.99.198.158:1082`、`ws://123.99.198.158`、
    /// `ws://123.99.198.158:1082/`。域名一并放行 —— 拨号阶段才需要真解析。
    public init?(text: String) {
        var value = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { return nil }
        if let scheme = value.range(of: "://") {
            value = String(value[scheme.upperBound...])
        }
        if let cut = value.firstIndex(where: { $0 == "/" || $0 == "?" || $0 == "#" }) {
            value = String(value[..<cut])
        }
        guard !value.isEmpty else { return nil }

        guard let colon = value.lastIndex(of: ":") else {
            self.host = value
            self.port = Self.defaultPort
            return
        }
        let hostPart = String(value[value.startIndex..<colon])
        let portPart = String(value[value.index(after: colon)...])
        guard !hostPart.isEmpty, let parsed = UInt16(portPart), parsed != 0 else { return nil }
        self.host = hostPart
        self.port = parsed
    }

    public init(host: String, port: UInt16 = NodeAddress.defaultPort) {
        self.host = host
        self.port = port
    }
}

/// 当前生效的对局密钥 —— 上报端唯一需要的密钥视图。
///
/// `sha256` 与 `key_id` 都由 material 现算，不接受外部传入：服务端会逐项重算
/// （`key_id == sha256[:16]` 且 `sha256(material) == sha256`），自己先算好就
/// 不可能送出对不上的组合。
public struct UploadKey: Equatable {
    /// RawDH 战斗材料固定 128 字节
    public static let materialBytes = 128
    /// key_id 取 sha256 前 16 位
    public static let keyIDLength = 16

    /// 材料所属会话，用于「同材料但换了会话 = 新一局」的更换判定
    public let session: String
    public let material: [UInt8]
    public let sha256: String
    public let keyID: String
    /// 观察时间（毫秒）。服务端按它判密钥新旧，断线补发乱序也不会倒回去
    public let observedMS: UInt64
    /// 是否已用真实战斗包验证过。false 也照发 —— 置信度不是发送前提
    public let verified: Bool

    public init?(session: String, material: [UInt8], observedMS: UInt64, verified: Bool) {
        guard material.count == Self.materialBytes else { return nil }
        let digest = Hex.encode(SHA256.hash(data: Data(material)))
        self.session = session
        self.material = material
        self.sha256 = digest
        self.keyID = String(digest.prefix(Self.keyIDLength))
        self.observedMS = observedMS
        self.verified = verified
    }

    /// 从证据落盘的候选直接构造。
    public init?(candidate: KeyCandidate, observedMS: UInt64, verified: Bool) {
        self.init(
            session: candidate.session,
            material: candidate.material,
            observedMS: observedMS,
            verified: verified
        )
    }

    /// 从十六进制文本还原材料 —— 界面上的「手动覆盖」用。
    /// 长度不是 128 字节、或含非 `[0-9a-fA-F]` 字符一律返回 nil。
    public static func material(fromHex text: String) -> [UInt8]? {
        guard let bytes = Hex.decode(text.trimmingCharacters(in: .whitespacesAndNewlines)),
              bytes.count == materialBytes else { return nil }
        return bytes
    }
}

/// 业务消息的 JSON 文本。字段与 `WsMirrorServer.cs` 的 `HandleBattleKey` /
/// `Dispatch` 逐项对应：`key_id`、`sha256`、`material` 三项校验，`observed_ms`
/// 与 `verified` 缺省即 0/false，`batch` 条目的 `k` 可缺省（沿用房间当前密钥）。
public enum ReporterPayload {
    public static func battleKey(_ key: UploadKey) -> String {
        "{\"type\":\"battle_key\",\"key_id\":\"\(key.keyID)\",\"sha256\":\"\(key.sha256)\","
            + "\"material\":\"\(Data(key.material).base64EncodedString())\","
            + "\"observed_ms\":\(key.observedMS),\"verified\":\(key.verified)}"
    }

    public static func batch(_ packets: [UploadPacket]) -> String {
        var items: [String] = []
        items.reserveCapacity(packets.count)
        for packet in packets {
            let data = Data(packet.datagram).base64EncodedString()
            if let keyID = packet.keyID {
                items.append("{\"data\":\"\(data)\",\"k\":\"\(keyID)\"}")
            } else {
                items.append("{\"data\":\"\(data)\"}")
            }
        }
        return "{\"batch\":[\(items.joined(separator: ","))]}"
    }

    /// 心跳。服务端只要在明文里看到 `"ping"` 就回 pong，这里给规范写法
    public static let ping = "{\"type\":\"ping\"}"
}

/// 上报端计数快照，字段与原实现 `CaptureStatus.upload` 对齐。
public struct ReporterStats: Equatable {
    /// 已连上且握手完成
    public var connected = false
    /// 累计成功发送
    public var sent = 0
    /// 累计补包条数（发出时所在代次落后于当前连接的包）
    public var resent = 0
    /// 因队列溢出丢弃的条数
    public var dropped = 0
    /// 当前排队条数
    public var queued = 0
    /// 当前待补发积压条数
    public var replay = 0
    /// 累计重连次数
    public var reconnects = 0
    /// 当前生效的密钥版本（空 = 尚未拿到密钥）
    public var keyID: String?
    /// 鉴权被拒（硬失败，不再重连）
    public var authFailed = false
    public var lastError: String?

    public init() {}
}

/// 一条 WebSocket 通道。真实现走 `NWConnection`，单测里换成脚本化的假通道。
public protocol ReporterTransport: AnyObject {
    var onOpen: (() -> Void)? { get set }
    var onText: ((String) -> Void)? { get set }
    var onClose: ((String) -> Void)? { get set }

    func connect(host: String, port: UInt16)
    /// 写成功（帧真正落到 socket）回调 true；写超时或失败回调 false
    func send(_ text: String, completion: @escaping (Bool) -> Void)
    func close()
}

public protocol ReporterScheduledTask: AnyObject {
    func cancel()
}

/// 时钟 + 定时器。抽出来是为了能在单测里把 5s 心跳、1~5s 退避压成同步推进。
public protocol ReporterScheduler: AnyObject {
    var now: TimeInterval { get }
    func schedule(after delay: TimeInterval, _ body: @escaping () -> Void) -> ReporterScheduledTask
}

public final class DispatchReporterScheduler: ReporterScheduler {
    private let queue: DispatchQueue

    public init(queue: DispatchQueue) {
        self.queue = queue
    }

    public var now: TimeInterval { ProcessInfo.processInfo.systemUptime }

    public func schedule(after delay: TimeInterval, _ body: @escaping () -> Void) -> ReporterScheduledTask {
        let item = DispatchWorkItem(block: body)
        queue.asyncAfter(deadline: .now() + max(0, delay), execute: item)
        return DispatchTask(item: item)
    }

    private final class DispatchTask: ReporterScheduledTask {
        private let item: DispatchWorkItem

        init(item: DispatchWorkItem) {
            self.item = item
        }

        func cancel() {
            item.cancel()
        }
    }
}

/// 上报端：连接节点、握手、下发密钥、批量上报、断线重连续发。
///
/// ```
/// Run（外层循环）
///  ├─ session：拨号 → 握手 → connected
///  │    ├─ markKeyDirty()   ← 新连接密钥必须重发（转发器侧状态可能已丢）
///  │    ├─ Kick()           ← 排空：先密钥，再积压报文
///  │    ├─ 心跳（5s）
///  │    └─ 读循环（阻塞，出错即断）
///  ├─ 退避 1s 起、每次 ×2、上限 5s（只增不减）
///  └─ 鉴权被拒 / stop() → 清空队列退出
/// ```
///
/// 状态全部跑在 `work` 这个串行队列上；对外方法一律投递进去，所以调用方
/// （抓包线程、界面）怎么并发调都不会把内部状态搅乱。
public final class WSReporter {
    public struct Config {
        public var address: NodeAddress
        /// 房间 Key：既是预共享密钥（派生会话密钥）也是房间号，32 位 hex
        public var apiKey: String
        /// 单批最大报文数
        public var batchMax: Int
        /// 队列上限（超出丢最旧）
        public var queueLimit: Int
        /// 单批写超时，用来发现半开连接
        public var writeTimeout: TimeInterval
        /// 拨号 + WebSocket 握手超时
        public var dialTimeout: TimeInterval
        /// 等待服务端 challenge / secure_ok 的时间
        public var authWait: TimeInterval
        /// 心跳间隔
        public var pingInterval: TimeInterval
        /// 收到过 pong 之后的读超时
        public var pongWait: TimeInterval
        public var reconnectMin: TimeInterval
        public var reconnectMax: TimeInterval
        /// 自动重连期间的失败日志节流间隔
        public var failureLogInterval: TimeInterval

        public init(
            address: NodeAddress,
            apiKey: String,
            batchMax: Int = UploadQueue.defaultBatchMax,
            queueLimit: Int = UploadQueue.defaultLimit,
            writeTimeout: TimeInterval = 5,
            dialTimeout: TimeInterval = 8,
            authWait: TimeInterval = 8,
            pingInterval: TimeInterval = 5,
            pongWait: TimeInterval = 10,
            reconnectMin: TimeInterval = 1,
            reconnectMax: TimeInterval = 5,
            failureLogInterval: TimeInterval = 10
        ) {
            self.address = address
            self.apiKey = apiKey
            self.batchMax = max(1, batchMax)
            self.queueLimit = max(1, queueLimit)
            self.writeTimeout = writeTimeout
            self.dialTimeout = dialTimeout
            self.authWait = authWait
            self.pingInterval = pingInterval
            self.pongWait = pongWait
            self.reconnectMin = max(0.01, reconnectMin)
            self.reconnectMax = max(self.reconnectMin, reconnectMax)
            self.failureLogInterval = failureLogInterval
        }
    }

    public let config: Config

    private let work: DispatchQueue
    private let scheduler: ReporterScheduler
    private let transportFactory: () -> ReporterTransport
    private let log: (String) -> Void
    private let onAuthFailed: (String) -> Void

    private var uploads: UploadQueue
    private var currentKey: UploadKey?
    private var keyDirty = false
    private var running = false
    private var authFailed = false
    /// 连接代次，每次开始一条连接就 +1
    private var generation: UInt64 = 0
    private var backoff: TimeInterval
    private var lastFailureLogAt: TimeInterval?
    private var lastError: String?
    private var totalSent = 0
    private var totalResent = 0
    private var sending = false
    private var connection: Connection?
    private var reconnectTask: ReporterScheduledTask?

    /// 一次连接的运行态。回调都带着它，回来时先比对身份再动状态。
    private final class Connection {
        let sequence: UInt64
        let transport: ReporterTransport
        let handshake: SecureClientHandshake
        var channel: SecureChannel?
        var ready = false
        var closed = false
        var pongSeen = false
        var dialTask: ReporterScheduledTask?
        var authTask: ReporterScheduledTask?
        var pingTask: ReporterScheduledTask?
        var readTask: ReporterScheduledTask?

        init(sequence: UInt64, transport: ReporterTransport, handshake: SecureClientHandshake) {
            self.sequence = sequence
            self.transport = transport
            self.handshake = handshake
        }
    }

    public init(
        config: Config,
        queue: DispatchQueue = DispatchQueue(label: "starradar.uploader"),
        scheduler: ReporterScheduler? = nil,
        transportFactory: (() -> ReporterTransport)? = nil,
        log: @escaping (String) -> Void,
        onAuthFailed: @escaping (String) -> Void = { _ in }
    ) {
        self.config = config
        self.work = queue
        self.scheduler = scheduler ?? DispatchReporterScheduler(queue: queue)
        self.transportFactory = transportFactory ?? {
            // 这里只能抓 `log` 形参，不能写 self —— 此刻成员还没初始化完
            WebSocketTransport(
                queue: queue,
                writeTimeout: config.writeTimeout,
                dialTimeout: config.dialTimeout,
                diagnostics: { log("[ws] \($0)") }
            )
        }
        self.log = log
        self.onAuthFailed = onAuthFailed
        self.uploads = UploadQueue(limit: config.queueLimit)
        self.backoff = config.reconnectMin
    }

    // MARK: - 对外接口

    public func start() {
        work.async {
            guard !self.running else { return }
            self.running = true
            self.authFailed = false
            self.backoff = self.config.reconnectMin
            self.connect()
        }
    }

    public func stop() {
        work.async {
            guard self.running || self.connection != nil else { return }
            self.running = false
            self.shutdown()
        }
    }

    /// 换密钥。同一局同一把材料不重发；材料变了或会话变了都立刻下发一次。
    public func setKey(_ key: UploadKey?) {
        work.async {
            if let key, let current = self.currentKey,
               current.session == key.session, current.sha256 == key.sha256 {
                return
            }
            self.currentKey = key
            self.keyDirty = true
            self.kick()
        }
    }

    /// 投递一条完整 IP 数据报。密钥版本与连接代次都取**入队时**的值。
    public func enqueue(_ datagram: [UInt8]) {
        work.async {
            guard self.running, !self.authFailed else { return }
            self.uploads.enqueue(
                datagram,
                generation: self.generation,
                keyID: self.currentKey?.keyID,
                now: self.scheduler.now
            )
            self.kick()
        }
    }

    public func stats() -> ReporterStats {
        work.sync {
            var snapshot = ReporterStats()
            snapshot.connected = self.connection?.ready ?? false
            snapshot.sent = self.totalSent
            snapshot.resent = self.totalResent
            snapshot.dropped = self.uploads.dropped
            snapshot.queued = self.uploads.count
            snapshot.replay = self.uploads.replayBacklog(generation: self.generation)
            snapshot.reconnects = self.generation > 0 ? Int(self.generation - 1) : 0
            snapshot.keyID = self.currentKey?.keyID
            snapshot.authFailed = self.authFailed
            snapshot.lastError = self.lastError
            return snapshot
        }
    }

    // MARK: - 连接生命周期

    private func connect() {
        guard running, !authFailed else {
            shutdown()
            return
        }
        let handshake: SecureClientHandshake
        do {
            handshake = try SecureClientHandshake(apiKey: config.apiKey)
        } catch {
            // 配错了房间 Key 属于使用者的错，等同鉴权失败：重试一万次也不会变好
            authRejected("\(error)")
            return
        }

        generation += 1
        let transport = transportFactory()
        let connection = Connection(sequence: generation, transport: transport, handshake: handshake)
        self.connection = connection

        transport.onOpen = { [weak self] in self?.handleOpen(connection) }
        transport.onText = { [weak self] text in self?.handleText(connection, text) }
        transport.onClose = { [weak self] reason in self?.handleClose(connection, reason) }

        connection.dialTask = scheduler.schedule(after: config.dialTimeout) { [weak self] in
            self?.failSession(connection, "节点拨号超时（\(Int(self?.config.dialTimeout ?? 0))s）")
        }
        log("[ws] 正在连接节点 \(config.address.host):\(config.address.port)")
        transport.connect(host: config.address.host, port: config.address.port)
    }

    private func handleOpen(_ connection: Connection) {
        guard connection === self.connection, !connection.closed else { return }
        connection.dialTask?.cancel()
        connection.dialTask = nil
        log("[ws] 已连接节点 \(config.address.host):\(config.address.port)")

        // 明文首帧：握手①②是明文，之后一律加密
        send(connection, connection.handshake.hello()) { [weak self] ok in
            guard let self else { return }
            guard ok else {
                self.failSession(connection, "发送 secure_hello 失败")
                return
            }
            // challenge 可能先于写入完成回调到达（回调之间还隔着一次队列投递），
            // 这时它已经挂好了自己的等待计时器，不能被这里顶掉
            guard connection.channel == nil, !connection.ready else { return }
            connection.authTask?.cancel()
            connection.authTask = self.scheduler.schedule(after: self.config.authWait) { [weak self] in
                self?.failSession(connection, "等待 secure_challenge 超时")
            }
        }
    }

    private func handleText(_ connection: Connection, _ text: String) {
        guard connection === self.connection, !connection.closed else { return }
        if connection.channel == nil {
            handleChallenge(connection, text)
        } else if !connection.ready {
            handleSecureOK(connection, text)
        } else {
            handleBusiness(connection, text)
        }
    }

    private func handleChallenge(_ connection: Connection, _ text: String) {
        // 明文阶段服务端只说两件事：challenge，或者「你被拒了」
        if let object = JSONValue.parseObject(text), object["type"]?.stringValue == SecureWS.errorType {
            authRejected(object["msg"]?.stringValue ?? "服务端拒绝握手")
            return
        }
        do {
            let (channel, finish) = try connection.handshake.acceptChallenge(text)
            connection.channel = channel
            connection.authTask?.cancel()
            connection.authTask = scheduler.schedule(after: config.authWait) { [weak self] in
                self?.failSession(connection, "等待 secure_ok 超时")
            }
            send(connection, finish) { [weak self] ok in
                guard let self else { return }
                guard ok else {
                    self.failSession(connection, "发送 secure_finish 失败")
                    return
                }
            }
        } catch {
            // challenge 解不动多半是链路或对端版本不对，重连一次说不定就好
            failSession(connection, "握手失败：\(error)")
        }
    }

    private func handleSecureOK(_ connection: Connection, _ text: String) {
        let object: [String: JSONValue]
        do {
            object = try connection.channel?.decryptObject(text) ?? [:]
        } catch {
            failSession(connection, "加密帧校验失败：\(error)")
            return
        }
        if object["type"]?.stringValue == SecureWS.errorType {
            authRejected(object["msg"]?.stringValue ?? "服务端拒绝握手证明")
            return
        }
        guard object["type"]?.stringValue == SecureWS.okType,
              object["v"]?.intValue == SecureWS.version else {
            failSession(connection, "secure_ok 非法")
            return
        }

        connection.ready = true
        connection.authTask?.cancel()
        connection.authTask = nil
        log("[ws] 鉴权通过 room=\(SecureWS.roomID(config.apiKey).prefix(8))… "
            + "节点 \(config.address.host):\(config.address.port)")

        // 新连接上转发器可能已经把密钥状态丢了，必须重发一次
        keyDirty = true
        kick()
        startPing(connection)
    }

    private func handleBusiness(_ connection: Connection, _ text: String) {
        let object: [String: JSONValue]
        do {
            object = try connection.channel?.decryptObject(text) ?? [:]
        } catch {
            failSession(connection, "加密帧校验失败：\(error)")
            return
        }
        switch object["type"]?.stringValue {
        case "pong":
            connection.pongSeen = true
            // 只在收到过 pong 之后才启用读超时：服务端不实现心跳也不会被误判
            armReadDeadline(connection)
        case SecureWS.errorType:
            log("[ws] 服务端错误：\(object["msg"]?.stringValue ?? "未说明")")
        default:
            break
        }
    }

    private func startPing(_ connection: Connection) {
        connection.pingTask?.cancel()
        connection.pingTask = scheduler.schedule(after: config.pingInterval) { [weak self] in
            guard let self, connection === self.connection, connection.ready, !connection.closed else { return }
            self.send(connection, ReporterPayload.ping) { [weak self] ok in
                guard let self else { return }
                guard ok else {
                    self.failSession(connection, "心跳写入失败（半开连接）")
                    return
                }
                self.startPing(connection)
            }
        }
    }

    private func armReadDeadline(_ connection: Connection) {
        guard connection.pongSeen else { return }
        connection.readTask?.cancel()
        connection.readTask = scheduler.schedule(after: config.pongWait) { [weak self] in
            self?.failSession(connection, "读超时 \(Int(self?.config.pongWait ?? 0))s")
        }
    }

    private func handleClose(_ connection: Connection, _ reason: String) {
        guard connection === self.connection else { return }
        teardown(connection)
        if authFailed || !running {
            shutdown()
            return
        }
        logThrottled("[ws] 已断开（\(reason)），尝试重连…")
        scheduleReconnect()
    }

    private func failSession(_ connection: Connection, _ reason: String) {
        guard connection === self.connection else { return }
        teardown(connection)
        lastError = reason
        if authFailed || !running {
            shutdown()
            return
        }
        logThrottled("[ws] 连接失败（\(reason)），尝试重连…")
        scheduleReconnect()
    }

    private func scheduleReconnect() {
        let delay = backoff
        backoff = min(backoff * 2, config.reconnectMax)
        reconnectTask?.cancel()
        reconnectTask = scheduler.schedule(after: delay) { [weak self] in
            guard let self else { return }
            self.reconnectTask = nil
            self.connect()
        }
    }

    private func authRejected(_ reason: String) {
        guard !authFailed else { return }
        authFailed = true
        running = false
        lastError = reason
        log("[ws] 鉴权失败: \(reason)")
        onAuthFailed(reason)
        shutdown()
    }

    /// 摘掉当前连接并复位它挂的所有定时器。onClose 会由 transport.close() 触发，
    /// 这里先把回调摘干净，免得同一条连接被收尾两次。
    private func teardown(_ connection: Connection) {
        if connection === self.connection { self.connection = nil }
        connection.closed = true
        connection.ready = false
        for task in [connection.dialTask, connection.authTask, connection.pingTask, connection.readTask] {
            task?.cancel()
        }
        connection.dialTask = nil
        connection.authTask = nil
        connection.pingTask = nil
        connection.readTask = nil
        connection.transport.onOpen = nil
        connection.transport.onText = nil
        connection.transport.onClose = nil
        connection.transport.close()
        sending = false
    }

    /// `Run` 跳出循环后的收尾：停定时器、丢连接、清空队列。
    private func shutdown() {
        reconnectTask?.cancel()
        reconnectTask = nil
        if let connection { teardown(connection) }
        uploads.removeAll()
        sending = false
        log("[ws] 已停止")
    }

    // MARK: - 发送

    private func kick() {
        guard !sending else { return }
        sending = true
        drain()
    }

    private func drain() {
        guard running, let connection, connection.ready, !connection.closed else {
            sending = false
            return
        }
        guard keyDirty else {
            sendBatch(connection)
            return
        }
        sendKey(connection) { [weak self] ok in
            guard let self, ok else { return }
            self.sendBatch(connection)
        }
    }

    /// 密钥必须先于报文单独发一条：断线期间转发器侧可能已经把密钥状态丢了。
    private func sendKey(_ connection: Connection, completion: @escaping (Bool) -> Void) {
        guard let key = currentKey else {
            // 还没拿到密钥：报文按「无密钥房间」发，转发器那边也能收
            keyDirty = false
            completion(true)
            return
        }
        send(connection, ReporterPayload.battleKey(key)) { [weak self] ok in
            guard let self else { return }
            guard ok else {
                // 密钥丢了不能继续发包：保持 dirty，等重连再发
                self.failSession(connection, "密钥下发未完成（\(key.keyID.prefix(8))…），等待重连续发")
                completion(false)
                return
            }
            self.keyDirty = false
            completion(true)
        }
    }

    private func sendBatch(_ connection: Connection) {
        guard connection === self.connection, connection.ready, !connection.closed else {
            sending = false
            return
        }
        let batch = uploads.peekBatch(max: config.batchMax)
        guard let last = batch.last else {
            sending = false
            return
        }
        send(connection, ReporterPayload.batch(batch)) { [weak self] ok in
            guard let self else { return }
            guard ok else {
                // 整批留队：什么都不删，断开重连后从最旧的补起
                self.failSession(connection, "发送未完成（\(batch.count) 条），强制重连续发")
                return
            }
            let removed = self.uploads.dropPrefix(through: last.sequence)
            self.totalSent += removed.count
            self.totalResent += removed.filter { $0.generation < self.generation }.count
            self.sendBatch(connection)
        }
    }

    /// 加密（除握手首帧外）并写出。回调保证回到本对象的串行队列上。
    private func send(_ connection: Connection, _ text: String, completion: @escaping (Bool) -> Void) {
        guard !connection.closed else {
            completion(false)
            return
        }
        let wire: String
        if let channel = connection.channel {
            do {
                wire = try channel.encrypt(text)
            } catch {
                completion(false)
                return
            }
        } else {
            wire = text
        }
        connection.transport.send(wire) { [weak self] ok in
            guard let self else { return }
            self.work.async {
                guard connection === self.connection, !connection.closed else {
                    completion(false)
                    return
                }
                completion(ok)
            }
        }
    }

    // MARK: - 日志

    private func logThrottled(_ message: String) {
        let now = scheduler.now
        if let last = lastFailureLogAt, now - last < config.failureLogInterval { return }
        lastFailureLogAt = now
        log(message)
    }
}
