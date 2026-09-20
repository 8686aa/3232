import CryptoKit
import XCTest
@testable import StarRadarCore

// MARK: - 可控时钟

/// 手工推进的时钟 + 定时器，替代原实现的真实 5s 心跳 / 1~5s 退避。
/// `advance` 只把**到期**的任务交出来，由测试在 `work` 队列上执行 —— 这样
/// 定时器回调与上报端内部状态始终跑在同一个串行队列上，测起来完全确定。
final class FakeScheduler: ReporterScheduler {
    private(set) var now: TimeInterval = 0
    /// 按排期顺序记录所有延时，供退避断言使用
    private(set) var scheduledDelays: [TimeInterval] = []

    private struct Entry {
        let id: Int
        let deadline: TimeInterval
        let body: () -> Void
    }

    private var entries: [Entry] = []
    private var cancelled: Set<Int> = []
    private var nextID = 0

    func schedule(after delay: TimeInterval, _ body: @escaping () -> Void) -> ReporterScheduledTask {
        nextID += 1
        let id = nextID
        let value = max(0, delay)
        entries.append(Entry(id: id, deadline: now + value, body: body))
        scheduledDelays.append(value)
        return FakeTask { [weak self] in self?.cancelled.insert(id) }
    }

    /// 推进时钟，返回到期且未被取消的任务（先按到期时间，再按排期先后）
    func advance(_ delta: TimeInterval) -> [() -> Void] {
        now += max(0, delta)
        return takeDue()
    }

    /// 推进到最近一个未取消任务的到期时刻 —— 不必知道退避到底排了多久
    func advanceToNextDeadline() -> [() -> Void] {
        guard let next = entries.filter({ !cancelled.contains($0.id) }).map(\.deadline).min() else {
            return []
        }
        now = max(now, next)
        return takeDue()
    }

    var pendingCount: Int { entries.filter { !cancelled.contains($0.id) }.count }

    private func takeDue() -> [() -> Void] {
        let due = entries
            .filter { !cancelled.contains($0.id) && $0.deadline <= now }
            .sorted { ($0.deadline, $0.id) < ($1.deadline, $1.id) }
        let ids = Set(due.map(\.id))
        entries.removeAll { ids.contains($0.id) }
        return due.map(\.body)
    }
}

private final class FakeTask: ReporterScheduledTask {
    private let onCancel: () -> Void

    init(_ onCancel: @escaping () -> Void) {
        self.onCancel = onCancel
    }

    func cancel() {
        onCancel()
    }
}

// MARK: - 假通道

/// 脚本化的通道：写结果可控，收帧由测试显式投递。
/// `send` 的完成回调是**同步**的 —— 上报端内部还会把它再投递回自己的队列，
/// 所以时序与真实网络一致（完成回调永远晚于本次发送返回）。
final class FakeTransport: ReporterTransport {
    var onOpen: (() -> Void)?
    var onText: ((String) -> Void)?
    var onClose: ((String) -> Void)?

    private(set) var host: String?
    private(set) var port: UInt16?
    private(set) var outbound: [String] = []
    private(set) var closeCount = 0
    private(set) var writesAfterClose = 0
    /// 写结果：false 模拟半开连接（写不出去）
    var sendResult = true
    var onOutbound: ((String) -> Void)?

    private var closed = false

    func connect(host: String, port: UInt16) {
        self.host = host
        self.port = port
    }

    func send(_ text: String, completion: @escaping (Bool) -> Void) {
        guard !closed else {
            writesAfterClose += 1
            completion(false)
            return
        }
        outbound.append(text)
        // 写失败 = 对端没收到，所以不通知服务端 —— 否则假服务端会收到实际没上线的帧
        if sendResult { onOutbound?(text) }
        completion(sendResult)
    }

    func close() {
        closed = true
        closeCount += 1
    }

    // 测试驱动
    func open() { onOpen?() }
    func deliver(_ text: String) { onText?(text) }
    func drop(_ reason: String) { onClose?(reason) }
}

// MARK: - 假服务端

/// 按 `WsMirrorServer.cs` 的语义在测试侧扮演转发器：明文 hello → 明文 challenge →
/// 加密 finish（校验客户端 proof）→ 加密 secure_ok，之后一律走 `enc` 信封。
/// 每条连接独立握手，房间级密钥由上报端重发 —— 这正是要验证的行为。
final class FakeServer {
    let apiKey: String
    let serverNonce: [UInt8]

    private(set) var rawFrames: [String] = []
    /// 解密后的业务明文（`secure_finish` 不计入）
    private(set) var business: [[String: JSONValue]] = []
    private(set) var helloCount = 0
    private(set) var finishCount = 0
    private(set) var finishAccepted = false
    private(set) var pings = 0

    /// 行为开关
    var challengeError: String?
    var rejectFinish = false
    var respondToPing = true

    private var channel: SecureChannel?
    private var keys: SecureWS.SessionKeys?
    private var transcript: String?
    private var pending: [String] = []
    private weak var transport: FakeTransport?

    init(apiKey: String, serverNonce: [UInt8]) {
        self.apiKey = apiKey
        self.serverNonce = serverNonce
    }

    var battleKeys: [[String: JSONValue]] {
        business.filter { $0["type"]?.stringValue == "battle_key" }
    }

    var batches: [[JSONValue]] {
        business.compactMap { $0["batch"]?.elements }
    }

    var hasPending: Bool { !pending.isEmpty }

    func attach(_ transport: FakeTransport) {
        self.transport = transport
        channel = nil
        keys = nil
        transcript = nil
        pending.removeAll()
        transport.onOutbound = { [weak self] text in self?.observe(text) }
    }

    @discardableResult
    func deliverNext() -> Bool {
        guard !pending.isEmpty, let transport = self.transport else { return false }
        transport.deliver(pending.removeFirst())
        return true
    }

    func observe(_ text: String) {
        rawFrames.append(text)
        guard let channel = self.channel else {
            handleHello(text)
            return
        }
        guard let plain = try? channel.decrypt(text) else { return }
        let decoded = String(decoding: plain, as: UTF8.self)
        guard let object = JSONValue.parseObject(decoded) else { return }
        if object["type"]?.stringValue == SecureWS.finishType {
            handleFinish(object)
            return
        }
        business.append(object)
        if object["type"]?.stringValue == "ping" {
            pings += 1
            if respondToPing { encryptAndQueue("{\"type\":\"pong\"}") }
        }
    }

    private func handleHello(_ text: String) {
        guard let object = JSONValue.parseObject(text),
              object["type"]?.stringValue == SecureWS.helloType else { return }
        helloCount += 1
        guard let clientNonce = try? SecureWS.decodeNonce(object["nonce"]?.stringValue, name: "客户端 nonce"),
              clientNonce.count == SecureWS.nonceBytes else { return }

        if let error = challengeError {
            pending.append("{\"type\":\"error\",\"msg\":\"\(error)\"}")
            return
        }
        guard let keys = try? SecureWS.deriveKeys(
            apiKey: apiKey,
            clientNonce: clientNonce,
            serverNonce: serverNonce
        ) else { return }
        self.keys = keys
        self.channel = try? SecureChannel(keys: keys, outboundDir: SecureWS.dirS2C)
        let transcript = SecureWS.buildTranscript(
            room: SecureWS.roomID(apiKey),
            clientNonce: clientNonce,
            serverNonce: serverNonce
        )
        self.transcript = transcript
        pending.append(
            "{\"type\":\"secure_challenge\",\"v\":\(SecureWS.version),"
                + "\"nonce\":\"\(Hex.encode(serverNonce))\","
                + "\"proof\":\"\(SecureWS.buildProof(keys: keys, transcript: transcript, side: "server"))\"}"
        )
    }

    private func handleFinish(_ object: [String: JSONValue]) {
        finishCount += 1
        guard let keys = self.keys, let transcript = self.transcript else { return }
        let expected = SecureWS.buildProof(keys: keys, transcript: transcript, side: "client")
        let supplied = (object["proof"]?.stringValue ?? "").lowercased()
        guard !rejectFinish, SecureWS.constantTimeEquals(supplied, expected) else {
            encryptAndQueue("{\"type\":\"error\",\"msg\":\"握手证明不通过\"}")
            return
        }
        finishAccepted = true
        encryptAndQueue("{\"type\":\"secure_ok\",\"v\":\(SecureWS.version)}")
    }

    private func encryptAndQueue(_ text: String) {
        guard let channel = self.channel, let wire = try? channel.encrypt(text) else { return }
        pending.append(wire)
    }
}

// MARK: - 测试台

final class ReporterHarness {
    let queue = DispatchQueue(label: "starradar.reporter.tests")
    let scheduler = FakeScheduler()
    let config: WSReporter.Config

    private(set) var transports: [FakeTransport] = []
    /// 每次拨号的时刻，用来验证退避只增不减
    private(set) var connectionTimes: [TimeInterval] = []
    private(set) var logs: [String] = []
    private(set) var authFailures: [String] = []

    let server: FakeServer
    private(set) var reporter: WSReporter! = nil

    /// 新通道的默认写结果
    private var transportSendResult = true

    init(apiKey: String? = nil, serverNonce: [UInt8]? = nil) {
        let key = apiKey ?? "00112233445566778899aabbccddeeff"
        let nonce = serverNonce ?? [UInt8](repeating: 0x5A, count: SecureWS.nonceBytes)
        server = FakeServer(apiKey: key, serverNonce: nonce)
        config = WSReporter.Config(
            address: NodeAddress(host: "127.0.0.1", port: 1082),
            apiKey: key
        )

        reporter = WSReporter(
            config: config,
            queue: queue,
            scheduler: scheduler,
            transportFactory: { [unowned self] in
                let transport = FakeTransport()
                transport.sendResult = self.transportSendResult
                self.transports.append(transport)
                self.connectionTimes.append(self.scheduler.now)
                self.server.attach(transport)
                return transport
            },
            log: { [unowned self] in self.logs.append($0) },
            onAuthFailed: { [unowned self] in self.authFailures.append($0) }
        )
    }

    var current: FakeTransport { transports[transports.count - 1] }

    /// 让当前通道写不出去（半开连接）
    func failWrites() {
        transportSendResult = false
        for transport in transports { transport.sendResult = false }
    }

    /// 恢复写能力：只影响之后新建的通道
    func recoverWrites() {
        transportSendResult = true
    }

    /// 跑完已投递到 work 队列上的所有回调。多跑几轮：完成回调之间还会互相排队
    func settle(_ rounds: Int = 8) {
        for _ in 0..<rounds { _ = reporter.stats() }
    }

    func start() {
        reporter.start()
        settle()
    }

    /// 让当前连接「拨号成功」
    func openConnection() {
        settle()
        guard let transport = transports.last else { return }
        queue.sync { transport.open() }
        settle()
    }

    /// 反复：先跑完回调，再投递一帧服务端待发帧
    func pump(maxSteps: Int = 64) {
        settle()
        for _ in 0..<maxSteps {
            let delivered = queue.sync { server.deliverNext() }
            guard delivered else { break }
            settle()
        }
    }

    @discardableResult
    func advance(_ delta: TimeInterval) -> Int {
        let bodies = scheduler.advance(delta)
        run(bodies)
        return bodies.count
    }

    @discardableResult
    func advanceToNextDeadline() -> Int {
        let bodies = scheduler.advanceToNextDeadline()
        run(bodies)
        return bodies.count
    }

    private func run(_ bodies: [() -> Void]) {
        for body in bodies { queue.sync(execute: body) }
        settle()
    }
}

// MARK: - 测试

final class WSReporterTests: XCTestCase {
    private let apiKey = "00112233445566778899aabbccddeeff"

    private func datagram(_ value: UInt8, count: Int = 32) -> [UInt8] {
        [UInt8](repeating: value, count: count)
    }

    private func material(_ value: UInt8) -> [UInt8] {
        [UInt8](repeating: value, count: UploadKey.materialBytes)
    }

    private func uploadKey(session: String = "s1", byte: UInt8 = 0x11, observedMS: UInt64 = 1_700_000_000_000)
        throws -> UploadKey {
        try XCTUnwrap(
            UploadKey(session: session, material: material(byte), observedMS: observedMS, verified: true)
        )
    }

    // MARK: - UploadQueue

    func testQueueSkipsEmptyDatagramsAndKeepsSequenceMonotonic() {
        var queue = UploadQueue(limit: 10)
        XCTAssertNil(queue.enqueue([], generation: 1, keyID: nil, now: 0))
        XCTAssertTrue(queue.isEmpty)
        // 空报文不占序号：第一条有效报文仍是 1
        XCTAssertEqual(queue.enqueue(datagram(1), generation: 1, keyID: nil, now: 0)?.sequence, 1)
        XCTAssertEqual(queue.enqueue(datagram(2), generation: 1, keyID: nil, now: 0)?.sequence, 2)
        XCTAssertEqual(queue.limit, 10)
        XCTAssertEqual(UploadQueue(limit: 0).limit, 1)
        XCTAssertEqual(UploadQueue.defaultLimit, 20000)
        XCTAssertEqual(UploadQueue.defaultBatchMax, 40)
    }

    func testQueueDropsOldestOnOverflow() {
        var queue = UploadQueue(limit: 3)
        for value in 1...5 {
            queue.enqueue(datagram(UInt8(value)), generation: 1, keyID: nil, now: 0)
        }
        XCTAssertEqual(queue.count, 3)
        XCTAssertEqual(queue.dropped, 2)
        XCTAssertEqual(queue.peekBatch().map(\.sequence), [3, 4, 5])
    }

    func testQueueDropPrefixRemovesOnlyConfirmedRange() {
        var queue = UploadQueue(limit: 10)
        queue.enqueue(datagram(1), generation: 1, keyID: "k1", now: 0)
        let second = queue.enqueue(datagram(2), generation: 1, keyID: "k1", now: 0)
        queue.enqueue(datagram(3), generation: 1, keyID: "k1", now: 0)

        XCTAssertEqual(queue.peekBatch(max: 2).map(\.sequence), [1, 2])
        XCTAssertEqual(queue.dropPrefix(through: 0).map(\.sequence), [])
        XCTAssertEqual(queue.dropPrefix(through: second!.sequence).map(\.sequence), [1, 2])
        XCTAssertEqual(queue.count, 1)
        XCTAssertEqual(queue.peekBatch().first?.sequence, 3)
    }

    /// 取批与写完成之间可能又溢出丢包，按 seq 删才不会误删没发出去的
    func testQueueDropPrefixIsSafeAfterOverflow() {
        var queue = UploadQueue(limit: 3)
        for value in 1...5 {
            queue.enqueue(datagram(UInt8(value)), generation: 1, keyID: nil, now: 0)
        }
        XCTAssertEqual(queue.dropPrefix(through: 3).map(\.sequence), [3])
        XCTAssertEqual(queue.count, 2)
        XCTAssertEqual(queue.peekBatch().map(\.sequence), [4, 5])
    }

    func testQueueReplayBacklogCountsLeadingOlderGenerations() {
        var queue = UploadQueue(limit: 10)
        queue.enqueue(datagram(1), generation: 1, keyID: nil, now: 0)
        queue.enqueue(datagram(2), generation: 1, keyID: nil, now: 0)
        queue.enqueue(datagram(3), generation: 2, keyID: nil, now: 0)
        queue.enqueue(datagram(4), generation: 2, keyID: nil, now: 0)

        XCTAssertEqual(queue.replayBacklog(generation: 2), 2)
        XCTAssertEqual(queue.replayBacklog(generation: 3), 4)
        XCTAssertEqual(queue.replayBacklog(generation: 1), 0)
        XCTAssertEqual(queue.replayBacklog(generation: 2), 2)

        let head = queue.peekBatch().first!
        queue.dropPrefix(through: head.sequence)
        XCTAssertEqual(queue.replayBacklog(generation: 2), 1)
    }

    func testQueuePeekBatchRespectsMax() {
        var queue = UploadQueue(limit: 10)
        XCTAssertTrue(queue.peekBatch().isEmpty)
        queue.enqueue(datagram(1), generation: 1, keyID: nil, now: 0)
        XCTAssertTrue(queue.peekBatch(max: 0).isEmpty)
        XCTAssertEqual(queue.peekBatch(max: 5).count, 1)
        queue.removeAll()
        XCTAssertTrue(queue.isEmpty)
    }

    // MARK: - NodeAddress

    func testNodeAddressNormalizesText() {
        XCTAssertEqual(NodeAddress(text: "123.99.198.158"), NodeAddress(host: "123.99.198.158", port: 1082))
        XCTAssertEqual(NodeAddress(text: "123.99.198.158:1082"), NodeAddress(host: "123.99.198.158", port: 1082))
        XCTAssertEqual(NodeAddress(text: "ws://123.99.198.158"), NodeAddress(host: "123.99.198.158", port: 1082))
        XCTAssertEqual(NodeAddress(text: "ws://123.99.198.158:2099/"), NodeAddress(host: "123.99.198.158", port: 2099))
        XCTAssertEqual(
            NodeAddress(text: "  wss://example.com:443/path?x=1#y  "),
            NodeAddress(host: "example.com", port: 443)
        )
        XCTAssertEqual(NodeAddress(text: "example.com:1")?.port, 1)
        XCTAssertEqual(NodeAddress.defaultPort, 1082)
    }

    func testNodeAddressRejectsMalformedText() {
        for text in ["", "   ", "ws://", ":1082", "host:", "host:0", "host:65536", "host:abc", "ws://:1082"] {
            XCTAssertNil(NodeAddress(text: text), "「\(text)」不该被接受")
        }
    }

    // MARK: - UploadKey

    func testUploadKeyDerivesSHA256AndKeyID() throws {
        let bytes = material(0x7F)
        let key = try XCTUnwrap(
            UploadKey(session: "s9", material: bytes, observedMS: 42, verified: false)
        )
        let digest = Hex.encode(SHA256.hash(data: Data(bytes)))
        XCTAssertEqual(key.sha256, digest)
        XCTAssertEqual(key.keyID, String(digest.prefix(16)))
        XCTAssertEqual(key.keyID.count, UploadKey.keyIDLength)
        XCTAssertEqual(key.session, "s9")
        XCTAssertEqual(key.observedMS, 42)
        XCTAssertFalse(key.verified)
        XCTAssertEqual(UploadKey.materialBytes, 128)
    }

    func testUploadKeyRejectsWrongMaterialLength() {
        for count in [0, 16, 127, 129, 256] {
            XCTAssertNil(
                UploadKey(
                    session: "s1",
                    material: [UInt8](repeating: 1, count: count),
                    observedMS: 0,
                    verified: false
                ),
                "\(count) 字节不该被接受"
            )
        }
    }

    func testUploadKeyFromCandidate() throws {
        let candidate = KeyCandidate(
            session: "session-7",
            upstream: .init(host: "10.0.0.1", port: 65010),
            command: 16403,
            sequence: 3,
            layer: "plain",
            offset: 4,
            material: material(0x2A),
            sourceContext: [1, 2, 3],
            contextStart: 2
        )
        let key = try XCTUnwrap(UploadKey(candidate: candidate, observedMS: 99, verified: true))
        XCTAssertEqual(key.session, "session-7")
        XCTAssertEqual(key.material, candidate.material)
        XCTAssertEqual(key.sha256, Hex.encode(SHA256.hash(data: Data(candidate.material))))
        XCTAssertEqual(key.keyID, String(key.sha256.prefix(16)))
    }

    // MARK: - ReporterPayload

    func testBattleKeyPayloadMatchesServerExpectations() throws {
        let key = try uploadKey()
        let object = try XCTUnwrap(JSONValue.parseObject(ReporterPayload.battleKey(key)))

        XCTAssertEqual(object["type"]?.stringValue, "battle_key")
        XCTAssertEqual(object["key_id"]?.stringValue, key.keyID)
        XCTAssertEqual(object["sha256"]?.stringValue, key.sha256)
        XCTAssertEqual(object["observed_ms"]?.uint64Value, key.observedMS)
        XCTAssertEqual(object["verified"]?.boolValue, true)

        // 服务端会 base64 解出来核 128 字节 + 重算 sha256，这里先自己核一遍
        let encoded = try XCTUnwrap(object["material"]?.stringValue)
        let decoded = try XCTUnwrap(Data(base64Encoded: encoded))
        XCTAssertEqual([UInt8](decoded), key.material)
        XCTAssertEqual(Hex.encode(SHA256.hash(data: decoded)), key.sha256)
        XCTAssertEqual(key.keyID, String(key.sha256.prefix(UploadKey.keyIDLength)))
    }

    func testBatchPayloadOmitsMissingKeyID() throws {
        let withKey = UploadPacket(
            sequence: 1, generation: 1, keyID: "0123456789abcdef", enqueuedAt: 0, datagram: datagram(1)
        )
        let withoutKey = UploadPacket(
            sequence: 2, generation: 1, keyID: nil, enqueuedAt: 0, datagram: datagram(2, count: 8)
        )
        let object = try XCTUnwrap(
            JSONValue.parseObject(ReporterPayload.batch([withKey, withoutKey]))
        )
        let items = try XCTUnwrap(object["batch"]?.elements)
        XCTAssertEqual(items.count, 2)

        XCTAssertEqual(items[0]["k"]?.stringValue, "0123456789abcdef")
        let first = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(items[0]["data"]?.stringValue)))
        XCTAssertEqual([UInt8](first), withKey.datagram)

        XCTAssertNil(items[1]["k"])
        let second = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(items[1]["data"]?.stringValue)))
        XCTAssertEqual([UInt8](second), withoutKey.datagram)
    }

    func testBatchAndPingPayloadShape() throws {
        let object = try XCTUnwrap(JSONValue.parseObject(ReporterPayload.batch([])))
        XCTAssertEqual(object["batch"]?.elements?.count, 0)
        XCTAssertEqual(ReporterPayload.ping, "{\"type\":\"ping\"}")
    }

    // MARK: - 全流程

    func testHandshakeSendsKeyBeforeBatchesAndDrainsQueue() throws {
        let h = ReporterHarness()
        let key = try uploadKey()
        h.reporter.setKey(key)
        h.start()
        h.openConnection()
        h.pump()

        var stats = h.reporter.stats()
        XCTAssertTrue(stats.connected)
        XCTAssertEqual(stats.keyID, key.keyID)
        XCTAssertEqual(stats.reconnects, 0)
        XCTAssertNil(stats.lastError)
        XCTAssertEqual(h.server.helloCount, 1)
        XCTAssertTrue(h.server.finishAccepted)

        // 密钥必须先于报文单独发一条
        XCTAssertEqual(h.server.business.count, 1)
        XCTAssertEqual(h.server.business.first?["type"]?.stringValue, "battle_key")

        for value in 1...3 {
            h.reporter.enqueue(datagram(UInt8(value)))
        }
        h.settle()

        stats = h.reporter.stats()
        XCTAssertEqual(stats.sent, 3)
        XCTAssertEqual(stats.queued, 0)
        XCTAssertEqual(stats.replay, 0)
        XCTAssertEqual(stats.resent, 0)

        let batches = h.server.batches
        // 批的切分时机不是契约（每次 enqueue 各自 kick，首批发几条取决于调度），
        // 只锁「3 条都发到、顺序不变、带 key、内容对」
        let sent = batches.flatMap { $0 }
        XCTAssertEqual(sent.count, 3)
        XCTAssertEqual(sent.map { $0["k"]?.stringValue }, Array(repeating: key.keyID, count: 3))
        for (index, item) in sent.enumerated() {
            let payload = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(item["data"]?.stringValue)))
            XCTAssertEqual([UInt8](payload), datagram(UInt8(index + 1)))
        }
    }

    func testKeyAndMaterialAreTheOnlyResendTriggers() throws {
        let h = ReporterHarness()
        let first = try uploadKey(byte: 0x11)
        h.reporter.setKey(first)
        h.start()
        h.openConnection()
        h.pump()
        XCTAssertEqual(h.server.battleKeys.count, 1)

        // 同一局、同一材料：不重发
        h.reporter.setKey(first)
        h.settle()
        XCTAssertEqual(h.server.battleKeys.count, 1)

        // 同材料但换会话 = 新一局：重发
        let sameBytesNewSession = try uploadKey(session: "s2", byte: 0x11)
        h.reporter.setKey(sameBytesNewSession)
        h.settle()
        XCTAssertEqual(h.server.battleKeys.count, 2)

        // 材料变了：重发
        let second = try uploadKey(session: "s2", byte: 0x22)
        h.reporter.setKey(second)
        h.settle()
        XCTAssertEqual(h.server.battleKeys.count, 3)
        XCTAssertEqual(h.server.battleKeys.last?["key_id"]?.stringValue, second.keyID)
        XCTAssertEqual(h.reporter.stats().keyID, second.keyID)
    }

    func testFailedBatchStaysQueuedAndIsResentAfterReconnect() throws {
        let h = ReporterHarness()
        h.start()
        h.openConnection()
        h.pump()
        XCTAssertTrue(h.reporter.stats().connected)

        // 写不出去：半开连接
        h.failWrites()
        for value in 1...3 {
            h.reporter.enqueue(datagram(UInt8(value)))
        }
        h.settle()

        var stats = h.reporter.stats()
        XCTAssertFalse(stats.connected)
        XCTAssertEqual(stats.sent, 0)
        XCTAssertEqual(stats.queued, 3, "整批必须留队")
        XCTAssertEqual(stats.dropped, 0)
        XCTAssertEqual(h.transports[0].closeCount, 1)
        XCTAssertTrue(stats.lastError?.contains("发送未完成") ?? false, "实际：\(stats.lastError ?? "nil")")
        XCTAssertEqual(h.server.batches.count, 0)

        // 恢复写能力，退避后重连
        h.recoverWrites()
        h.advanceToNextDeadline()
        XCTAssertEqual(h.transports.count, 2)
        h.openConnection()
        h.pump()

        stats = h.reporter.stats()
        XCTAssertTrue(stats.connected)
        XCTAssertEqual(stats.sent, 3)
        XCTAssertEqual(stats.resent, 3, "3 条都是上一条连接遗留的")
        XCTAssertEqual(stats.queued, 0)
        XCTAssertEqual(stats.reconnects, 1)

        let batches = h.server.batches
        XCTAssertEqual(batches.count, 1)
        XCTAssertEqual(batches[0].count, 3)
        XCTAssertNil(batches[0][0]["k"], "入队时还没有密钥，条目不带 k")
    }

    func testFailedKeyPushKeepsKeyDirtyAcrossReconnect() throws {
        let h = ReporterHarness(apiKey: apiKey)
        h.start()
        h.openConnection()
        h.pump()

        h.failWrites()
        let key = try uploadKey()
        h.reporter.setKey(key)
        h.settle()

        XCTAssertFalse(h.reporter.stats().connected)
        XCTAssertEqual(h.server.battleKeys.count, 0, "写失败不该留下半条密钥")
        XCTAssertTrue(
            h.reporter.stats().lastError?.contains("密钥下发未完成") ?? false,
            "实际：\(h.reporter.stats().lastError ?? "nil")"
        )

        h.recoverWrites()
        h.advanceToNextDeadline()
        h.openConnection()
        h.pump()

        XCTAssertEqual(h.server.battleKeys.count, 1)
        XCTAssertEqual(h.server.business.first?["type"]?.stringValue, "battle_key", "密钥仍要先于任何报文")
        XCTAssertEqual(h.reporter.stats().keyID, key.keyID)
    }

    func testReconnectBackoffDoublesAndCapsWithoutResetting() {
        let h = ReporterHarness()
        h.start()
        XCTAssertEqual(h.connectionTimes, [0])

        // 每次拨号都超时：8s 拨号超时 + 退避 = 下一次拨号时刻
        for _ in 0..<5 {
            h.advanceToNextDeadline() // 拨号超时
            h.advanceToNextDeadline() // 退避到期后重连
        }

        XCTAssertEqual(h.connectionTimes, [0, 9, 19, 31, 44, 57])
        XCTAssertEqual(h.transports.count, 6)
        XCTAssertEqual(h.reporter.stats().reconnects, 5)
        XCTAssertTrue(h.reporter.stats().lastError?.contains("拨号超时") ?? false)
        // 退避序列里的重连延时只增不减：1 → 2 → 4 → 5 → 5
        let backoffs = h.scheduler.scheduledDelays.filter { $0 != h.config.dialTimeout }
        XCTAssertEqual(backoffs, [1, 2, 4, 5, 5])
    }

    func testDialTimeoutFailsThenReconnects() {
        let h = ReporterHarness()
        h.start()
        XCTAssertEqual(h.transports.count, 1)
        XCTAssertEqual(h.transports[0].host, "127.0.0.1")
        XCTAssertEqual(h.transports[0].port, 1082)

        h.advance(8)
        var stats = h.reporter.stats()
        XCTAssertFalse(stats.connected)
        XCTAssertEqual(stats.lastError, "节点拨号超时（8s）")
        XCTAssertEqual(h.transports[0].closeCount, 1)

        h.advanceToNextDeadline()
        stats = h.reporter.stats()
        XCTAssertEqual(h.transports.count, 2)
        XCTAssertEqual(stats.reconnects, 1)
    }

    func testDialTimerIsCancelledOnceOpened() {
        let h = ReporterHarness()
        h.start()
        h.openConnection()
        h.pump()

        h.advance(8)
        let stats = h.reporter.stats()
        XCTAssertTrue(stats.connected)
        XCTAssertNil(stats.lastError)
        XCTAssertEqual(h.transports.count, 1)
    }

    func testPlaintextAuthRejectionIsHardFailure() {
        let h = ReporterHarness()
        h.server.challengeError = "房间已满"
        h.start()
        h.openConnection()
        h.pump()

        let stats = h.reporter.stats()
        XCTAssertTrue(stats.authFailed)
        XCTAssertFalse(stats.connected)
        XCTAssertEqual(stats.lastError, "房间已满")
        XCTAssertEqual(h.authFailures, ["房间已满"])
        XCTAssertTrue(h.logs.contains("[ws] 鉴权失败: 房间已满"))
        XCTAssertEqual(h.transports[0].closeCount, 1)

        // 硬失败：不再重连，也不再收包
        h.advance(600)
        XCTAssertEqual(h.transports.count, 1)
        h.reporter.enqueue(datagram(1))
        h.settle()
        XCTAssertEqual(h.reporter.stats().queued, 0)
    }

    func testEncryptedAuthRejectionIsHardFailure() {
        let h = ReporterHarness()
        h.server.rejectFinish = true
        h.start()
        h.openConnection()
        h.pump()

        let stats = h.reporter.stats()
        XCTAssertTrue(stats.authFailed)
        XCTAssertFalse(stats.connected)
        XCTAssertEqual(stats.lastError, "握手证明不通过")
        XCTAssertFalse(h.server.finishAccepted)
        h.advance(600)
        XCTAssertEqual(h.transports.count, 1)
    }

    func testMalformedAPIKeyFailsWithoutDialing() {
        let h = ReporterHarness(apiKey: "not-a-hex-key")
        h.start()

        let stats = h.reporter.stats()
        XCTAssertTrue(stats.authFailed)
        XCTAssertTrue(h.transports.isEmpty, "房间 Key 本身就是错的，连一次都不该拨")
        XCTAssertEqual(h.authFailures, ["房间 Key 需为 32 位十六进制"])
        XCTAssertTrue(h.logs.contains("[ws] 已停止"))
        h.advance(600)
        XCTAssertTrue(h.transports.isEmpty)
    }

    func testPingKeepsRunningWithoutPongAndReadTimeoutArmsAfterPong() {
        let h = ReporterHarness()
        h.start()
        h.openConnection()
        h.pump()
        XCTAssertTrue(h.reporter.stats().connected)

        // 服务端不回 pong：心跳照发，但不启用读超时
        h.server.respondToPing = false
        h.advance(h.config.pingInterval)
        XCTAssertEqual(h.server.pings, 1)
        h.advance(h.config.pongWait)
        XCTAssertEqual(h.server.pings, 2)
        XCTAssertTrue(h.reporter.stats().connected)
        XCTAssertNil(h.reporter.stats().lastError)

        // 收到一次 pong 之后才启用读超时
        h.server.respondToPing = true
        h.advance(h.config.pingInterval)
        h.pump()
        XCTAssertTrue(h.reporter.stats().connected)

        // 再断掉 pong：读超时到期即断
        h.server.respondToPing = false
        h.advance(h.config.pongWait)
        let stats = h.reporter.stats()
        XCTAssertFalse(stats.connected)
        XCTAssertEqual(stats.lastError, "读超时 10s")
    }

    func testStopClearsQueueAndIgnoresLaterEnqueues() {
        let h = ReporterHarness()
        h.start()
        h.openConnection()
        h.pump()

        h.failWrites()
        h.reporter.enqueue(datagram(1))
        h.settle()
        XCTAssertEqual(h.reporter.stats().queued, 1)

        h.reporter.stop()
        h.settle()
        XCTAssertEqual(h.reporter.stats().queued, 0)
        XCTAssertTrue(h.logs.contains("[ws] 已停止"))

        h.reporter.enqueue(datagram(2))
        h.settle()
        XCTAssertEqual(h.reporter.stats().queued, 0)

        h.advance(600)
        XCTAssertEqual(h.transports.count, 1, "stop 之后不再重连")
    }

    func testEnqueueBeforeStartIsIgnored() {
        let h = ReporterHarness()
        h.reporter.enqueue(datagram(1))
        h.settle()
        XCTAssertEqual(h.reporter.stats().queued, 0)
        XCTAssertTrue(h.transports.isEmpty)
    }

    /// 断开后仍收到 peer 帧也不该动状态：回调里第一件事就是比对连接身份
    func testStaleConnectionCallbacksAreIgnored() {
        let h = ReporterHarness()
        h.start()
        h.openConnection()
        h.pump()
        XCTAssertTrue(h.reporter.stats().connected)

        let stale = h.current
        h.advance(8) // 触发一次心跳，连接保持
        stale.drop("对端关闭连接")
        h.settle()
        XCTAssertFalse(h.reporter.stats().connected)

        // 旧连接再投帧不该被当成当前连接处理
        stale.deliver("{\"type\":\"error\",\"msg\":\"stale\"}")
        h.settle()
        XCTAssertTrue(h.logs.allSatisfy { !$0.contains("stale") })
    }
}
