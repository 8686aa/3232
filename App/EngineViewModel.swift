import Combine
import SwiftUI
import StarRadarCore
import UIKit

/// 界面与引擎之间的桥。引擎的回调都在自己的队列上，这里统一跳回主线程。
@MainActor
final class EngineViewModel: ObservableObject {

    /// 日志级别（决定霓虹日志里的颜色）
    enum Level {
        case info, ok, warn, err
    }

    struct LogLine: Identifiable {
        let id = UUID()
        let at: Date
        let level: Level
        let msg: String
    }

    // MARK: - 运行状态

    @Published private(set) var isRunning = false
    @Published private(set) var stats = EngineStats()
    @Published private(set) var reportStats = ReporterStats()
    @Published private(set) var lines: [LogLine] = []
    /// 报文流（最新在最前）
    @Published private(set) var rows: [PktInfo] = []
    @Published private(set) var latestMaterialHex: String?

    /// 节点测速结果，-1 = 离线
    @Published private(set) var latMs: Int64 = -1
    @Published private(set) var localIp = "—"

    /// 累计上下行（来自链路快照，含被签名门挡下的报文）
    @Published private(set) var upPackets: Int64 = 0
    @Published private(set) var downPackets: Int64 = 0
    @Published private(set) var upBytes: Int64 = 0
    @Published private(set) var downBytes: Int64 = 0

    // MARK: - 配置

    @Published var portText = "1010" {
        didSet { defaults.set(portText, forKey: DefaultsKey.port) }
    }
    @Published var advertisedHost = ""
    @Published var interceptPortsText = "65010"
    /// 房间 Key：既是预共享密钥也是房间号，32 位十六进制
    @Published var roomKeyText = "" {
        didSet { defaults.set(roomKeyText, forKey: DefaultsKey.roomKey) }
    }
    /// 手动覆盖的对局密钥材料：128 字节十六进制。填了就压过自动抽取的候选
    @Published var keyOverrideText = "" {
        didSet { defaults.set(keyOverrideText, forKey: DefaultsKey.keyOverride) }
    }
    /// 订阅节点列表，只存 IP（上报端口固定 1082）
    @Published private(set) var nodes: [String] = []
    @Published private(set) var selectedHost = ""
    @Published var errorMessage: String?

    /// 星图与波形的数据源，交给 Canvas 自己按帧推进
    let radar = RadarModel()
    let wave = WaveModel()

    private enum DefaultsKey {
        static let port = "listen.port"
        static let nodes = "report.nodes"
        static let selectedHost = "report.selectedHost"
        static let roomKey = "report.roomKey"
        static let keyOverride = "report.keyOverride"
    }

    private let engine = MiddlemanEngine()
    private let defaults = UserDefaults.standard
    private var reporter: WSReporter?
    /// 上一次真正下发给上报端的密钥，用来避免每秒重复下发
    private var pushedKey: UploadKey?
    private var pollTimer: Timer?
    private var probing = false
    private var ticks = 0
    private var lastUpBytes: Int64 = 0
    private var lastDownBytes: Int64 = 0

    private let maxLog = 400
    private let maxRows = 60
    private let rowsPerTick = 12

    init() {
        // 属性观察器在初始化阶段不触发，所以这里直接读盘不会把默认值写回去
        let savedPort = defaults.string(forKey: DefaultsKey.port) ?? ""
        if !savedPort.isEmpty { portText = savedPort }
        roomKeyText = defaults.string(forKey: DefaultsKey.roomKey) ?? ""
        keyOverrideText = defaults.string(forKey: DefaultsKey.keyOverride) ?? ""

        let saved = defaults.string(forKey: DefaultsKey.nodes) ?? ""
        let list = saved.split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        nodes = list
        let savedHost = defaults.string(forKey: DefaultsKey.selectedHost) ?? ""
        selectedHost = nodes.contains(savedHost) ? savedHost : (nodes.first ?? "")

        engine.log.onLine = { [weak self] line in
            DispatchQueue.main.async { self?.append(line) }
        }
        // 链路快照直接记，读界面时再取 —— 回调在引擎队列上，必须无阻塞
        engine.onFlow = { up, srcIp, sport, dstIp, dport, len in
            FlowHub.shared.report(up: up, srcIp: srcIp, sport: sport,
                                  dstIp: dstIp, dport: dport, len: len)
        }
        RadarRouter.shared.log = { [weak self] line in
            DispatchQueue.main.async { self?.append(line) }
        }

        localIp = LocalAddress.primaryIPv4() ?? "—"
        append("本机内网地址 \(localIp)")
        append("热点设备把代理指向本机 \(localIp):\(portText) 后开始上报")
        startPolling()
    }

    // MARK: - 派生状态

    /// 当前用于上报/测速的节点
    var currentNode: String {
        selectedHost.isEmpty ? (nodes.first ?? "") : selectedHost
    }

    var wsState: String {
        guard isRunning else { return "未连接" }
        if reportStats.authFailed { return "鉴权失败" }
        return reportStats.connected ? "已连接" : "连接中"
    }

    var latLabel: String {
        if latMs < 0 { return "离线" }
        if latMs < 1000 { return "\(latMs)ms" }
        return String(format: "%.1fs", Double(latMs) / 1000.0)
    }

    /// 手动覆盖文本的解析结果。nil = 没填或填得对，非 nil 是给界面看的错误说明
    var keyOverrideError: String? {
        let text = keyOverrideText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return nil }
        guard UploadKey.material(fromHex: text) != nil else {
            return "覆盖密钥需为 128 字节十六进制（256 个字符）"
        }
        return nil
    }

    // MARK: - 日志

    private func append(_ line: String, _ level: Level? = nil) {
        let msg = Self.stripTimestamp(line)
        lines.append(LogLine(at: Date(), level: level ?? Self.inferLevel(msg), msg: msg))
        if lines.count > maxLog {
            lines.removeFirst(lines.count - maxLog)
        }
    }

    /// 引擎写出来的是 "[HH:mm:ss.SSS] 正文"，界面自己带时间，剥掉前缀
    private static func stripTimestamp(_ line: String) -> String {
        guard line.hasPrefix("["), let close = line.firstIndex(of: "]") else { return line }
        let inner = line[line.index(after: line.startIndex)..<close]
        guard inner.count == 12, inner.contains(":"), inner.contains(".") else { return line }
        return String(line[line.index(after: close)...]).trimmingCharacters(in: .whitespaces)
    }

    private static func inferLevel(_ msg: String) -> Level {
        if msg.contains("错误") || msg.contains("失败") || msg.contains("异常")
            || msg.contains("不可达") || msg.contains("被拒") || msg.contains("非法") {
            return .err
        }
        if msg.contains("抖动") || msg.contains("超时") || msg.contains("重连")
            || msg.contains("压缩") || msg.contains("丢弃") {
            return .warn
        }
        if msg.contains("启动") || msg.contains("已连接") || msg.contains("鉴权通过")
            || msg.contains("接受") || msg.contains("识别对局") || msg.contains("已装载") {
            return .ok
        }
        return .info
    }

    // MARK: - 节点

    func selectNode(_ ip: String) {
        guard selectedHost != ip else { return }
        selectedHost = ip
        saveNodes()
        append("已选择节点 ws://\(ip):1082", .info)
        probeNode()
    }

    func addNode(_ ip: String) {
        let value = ip.trimmingCharacters(in: .whitespaces)
        guard !value.isEmpty, !nodes.contains(value) else { return }
        nodes.append(value)
        selectedHost = value
        saveNodes()
        probeNode()
    }

    func removeNode(_ ip: String) {
        guard nodes.count > 1 else {
            append("至少保留一个节点", .warn)
            return
        }
        guard let idx = nodes.firstIndex(of: ip) else { return }
        nodes.remove(at: idx)
        if selectedHost == ip {
            selectedHost = nodes[min(idx, nodes.count - 1)]
        }
        saveNodes()
    }

    private func saveNodes() {
        defaults.set(nodes.joined(separator: ","), forKey: DefaultsKey.nodes)
        defaults.set(selectedHost, forKey: DefaultsKey.selectedHost)
    }

    // MARK: - 启停

    func start() {
        guard !isRunning else { return }
        guard !nodes.isEmpty, !currentNode.isEmpty else {
            errorMessage = "请先添加订阅节点"
            return
        }
        let trimmedPort = portText.trimmingCharacters(in: .whitespaces)
        guard let port = UInt16(trimmedPort), port > 0 else {
            errorMessage = "监听端口需为 1–65535 的整数"
            return
        }
        let keyText = roomKeyText.trimmingCharacters(in: .whitespaces)
        let apiKey: String
        do {
            apiKey = try SecureWS.normalizeAPIKey(keyText)
        } catch {
            errorMessage = "房间 Key 需为 32 位十六进制"
            return
        }

        if selectedHost.isEmpty { selectedHost = nodes[0] }
        applyConfig(port: port)

        do {
            try engine.start()
        } catch {
            errorMessage = "启动失败：\(error)"
            return
        }

        isRunning = true
        errorMessage = nil
        FlowHub.shared.clear()
        rows.removeAll()
        wave.reset()
        radar.clear()
        radar.live = true
        lastUpBytes = 0
        lastDownBytes = 0

        append("=== 开始监听 ===", .ok)
        append("本机 \(localIp):\(port)  节点 ws://\(currentNode):1082", .info)

        startReporter(apiKey: apiKey)
        // 后台没有意义：普通 App 没有常驻权限，灭屏即挂起
        UIApplication.shared.isIdleTimerDisabled = true
        probeNode()
        // 向 <节点IP>:666 校验房间Key，取回分享链接后自动跳到内置雷达页
        RadarRouter.shared.openShare(host: currentNode, apiKey: apiKey)
    }

    func stop() {
        stopReporter()
        engine.stop()
        isRunning = false
        radar.live = false
        radar.clear()
        wave.reset()
        FlowHub.shared.clear()
        UIApplication.shared.isIdleTimerDisabled = false
        append("=== 已停止监听 ===", .info)
        refreshFromEngine()
    }

    /// 配置只能在引擎停下来的时候改
    private func applyConfig(port: UInt16) {
        engine.config.listenPort = port
        let host = advertisedHost.trimmingCharacters(in: .whitespaces)
        engine.config.advertisedHost = host.isEmpty ? nil : host
        let ports = interceptPortsText
            .split(separator: ",")
            .compactMap { UInt16($0.trimmingCharacters(in: .whitespaces)) }
        engine.config.interceptPorts = Set(ports.isEmpty ? [65010] : ports)
    }

    // MARK: - 上报端

    private func startReporter(apiKey: String) {
        stopReporter()
        let config = WSReporter.Config(address: NodeAddress(host: currentNode), apiKey: apiKey)
        let reporter = WSReporter(
            config: config,
            log: { [weak self] line in
                DispatchQueue.main.async { self?.append("上报：\(line)") }
            },
            onAuthFailed: { [weak self] reason in
                DispatchQueue.main.async { self?.append("上报鉴权被拒：\(reason)", .err) }
            }
        )
        self.reporter = reporter
        // 引擎采集到的是「确定该上报的完整 IP 数据报」，这里只管投给上报端。
        // 弱引用上报端：停掉之后回调自动变空操作，不会再往一条已停止的链路里塞包。
        engine.onUpload = { [weak reporter] datagram in reporter?.enqueue(datagram) }
        pushedKey = nil
        reporter.start()
        pushKeyIfChanged()
    }

    private func stopReporter() {
        engine.onUpload = nil
        pushedKey = nil
        reporter?.stop()
        reporter = nil
    }

    /// 当前该下发给转发器的对局密钥。
    ///
    /// 手动覆盖优先：自动抽取是照 base64 形状猜出来的，猜错字节段时得靠真实材料顶掉它。
    private func currentKey() -> UploadKey? {
        if let material = UploadKey.material(fromHex: keyOverrideText) {
            // 覆盖密钥每次都用「现在」当观测时间，否则服务端按 observed_ms 判旧会不采用
            return UploadKey(
                session: "manual",
                material: material,
                observedMS: UInt64(Date().timeIntervalSince1970 * 1000),
                verified: false
            )
        }
        return engine.latestKey
    }

    /// 密钥变了才下发。上报端自己也会按 (会话, 材料) 去重，这里是省掉每秒一次空轮询。
    private func pushKeyIfChanged() {
        guard let reporter else { return }
        let key = currentKey()
        // 比 (会话, 材料) 而不是整个结构体：覆盖密钥的 observed_ms 每次都取当前时间
        let same = key?.session == pushedKey?.session && key?.sha256 == pushedKey?.sha256
        guard !same else { return }
        pushedKey = key
        reporter.setKey(key)
    }

    func copyLatestMaterial() {
        guard let latestMaterialHex else { return }
        UIPasteboard.general.string = latestMaterialHex
    }

    // MARK: - 每秒节拍

    private func startPolling() {
        pollTimer?.invalidate()
        let timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            // 先解包成不可变捕获：直接写 self? 会被判成「并发代码里引用可变捕获的 self」
            guard let self else { return }
            Task { @MainActor in self.tick() }
        }
        pollTimer = timer
    }

    private func tick() {
        ticks += 1
        refreshFromEngine()
        if isRunning {
            syncFlow()
            pushWave()
        } else {
            wave.push(up: 0, down: 0)
        }
        // 未监听时每 10s 测一次节点延迟
        if ticks % 10 == 0 && !isRunning { probeNode() }
    }

    private func refreshFromEngine() {
        stats = engine.stats()
        if let candidate = engine.candidates.last {
            latestMaterialHex = candidate.material.map { String(format: "%02x", $0) }.joined()
        }
        if let reporter {
            reportStats = reporter.stats()
            pushKeyIfChanged()
        } else {
            reportStats = ReporterStats()
        }
    }

    /// 把链路快照搬进星图、报文流与统计卡（@Published 只能在主线程写）
    private func syncFlow() {
        radar.setDevices(FlowHub.shared.clientIps())
        radar.setRemotes(FlowHub.shared.remoteIps(), targets: [])

        for p in FlowHub.shared.drain(rowsPerTick) {
            rows.insert(p, at: 0)
            let devIp = p.up ? p.srcIp : p.dstIp
            let remoteIp = p.up ? p.dstIp : p.srcIp
            radar.emit(up: p.up, deviceIp: devIp, remoteIp: remoteIp)
        }
        if rows.count > maxRows { rows.removeLast(rows.count - maxRows) }

        let totals = FlowHub.shared.totals()
        upPackets = totals.upPackets
        downPackets = totals.downPackets
        upBytes = totals.upBytes
        downBytes = totals.downBytes
    }

    /// 波形按每秒字节差换算成 kbps
    private func pushWave() {
        let dUp = max(0, upBytes - lastUpBytes)
        let dDown = max(0, downBytes - lastDownBytes)
        lastUpBytes = upBytes
        lastDownBytes = downBytes
        wave.push(up: CGFloat(dUp) * 8 / 1000, down: CGFloat(dDown) * 8 / 1000)
    }

    // MARK: - 节点测速

    /// 真实 WS 握手 + 首帧写出耗时（3s 超时）
    private func probeNode() {
        guard !probing else { return }
        let host = currentNode
        guard !host.isEmpty, let url = URL(string: "ws://\(host):1082") else { return }
        probing = true

        let start = Date()
        let cfg = URLSessionConfiguration.default
        cfg.timeoutIntervalForRequest = 3
        cfg.waitsForConnectivity = false
        let session = URLSession(configuration: cfg)
        let task = session.webSocketTask(with: url)
        task.resume()

        task.send(.string("{\"type\":\"ping\"}")) { [weak self] error in
            let ms: Int64 = error == nil ? Int64(Date().timeIntervalSince(start) * 1000) : -1
            task.cancel(with: .normalClosure, reason: nil)
            session.invalidateAndCancel()
            DispatchQueue.main.async { self?.finishProbe(ms) }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 3.5) { [weak self] in
            task.cancel(with: .normalClosure, reason: nil)
            session.invalidateAndCancel()
            self?.finishProbe(-1)
        }
    }

    /// 只认第一次结果（主线程调用，天然串行）
    private func finishProbe(_ ms: Int64) {
        guard probing else { return }
        probing = false
        latMs = ms
    }
}
