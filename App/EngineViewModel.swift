import Combine
import SwiftUI
import StarRadarCore
import UIKit

/// 界面与引擎之间的桥。引擎的回调都在自己的队列上，这里统一跳回主线程。
@MainActor
final class EngineViewModel: ObservableObject {
    @Published private(set) var isRunning = false
    @Published private(set) var stats = EngineStats()
    @Published private(set) var logLines: [String] = []
    @Published private(set) var latestMaterialHex: String?

    @Published var portText = "1080"
    @Published var advertisedHost = ""
    @Published var interceptPortsText = "65010"
    @Published var errorMessage: String?

    /// 上报节点地址。只填 IP 就按默认端口 1082
    @Published var reportAddressText = "" {
        didSet { defaults.set(reportAddressText, forKey: DefaultsKey.reportAddress) }
    }
    /// 房间 Key：既是预共享密钥也是房间号，32 位十六进制
    @Published var roomKeyText = "" {
        didSet { defaults.set(roomKeyText, forKey: DefaultsKey.roomKey) }
    }
    /// 手动覆盖的对局密钥材料：128 字节十六进制。填了就压过自动抽取的候选
    @Published var keyOverrideText = "" {
        didSet { defaults.set(keyOverrideText, forKey: DefaultsKey.keyOverride) }
    }
    @Published private(set) var reportStats = ReporterStats()
    /// 配置层面的问题（地址解析不了、Key 不是 32 位 hex），与上报端自己的 lastError 分开
    @Published private(set) var reportConfigError: String?

    private enum DefaultsKey {
        static let reportAddress = "report.address"
        static let roomKey = "report.roomKey"
        static let keyOverride = "report.keyOverride"
    }

    private let engine = MiddlemanEngine()
    private let defaults = UserDefaults.standard
    private var reporter: WSReporter?
    /// 上一次真正下发给上报端的密钥，用来避免每秒重复下发
    private var pushedKey: UploadKey?
    private var pollTimer: Timer?
    private let maxLogLines = 200

    init() {
        reportAddressText = defaults.string(forKey: DefaultsKey.reportAddress) ?? ""
        roomKeyText = defaults.string(forKey: DefaultsKey.roomKey) ?? ""
        keyOverrideText = defaults.string(forKey: DefaultsKey.keyOverride) ?? ""
        engine.log.onLine = { [weak self] line in
            DispatchQueue.main.async {
                guard let self else { return }
                self.appendLog(line)
            }
        }
    }

    private func appendLog(_ line: String) {
        logLines.append(line)
        if logLines.count > maxLogLines {
            logLines.removeFirst(logLines.count - maxLogLines)
        }
    }

    var listenSummary: String {
        guard isRunning else { return "未启动" }
        let tcp = engine.tcpPort.map(String.init) ?? "-"
        let udp = engine.udpPort.map(String.init) ?? "-"
        return "TCP \(tcp) / UDP \(udp)"
    }

    /// 界面用：有没有真的把上报端建起来
    var reportConfigured: Bool { reporter != nil }

    /// 上报连接状态。地址与房间 Key 都填了才会真的去连
    var reportConnectionSummary: String {
        guard isRunning else { return "未启动" }
        guard reporter != nil else {
            return reportConfigError == nil ? "未配置" : "配置有误"
        }
        if reportStats.authFailed { return "鉴权被拒" }
        return reportStats.connected ? "已连接" : "连接中"
    }

    /// 上报端给出的失败原因，没有就退回配置错误
    var reportFailure: String? {
        reportStats.lastError ?? reportConfigError
    }

    // MARK: - 启停

    func start() {
        guard !isRunning else { return }
        applyConfig()

        do {
            try engine.start()
        } catch {
            errorMessage = "启动失败：\(error)"
            return
        }

        isRunning = true
        errorMessage = nil
        startReporter()
        // 后台没有意义：普通 App 没有常驻权限，灭屏即挂起
        UIApplication.shared.isIdleTimerDisabled = true
        startPolling()
    }

    func stop() {
        stopReporter()
        engine.stop()
        isRunning = false
        UIApplication.shared.isIdleTimerDisabled = false
        pollTimer?.invalidate()
        pollTimer = nil
        refreshFromEngine()
    }

    // MARK: - 上报端

    /// 用界面上的地址与房间 Key 建一个上报端。两项都空就不上报。
    private func makeReporter() -> WSReporter? {
        let addressText = reportAddressText.trimmingCharacters(in: .whitespaces)
        let keyText = roomKeyText.trimmingCharacters(in: .whitespaces)
        // 两项要一起填：没有地址没地方连，没有房间 Key 连握手都过不去
        if addressText.isEmpty && keyText.isEmpty {
            reportConfigError = nil
            return nil
        }
        guard !addressText.isEmpty else {
            reportConfigError = "请填上报的订阅地址"
            return nil
        }
        guard let address = NodeAddress(text: addressText) else {
            reportConfigError = "订阅地址无法解析：\(addressText)"
            return nil
        }
        guard !keyText.isEmpty else {
            reportConfigError = "请填房间 Key（32 位十六进制）"
            return nil
        }
        let apiKey: String
        do {
            apiKey = try SecureWS.normalizeAPIKey(keyText)
        } catch {
            reportConfigError = "房间 Key 需为 32 位十六进制"
            return nil
        }
        reportConfigError = nil

        let config = WSReporter.Config(address: address, apiKey: apiKey)
        return WSReporter(
            config: config,
            log: { [weak self] line in
                DispatchQueue.main.async {
                    guard let self else { return }
                    self.appendLog("上报：\(line)")
                }
            },
            onAuthFailed: { [weak self] reason in
                DispatchQueue.main.async {
                    guard let self else { return }
                    self.reportConfigError = "上报鉴权被拒：\(reason)"
                }
            }
        )
    }

    private func startReporter() {
        stopReporter()
        guard let reporter = makeReporter() else {
            reportStats = ReporterStats()
            return
        }
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

    /// 手动覆盖文本的解析结果。nil = 没填或填得对，非 nil 是给界面看的错误说明
    var keyOverrideError: String? {
        let text = keyOverrideText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return nil }
        guard UploadKey.material(fromHex: text) != nil else {
            return "覆盖密钥需为 128 字节十六进制（256 个字符）"
        }
        return nil
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

    /// 配置只能在引擎停下来的时候改
    private func applyConfig() {
        engine.config.listenPort = UInt16(portText.trimmingCharacters(in: .whitespaces)) ?? 1080
        let host = advertisedHost.trimmingCharacters(in: .whitespaces)
        engine.config.advertisedHost = host.isEmpty ? nil : host
        let ports = interceptPortsText
            .split(separator: ",")
            .compactMap { UInt16($0.trimmingCharacters(in: .whitespaces)) }
        engine.config.interceptPorts = Set(ports.isEmpty ? [65010] : ports)
    }

    private func startPolling() {
        pollTimer?.invalidate()
        let timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            // 先解包成不可变捕获：直接写 self? 会被判成「并发代码里引用可变捕获的 self」
            guard let self else { return }
            Task { @MainActor in self.refreshFromEngine() }
        }
        pollTimer = timer
    }

    private func refreshFromEngine() {
        stats = engine.stats()
        if let candidate = engine.candidates.last {
            latestMaterialHex = candidate.material.map { String(format: "%02x", $0) }.joined()
        }
        if let reporter {
            reportStats = reporter.stats()
            pushKeyIfChanged()
        }
    }

    func copyLatestMaterial() {
        guard let latestMaterialHex else { return }
        UIPasteboard.general.string = latestMaterialHex
    }
}
