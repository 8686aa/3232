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
    @Published var interceptPortsText = "158"
    @Published var errorMessage: String?

    private let engine = MiddlemanEngine()
    private var pollTimer: Timer?
    private let maxLogLines = 200

    init() {
        engine.log.onLine = { [weak self] line in
            DispatchQueue.main.async {
                guard let self else { return }
                self.logLines.append(line)
                if self.logLines.count > self.maxLogLines {
                    self.logLines.removeFirst(self.logLines.count - self.maxLogLines)
                }
            }
        }
    }

    var listenSummary: String {
        guard isRunning else { return "未启动" }
        let tcp = engine.tcpPort.map(String.init) ?? "-"
        let udp = engine.udpPort.map(String.init) ?? "-"
        return "TCP \(tcp) / UDP \(udp)"
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
        // 后台没有意义：普通 App 没有常驻权限，灭屏即挂起
        UIApplication.shared.isIdleTimerDisabled = true
        startPolling()
    }

    func stop() {
        engine.stop()
        isRunning = false
        UIApplication.shared.isIdleTimerDisabled = false
        pollTimer?.invalidate()
        pollTimer = nil
        refreshFromEngine()
    }

    /// 配置只能在引擎停下来的时候改
    private func applyConfig() {
        engine.config.listenPort = UInt16(portText.trimmingCharacters(in: .whitespaces)) ?? 1080
        let host = advertisedHost.trimmingCharacters(in: .whitespaces)
        engine.config.advertisedHost = host.isEmpty ? nil : host
        let ports = interceptPortsText
            .split(separator: ",")
            .compactMap { UInt16($0.trimmingCharacters(in: .whitespaces)) }
        engine.config.interceptPorts = Set(ports.isEmpty ? [158] : ports)
    }

    private func startPolling() {
        pollTimer?.invalidate()
        let timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refreshFromEngine() }
        }
        pollTimer = timer
    }

    private func refreshFromEngine() {
        stats = engine.stats()
        if let candidate = engine.candidates.last {
            latestMaterialHex = candidate.material.map { String(format: "%02x", $0) }.joined()
        }
    }

    func copyLatestMaterial() {
        guard let latestMaterialHex else { return }
        UIPasteboard.general.string = latestMaterialHex
    }
}
