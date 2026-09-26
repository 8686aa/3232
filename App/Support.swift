import Foundation
import SwiftUI
import UIKit

// MARK: - 全局配色

/// 全 App 只用系统语义色，浅色/深色自动适配。
/// 这里只额外固定「上行 / 下行」两个业务色，保证波形、拓扑、报文流三处口径一致。
enum Palette {
    /// 上行（客户端 → 远端）
    static let up = Color.blue
    /// 下行（远端 → 客户端）
    static let down = Color.orange
}

/// 日志级别 → 颜色
func levelColor(_ level: EngineViewModel.Level) -> Color {
    switch level {
    case .info: return .secondary
    case .ok:   return .green
    case .warn: return .orange
    case .err:  return .red
    }
}

// MARK: - 格式化

private let groupedFormatter: NumberFormatter = {
    let formatter = NumberFormatter()
    formatter.numberStyle = .decimal
    formatter.maximumFractionDigits = 0
    return formatter
}()

/// 千分位数字，例：12345 → "12,345"
func fmt(_ n: Int64) -> String {
    groupedFormatter.string(from: NSNumber(value: n)) ?? "\(n)"
}

private let clockFormatter: DateFormatter = {
    let formatter = DateFormatter()
    formatter.dateFormat = "HH:mm:ss"
    return formatter
}()

/// 时间戳 → "HH:mm:ss"
func fmtTime(_ d: Date) -> String {
    clockFormatter.string(from: d)
}

/// IPv4 取后两段、IPv6 取末两组，避免长地址把列表撑破
func shortIp(_ ip: String) -> String {
    if ip.contains(":") {
        let parts = ip.split(separator: ":")
        guard parts.count >= 2 else { return ip }
        return "…" + parts[parts.count - 2] + ":" + parts[parts.count - 1]
    }
    let parts = ip.split(separator: ".")
    guard parts.count >= 2 else { return ip }
    return "\(parts[parts.count - 2]).\(parts[parts.count - 1])"
}

// MARK: - 宽屏适配（iPad / 横屏）

extension View {
    /// 把正文限宽居中。
    ///
    /// iPad 上 List / Form 默认铺满整屏：1024–1366pt 宽时，一行说明文字会拉到上千点，
    /// 「标签 —— 值」的两端也被扯得老远，读起来很散。这里限到 700pt 居中
    /// （接近系统的 readable content 宽度）。
    ///
    /// iPhone 竖屏可用宽度本来就小于 700，等于什么都没做。列表容器自己的底色先关掉、
    /// 再由本修饰符按整屏画一张同色的底：否则限宽后两侧会露出窗口底色，看着像被切过。
    func readableFrame(limit: CGFloat = 700) -> some View {
        scrollContentBackground(.hidden)
            .frame(maxWidth: limit)
            .frame(maxWidth: .infinity)
            .background(Color(uiColor: .systemGroupedBackground))
    }
}
