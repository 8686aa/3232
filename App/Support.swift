import Foundation
import SwiftUI

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
