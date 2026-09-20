import SwiftUI

/// 色板（ARGB，0xAARRGGBB），与参考实现的 Palette 一一对应
enum P {
    static let BG0: UInt32      = 0xFF04060D
    static let BG1: UInt32      = 0xFF070C18
    static let BG2: UInt32      = 0xFF0B1220
    static let TXT: UInt32      = 0xFFE9EFFF
    static let TXT_DIM: UInt32  = 0xFF8C9DC4
    static let TXT_MUTE: UInt32 = 0xFF5B6B91
    static let CYAN: UInt32     = 0xFF22D3EE
    static let TEAL: UInt32     = 0xFF5EEAD4
    static let VIOLET: UInt32   = 0xFF8B5CF6
    static let AMBER: UInt32    = 0xFFFBBF24
    static let GREEN: UInt32    = 0xFF34D399
    static let RED: UInt32      = 0xFFF87171
    /// 下行紫
    static let DOWN: UInt32     = 0xFFC4B5FD
    /// 星图网格线
    static let GRID: UInt32     = 0xFF78A0DC

    /// 替换 alpha 通道
    static func alpha(_ color: UInt32, _ a: Int) -> UInt32 {
        (color & 0x00FFFFFF) | (UInt32(max(0, min(255, a))) << 24)
    }

    /// ARGB 线性插值
    static func mix(_ c1: UInt32, _ c2: UInt32, _ t: Float) -> UInt32 {
        let tt = max(0, min(1, t))
        func ch(_ shift: UInt32) -> UInt32 {
            let a = Float((c1 >> shift) & 0xFF)
            let b = Float((c2 >> shift) & 0xFF)
            return UInt32(max(0, min(255, a + (b - a) * tt)))
        }
        return (ch(24) << 24) | (ch(16) << 16) | (ch(8) << 8) | ch(0)
    }

    static func color(_ argb: UInt32) -> Color { Color(argb: argb) }
}

extension Color {
    /// 0xAARRGGBB
    init(argb: UInt32) {
        let a = Double((argb >> 24) & 0xFF) / 255.0
        let r = Double((argb >> 16) & 0xFF) / 255.0
        let g = Double((argb >> 8) & 0xFF) / 255.0
        let b = Double(argb & 0xFF) / 255.0
        self = Color(.sRGB, red: r, green: g, blue: b, opacity: a)
    }
}

/// 字体：mono / sans / sans-medium / sans-bold
enum Fonts {
    static func mono(_ size: CGFloat) -> Font { .system(size: size, design: .monospaced) }
    static func sans(_ size: CGFloat) -> Font { .system(size: size) }
    static func sansMedium(_ size: CGFloat) -> Font { .system(size: size, weight: .medium) }
    static func sansBold(_ size: CGFloat) -> Font { .system(size: size, weight: .bold) }
}

private let groupFormatter: NumberFormatter = {
    let f = NumberFormatter()
    f.numberStyle = .decimal
    f.groupingSeparator = ","
    f.maximumFractionDigits = 0
    return f
}()

/// 千分位逗号
func fmt(_ n: Int64) -> String {
    groupFormatter.string(from: NSNumber(value: n)) ?? "\(n)"
}

private let hmsFormatter: DateFormatter = {
    let f = DateFormatter()
    f.dateFormat = "HH:mm:ss"
    return f
}()

func fmtTime(_ d: Date) -> String { hmsFormatter.string(from: d) }

/// IPv4 取后两段，IPv6 取末两组
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
