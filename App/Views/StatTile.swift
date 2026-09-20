import SwiftUI

/// 统计卡，含数值变化 bump 动画
struct StatTile: View {
    let title: String
    var accent: UInt32 = P.CYAN
    var valueColor: UInt32 = P.TXT
    let value: Int64

    @State private var scale: CGFloat = 1

    var body: some View {
        NeonCard(accent: accent) {
            VStack(alignment: .leading, spacing: 0) {
                Text(title)
                    .font(Fonts.sans(11))
                    .tracking(0.9)
                    .foregroundColor(P.color(P.TXT_MUTE))
                Text(fmt(value))
                    .font(Fonts.mono(21))
                    .foregroundColor(P.color(valueColor))
                    .padding(.top, 7)
                    .lineLimit(1)
                    .minimumScaleFactor(0.6)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .scaleEffect(scale, anchor: .leading)
        }
        // 单参数写法是为了兼容 iOS 16（双参数的 onChange 要 17）
        .onChange(of: value) { _ in
            withAnimation(.easeOut(duration: 0.09)) { scale = 1.09 }
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.09) {
                withAnimation(.easeOut(duration: 0.17)) { scale = 1 }
            }
        }
    }
}
