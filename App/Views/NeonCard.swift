import SwiftUI

/// 玻璃拟态卡片
struct NeonCard<Content: View>: View {
    var accent: UInt32 = P.CYAN
    @ViewBuilder var content: () -> Content

    var body: some View {
        content()
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .fill(LinearGradient(colors: [P.color(0xE60C1323), P.color(0xCC060B16)],
                                         startPoint: .top, endPoint: .bottom))
                    .shadow(color: Color(argb: 0xCC000000), radius: 7, x: 0, y: 6)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .stroke(P.color(P.alpha(accent, 0x3D)), lineWidth: 1)
                    .shadow(color: P.color(P.alpha(accent, 0x4D)), radius: 3.5)
            )
            .overlay(alignment: .top) {
                LinearGradient(colors: [P.color(P.alpha(0xFFFFFF, 0x14)), P.color(P.alpha(0xFFFFFF, 0x00))],
                               startPoint: .top, endPoint: .bottom)
                    .frame(height: 18)
                    .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                    .allowsHitTesting(false)
            }
    }
}
