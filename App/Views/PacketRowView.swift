import SwiftUI

/// 单条报文
struct PktInfo: Identifiable {
    let id = UUID()
    let time: Date
    let up: Bool
    let srcIp: String
    let srcPort: Int
    let dstIp: String
    let dstPort: Int
    let proto: String
    let len: Int
    let target: Bool
}

struct PacketRowView: View {
    let info: PktInfo

    var body: some View {
        HStack(spacing: 0) {
            RoundedRectangle(cornerRadius: 1.5, style: .continuous)
                .fill(P.color(P.alpha(info.up ? P.TEAL : P.DOWN, 0xCC)))
                .frame(width: 2.5, height: 22)

            Text(fmtTime(info.time))
                .font(Fonts.mono(9.5))
                .foregroundColor(P.color(P.alpha(P.TXT_MUTE, 0xE6)))
                .padding(.leading, 9)

            Text(info.up ? "▲" : "▼")
                .font(Fonts.sans(9))
                .foregroundColor(P.color(info.up ? P.TEAL : P.DOWN))
                .padding(.leading, 7)

            Text(shortIp(info.srcIp))
                .font(Fonts.mono(11))
                .foregroundColor(P.color(P.alpha(P.TXT, 0xEB)))
                .padding(.leading, 5)

            Text("→")
                .font(Fonts.mono(11))
                .foregroundColor(P.color(P.alpha(P.TXT_DIM, 0x99)))
                .padding(.leading, 5)

            Text("\(shortIp(info.dstIp)):\(info.dstPort)")
                .font(Fonts.mono(11))
                .foregroundColor(P.color(P.alpha(dstColor, 0xEB)))
                .padding(.leading, 5)

            Text(info.proto)
                .font(Fonts.mono(9.5))
                .foregroundColor(P.color(P.alpha(P.TXT_DIM, 0xCC)))
                .padding(.leading, 5)

            Spacer(minLength: 4)

            Text("\(info.len)B")
                .font(Fonts.mono(9.5))
                .foregroundColor(P.color(P.alpha(P.TXT_MUTE, 0xE6)))
        }
        .lineLimit(1)
        .padding(.horizontal, 9)
        .frame(height: 30)
        .background(info.target ? P.color(P.alpha(P.AMBER, 0x0F)) : Color.clear)
    }

    private var dstColor: UInt32 {
        if info.target { return P.AMBER }
        return info.up ? P.DOWN : P.TEAL
    }
}
