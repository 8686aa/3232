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
        HStack(spacing: 10) {
            Image(systemName: info.up ? "arrow.up" : "arrow.down")
                .font(.caption2.weight(.bold))
                .foregroundStyle(info.up ? Palette.up : Palette.down)
                .frame(width: 16)

            VStack(alignment: .leading, spacing: 2) {
                Text(route)
                    .font(.footnote.monospaced())
                    .lineLimit(1)
                Text("\(fmtTime(info.time)) · \(info.proto)")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }

            Spacer(minLength: 4)

            if info.target {
                Text("目标")
                    .font(.caption2)
                    .foregroundStyle(Palette.down)
            }

            Text("\(info.len) B")
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
        }
    }

    private var route: String {
        "\(shortIp(info.srcIp)) → \(shortIp(info.dstIp)):\(info.dstPort)"
    }
}
