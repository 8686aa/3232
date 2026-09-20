import SwiftUI
import UIKit

/// 首页：霓虹暗黑皮肤，一屏看完「节点 / 配置 / 统计 / 星图 / 波形 / 报文流 / 日志」。
struct ContentView: View {
    @ObservedObject var model: EngineViewModel

    @State private var showAddNode = false
    @State private var draftNode = ""
    @State private var errMsg = ""
    @State private var showErr = false

    var body: some View {
        VStack(spacing: 0) {
            header

            ScrollView(showsIndicators: false) {
                VStack(alignment: .leading, spacing: 0) {
                    nodeSection
                    keySection
                    portSection
                    statsSection
                    radarSection
                    waveSection
                    packetSection
                    logSection
                }
                .padding(.horizontal, 14)
                .padding(.top, 14)
                .padding(.bottom, 8)
            }

            bottomBar
        }
        .background(P.color(P.BG0).ignoresSafeArea())
        .alert("添加订阅节点", isPresented: $showAddNode) {
            TextField("节点 IP", text: $draftNode)
                .keyboardType(.numbersAndPunctuation)
            Button("取消", role: .cancel) { draftNode = "" }
            Button("添加") { addNode() }
        } message: {
            Text("只需输入节点 IP，端口固定 1082")
        }
        .alert("提示", isPresented: $showErr) {
            Button("好", role: .cancel) {}
        } message: {
            Text(errMsg)
        }
        // 单参数写法是为了兼容 iOS 16（双参数的 onChange 要 17）
        .onChange(of: model.wsState) { newValue in
            // 鉴权失败：节点明确拒绝，上报已终止，不再重连
            if newValue == "鉴权失败" && model.isRunning {
                errMsg = "鉴权失败：房间 Key 无效，已停止上报"
                showErr = true
            }
        }
        .onChange(of: model.errorMessage) { newValue in
            guard let newValue else { return }
            errMsg = newValue
            showErr = true
            model.errorMessage = nil
        }
    }

    // MARK: - 标题栏

    private var header: some View {
        HStack(alignment: .center, spacing: 0) {
            VStack(alignment: .leading, spacing: 3) {
                Text("星辰雷达")
                    .font(Fonts.sansBold(17))
                    .tracking(1.0)
                    .foregroundColor(P.color(P.TXT))
                Text("Star Radar · iOS v1.0.0-alpha")
                    .font(Fonts.sans(10))
                    .foregroundColor(P.color(P.TXT_MUTE))
            }
            Spacer(minLength: 8)
            connChip
        }
        .padding(.leading, 16)
        .padding(.trailing, 14)
        .padding(.top, 12)
        .padding(.bottom, 12)
        .background(
            ZStack(alignment: .bottom) {
                LinearGradient(colors: [P.color(0xE60C1323), P.color(0xA0070C18)],
                               startPoint: .top, endPoint: .bottom)
                Rectangle().fill(P.color(0x291860DC)).frame(height: 1)
            }
        )
    }

    private var connChip: some View {
        Text(model.isRunning ? model.wsState : "未连接")
            .font(Fonts.sans(11))
            .foregroundColor(P.color(model.isRunning ? P.BG0 : P.alpha(P.TXT_DIM, 0xCC)))
            .lineLimit(1)
            .padding(.horizontal, 12)
            .padding(.vertical, 5)
            .background(
                Capsule().fill(model.isRunning
                    ? AnyShapeStyle(LinearGradient(colors: [P.color(P.CYAN), P.color(P.TEAL)],
                                                   startPoint: .leading, endPoint: .trailing))
                    : AnyShapeStyle(P.color(0x1F5B6B91)))
            )
            .overlay(
                Capsule().stroke(P.color(model.isRunning ? 0x00000000 : 0x3D8C9DC4), lineWidth: 1)
            )
    }

    // MARK: - 订阅节点

    private var nodeSection: some View {
        VStack(alignment: .leading, spacing: 0) {
            sectionHeader("订阅节点", bar: P.CYAN, trailing: model.latLabel, trailingColor: latColor)
                .padding(.bottom, 8)

            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    ForEach(model.nodes, id: \.self) { ip in
                        nodeChip(ip: ip, selected: ip == model.selectedHost)
                            .onTapGesture { model.selectNode(ip) }
                            .onLongPressGesture { model.removeNode(ip) }
                    }
                    addChip
                }
                .padding(.horizontal, 1)
                .padding(.vertical, 2)
            }
        }
    }

    private func nodeChip(ip: String, selected: Bool) -> some View {
        Text(ip)
            .font(Fonts.mono(12))
            .foregroundColor(P.color(selected ? P.CYAN : P.alpha(P.TXT_DIM, 0xE6)))
            .lineLimit(1)
            .padding(.horizontal, 12)
            .padding(.vertical, 7)
            .background(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(P.color(selected ? P.alpha(P.CYAN, 0x1A) : 0x66070C18))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .stroke(P.color(selected ? P.alpha(P.CYAN, 0x73) : P.alpha(0xFF1860DC, 0x33)), lineWidth: 1)
            )
    }

    private var addChip: some View {
        Button {
            draftNode = ""
            showAddNode = true
        } label: {
            Text("+ 添加")
                .font(Fonts.sans(12))
                .foregroundColor(P.color(P.alpha(P.TXT_DIM, 0xE6)))
                .padding(.horizontal, 12)
                .padding(.vertical, 7)
                .background(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .fill(P.color(0x33070C18))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .stroke(P.color(P.alpha(P.CYAN, 0x33)),
                                style: StrokeStyle(lineWidth: 1, dash: [4, 4]))
                )
        }
    }

    // MARK: - 房间 KEY

    private var keySection: some View {
        VStack(alignment: .leading, spacing: 0) {
            sectionHeader("房间 KEY", bar: P.VIOLET, trailing: keyHint, trailingColor: P.TXT_MUTE)
                .padding(.top, 16)
                .padding(.bottom, 8)
            neonField($model.roomKeyText, placeholder: "32 位房间 Key", keyboard: .asciiCapable)
        }
    }

    // MARK: - 监听端口

    private var portSection: some View {
        VStack(alignment: .leading, spacing: 0) {
            sectionHeader("监听端口", bar: P.TEAL, trailing: "1–65535", trailingColor: P.TXT_MUTE)
                .padding(.top, 16)
                .padding(.bottom, 8)
            neonField($model.portText, placeholder: "1010", keyboard: .numberPad)
                .frame(width: 118)
                .disabled(model.isRunning)
        }
    }

    // MARK: - 统计

    private var statsSection: some View {
        VStack(spacing: 10) {
            HStack(spacing: 10) {
                StatTile(title: "上行报文", accent: P.TEAL, valueColor: P.TXT, value: model.upPackets)
                StatTile(title: "下行报文", accent: P.VIOLET, valueColor: P.DOWN, value: model.downPackets)
            }
            HStack(spacing: 10) {
                StatTile(title: "上行流量 KB", accent: P.CYAN, valueColor: P.TXT, value: model.upBytes / 1024)
                StatTile(title: "下行流量 KB", accent: P.VIOLET, valueColor: P.DOWN, value: model.downBytes / 1024)
            }
            HStack(spacing: 10) {
                StatTile(title: "已上报", accent: P.TEAL, valueColor: P.TXT, value: Int64(model.reportStats.sent))
                StatTile(title: "待发队列", accent: P.AMBER, valueColor: P.AMBER,
                         value: Int64(model.reportStats.queued))
            }
            HStack(spacing: 10) {
                StatTile(title: "补发", accent: P.TEAL, valueColor: P.TXT, value: Int64(model.reportStats.resent))
                StatTile(title: "待补发", accent: P.AMBER, valueColor: P.AMBER,
                         value: Int64(model.reportStats.replay))
            }
        }
        .padding(.top, 16)
    }

    // MARK: - 星图

    private var radarSection: some View {
        NeonCard {
            VStack(alignment: .leading, spacing: 0) {
                cardTitle("链路拓扑", trailing: radarHint)
                RadarView(model: model.radar)
                    .frame(height: 268)
                    .padding(.top, 6)
            }
        }
        .padding(.top, 14)
    }

    // MARK: - 波形

    private var waveSection: some View {
        NeonCard(accent: P.VIOLET) {
            VStack(alignment: .leading, spacing: 0) {
                cardTitle("流量波形", trailing: nil)
                WaveView(model: model.wave)
                    .frame(height: 128)
                    .padding(.top, 6)
            }
        }
        .padding(.top, 12)
    }

    // MARK: - 报文流

    private var packetSection: some View {
        NeonCard {
            VStack(alignment: .leading, spacing: 0) {
                cardTitle("报文流", trailing: "近 \(model.rows.count) 条")
                ScrollView(showsIndicators: false) {
                    LazyVStack(spacing: 0) {
                        ForEach(model.rows) { row in
                            PacketRowView(info: row)
                        }
                    }
                }
                .frame(height: 212)
                .padding(.top, 6)
                .overlay {
                    if model.rows.isEmpty {
                        Text("等待数据包…")
                            .font(Fonts.mono(11))
                            .foregroundColor(P.color(P.TXT_MUTE))
                    }
                }
            }
        }
        .padding(.top, 12)
    }

    // MARK: - 日志

    private var logSection: some View {
        NeonCard(accent: P.TEAL) {
            VStack(alignment: .leading, spacing: 0) {
                cardTitle("运行日志", trailing: "\(model.lines.count) 条")
                ScrollView(showsIndicators: false) {
                    VStack(alignment: .leading, spacing: 3) {
                        ForEach(tailLines) { line in
                            HStack(alignment: .top, spacing: 6) {
                                Text(fmtTime(line.at))
                                    .font(Fonts.mono(10))
                                    .foregroundColor(P.color(P.TXT_MUTE))
                                Text(line.msg)
                                    .font(Fonts.mono(10))
                                    .foregroundColor(P.color(levelColor(line.level)))
                                    .fixedSize(horizontal: false, vertical: true)
                                Spacer(minLength: 0)
                            }
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 1)
                }
                .frame(height: 168)
                .padding(.top, 6)
            }
        }
        .padding(.top, 12)
    }

    /// 只渲染尾部 120 条，避免日志长了以后拖慢滚动
    private var tailLines: [EngineViewModel.LogLine] {
        model.lines.count > 120 ? Array(model.lines.suffix(120)) : model.lines
    }

    // MARK: - 底栏

    private var bottomBar: some View {
        VStack(spacing: 0) {
            Text(footText)
                .font(Fonts.mono(10))
                .foregroundColor(P.color(P.TXT_MUTE))
                .lineLimit(1)
                .minimumScaleFactor(0.7)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.bottom, 10)

            HStack(spacing: 10) {
                startButton
                stopButton
            }
        }
        .padding(.horizontal, 14)
        .padding(.top, 10)
        .padding(.bottom, 12)
        .background(
            ZStack(alignment: .top) {
                LinearGradient(colors: [P.color(0xF2070C18), P.color(0xFA04060D)],
                               startPoint: .top, endPoint: .bottom)
                Rectangle().fill(P.color(0x331860DC)).frame(height: 1)
            }
        )
    }

    private var startButton: some View {
        Button {
            model.start()
        } label: {
            Text("开始监听")
                .font(Fonts.sansBold(14))
                .foregroundColor(P.color(model.isRunning ? P.alpha(P.TXT_MUTE, 0x99) : P.BG0))
                .frame(maxWidth: .infinity)
                .frame(height: 44)
                .background(
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .fill(model.isRunning
                            ? AnyShapeStyle(P.color(0x140F2A33))
                            : AnyShapeStyle(LinearGradient(colors: [P.color(P.CYAN), P.color(P.TEAL)],
                                                           startPoint: .leading, endPoint: .trailing)))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .stroke(P.color(model.isRunning ? P.alpha(P.CYAN, 0x22) : 0x00000000), lineWidth: 1)
                )
        }
        .disabled(model.isRunning)
    }

    private var stopButton: some View {
        Button {
            model.stop()
        } label: {
            Text("停止监听")
                .font(Fonts.sansBold(14))
                .foregroundColor(P.color(model.isRunning ? P.RED : P.alpha(P.RED, 0x66)))
                .frame(maxWidth: .infinity)
                .frame(height: 44)
                .background(
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .fill(P.color(model.isRunning ? 0x1AF87171 : 0x0FF87171))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .stroke(P.color(model.isRunning ? 0x66F87171 : 0x33F87171), lineWidth: 1)
                )
        }
        .disabled(!model.isRunning)
    }

    // MARK: - 公共片段

    private func sectionHeader(_ title: String, bar: UInt32,
                               trailing: String? = nil,
                               trailingColor: UInt32 = P.TXT_MUTE) -> some View {
        HStack(spacing: 7) {
            RoundedRectangle(cornerRadius: 1.5, style: .continuous)
                .fill(P.color(bar))
                .frame(width: 3, height: 12)
            Text(title)
                .font(Fonts.sansMedium(12))
                .foregroundColor(P.color(P.alpha(P.TXT, 0xD9)))
            Spacer(minLength: 6)
            if let t = trailing {
                Text(t)
                    .font(Fonts.mono(11))
                    .foregroundColor(P.color(trailingColor))
            }
        }
    }

    private func cardTitle(_ title: String, trailing: String?) -> some View {
        HStack(spacing: 7) {
            RoundedRectangle(cornerRadius: 1.5, style: .continuous)
                .fill(P.color(P.CYAN))
                .frame(width: 3, height: 12)
            Text(title)
                .font(Fonts.sansMedium(12))
                .foregroundColor(P.color(P.alpha(P.TXT, 0xD9)))
            Spacer(minLength: 6)
            if let t = trailing {
                Text(t)
                    .font(Fonts.mono(10))
                    .foregroundColor(P.color(P.TXT_MUTE))
            }
        }
    }

    private func neonField(_ text: Binding<String>, placeholder: String,
                           keyboard: UIKeyboardType = .default) -> some View {
        TextField(placeholder, text: text)
            .font(Fonts.mono(14))
            .foregroundColor(P.color(P.TXT))
            .tint(P.color(P.CYAN))
            .keyboardType(keyboard)
            .autocorrectionDisabled()
            .textInputAutocapitalization(.never)
            .padding(.horizontal, 12)
            .padding(.vertical, 9)
            .background(
                RoundedRectangle(cornerRadius: 10, style: .continuous).fill(P.color(0xB80C1323))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 10, style: .continuous).stroke(P.color(0x331860DC), lineWidth: 1)
            )
    }

    // MARK: - 计算属性

    private var latColor: UInt32 {
        if !model.isRunning || model.latMs < 0 { return P.RED }
        if model.latMs < 200 { return P.TEAL }
        if model.latMs < 600 { return P.AMBER }
        return P.RED
    }

    private var keyHint: String {
        let n = model.roomKeyText.trimmingCharacters(in: .whitespaces).count
        return n == 0 ? "未填写，节点将拒绝鉴权" : "已填 \(n)/32"
    }

    private var radarHint: String {
        model.isRunning ? "监听中 · 热点客户端全覆盖 · 会话流过滤后上报" : "待机中 · 未开始监听"
    }

    private var footText: String {
        "本机 \(model.localIp):\(model.portText)  ·  节点 \(model.currentNode):1082  ·  重连 \(model.reportStats.reconnects)"
            + "  ·  过滤 \(model.stats.udpFlowsFiltered)  ·  丢弃 \(model.reportStats.dropped)"
    }

    private func levelColor(_ level: EngineViewModel.Level) -> UInt32 {
        switch level {
        case .info: return P.TXT_DIM
        case .ok:   return P.TEAL
        case .warn: return P.AMBER
        case .err:  return P.RED
        }
    }

    // MARK: - 动作

    private func addNode() {
        let ip = draftNode.trimmingCharacters(in: .whitespaces)
        draftNode = ""
        model.addNode(ip)
    }
}
