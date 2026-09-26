import SwiftUI

/// 概览页：运行状态、流量与上报统计，以及开始/停止按钮。
struct OverviewPage: View {
    @ObservedObject var model: EngineViewModel

    @State private var errMsg = ""
    @State private var showErr = false

    var body: some View {
        NavigationStack {
            List {
                statusSection
                trafficSection
                reportSection
                controlSection
            }
            .readableFrame()
            .navigationTitle("GORaDar")
            .alert("提示", isPresented: $showErr) {
                Button("好", role: .cancel) {}
            } message: {
                Text(errMsg)
            }
            // 单参数写法是为了兼容 iOS 16（双参数的 onChange 要 17）
            .onChange(of: model.errorMessage) { value in
                guard let value else { return }
                errMsg = value
                showErr = true
                model.errorMessage = nil
            }
        }
    }

    // MARK: - 运行状态

    private var statusSection: some View {
        Section("运行状态") {
            HStack {
                Text("状态")
                Spacer()
                HStack(spacing: 6) {
                    Circle()
                        .fill(model.isRunning ? Color.green : Color.secondary)
                        .frame(width: 8, height: 8)
                    Text(model.isRunning ? model.wsState : "未运行")
                        .foregroundStyle(model.isRunning ? Color.primary : Color.secondary)
                }
            }
            LabeledContent("当前节点", value: nodeText)
            LabeledContent("节点延迟", value: model.latLabel)
            LabeledContent("本机地址", value: "\(model.localIp):\(model.portText)")
            LabeledContent("房间 KEY", value: keyText)
        }
    }

    private var nodeText: String {
        model.currentNode.isEmpty ? "未配置" : "\(model.currentNode):1082"
    }

    private var keyText: String {
        model.roomKeyText.trimmingCharacters(in: .whitespaces).isEmpty ? "未填写" : "已填写"
    }

    // MARK: - 流量统计

    private var trafficSection: some View {
        Section("流量统计") {
            LabeledContent("上行报文", value: fmt(model.upPackets))
            LabeledContent("下行报文", value: fmt(model.downPackets))
            LabeledContent("上行流量", value: "\(fmt(model.upBytes / 1024)) KB")
            LabeledContent("下行流量", value: "\(fmt(model.downBytes / 1024)) KB")
        }
    }

    // MARK: - 上报队列

    private var reportSection: some View {
        Section("上报队列") {
            LabeledContent("已上报", value: fmt(Int64(model.reportStats.sent)))
            LabeledContent("待发队列", value: fmt(Int64(model.reportStats.queued)))
            LabeledContent("补发", value: fmt(Int64(model.reportStats.resent)))
            LabeledContent("待补发", value: fmt(Int64(model.reportStats.replay)))
            LabeledContent("重连", value: fmt(Int64(model.reportStats.reconnects)))
            LabeledContent("丢弃", value: fmt(Int64(model.reportStats.dropped)))
        }
    }

    // MARK: - 控制

    private var controlSection: some View {
        Section {
            Button {
                model.start()
            } label: {
                Text("开始监听").frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(model.isRunning)
            .listRowInsets(EdgeInsets(top: 6, leading: 16, bottom: 6, trailing: 16))
            .listRowBackground(Color.clear)

            Button {
                model.stop()
            } label: {
                Text("停止监听").frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
            .controlSize(.large)
            .tint(.red)
            .disabled(!model.isRunning)
            .listRowInsets(EdgeInsets(top: 6, leading: 16, bottom: 6, trailing: 16))
            .listRowBackground(Color.clear)
        } header: {
            Text("控制")
        } footer: {
            Text("开始监听会先用房间 KEY 向节点校验，校验通过后自动切到「雷达」页。")
        }
    }
}
