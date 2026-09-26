import SwiftUI

/// 链路页：拓扑图 + 流量波形 + 当前链路摘要。
struct LinkPage: View {
    @ObservedObject var model: EngineViewModel

    var body: some View {
        NavigationStack {
            List {
                Section {
                    RadarView(model: model.radar)
                        .frame(height: 320)
                        .listRowInsets(EdgeInsets())
                } header: {
                    Text("链路拓扑")
                } footer: {
                    Text("内圈是接入本机代理的客户端，外圈是它们访问的远端，光点表示数据流向。")
                }

                Section("流量波形") {
                    WaveView(model: model.wave)
                        .frame(height: 150)
                        .listRowInsets(EdgeInsets(top: 8, leading: 8, bottom: 8, trailing: 8))
                }

                Section("当前链路") {
                    LabeledContent("本机服务", value: "\(model.localIp):\(model.portText)")
                    LabeledContent("上报节点", value: nodeText)
                    LabeledContent("识别对局流", value: fmt(Int64(model.stats.gameFlows)))
                    LabeledContent("被挡报文", value: fmt(Int64(model.stats.udpFlowsFiltered)))
                    LabeledContent("已上报报文", value: fmt(Int64(model.stats.udpUploaded)))
                }
            }
            .navigationTitle("链路")
        }
    }

    private var nodeText: String {
        model.currentNode.isEmpty ? "未配置" : "\(model.currentNode):1082"
    }
}
