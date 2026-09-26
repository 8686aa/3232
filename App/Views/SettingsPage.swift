import SwiftUI

/// 设置页：订阅节点、房间 KEY、监听端口。
struct SettingsPage: View {
    @ObservedObject var model: EngineViewModel

    @State private var showAddNode = false
    @State private var draftNode = ""

    var body: some View {
        NavigationStack {
            Form {
                nodeSection
                keySection
                portSection
                aboutSection
            }
            .navigationTitle("设置")
            .alert("添加订阅节点", isPresented: $showAddNode) {
                TextField("节点 IP", text: $draftNode)
                    .keyboardType(.numbersAndPunctuation)
                Button("取消", role: .cancel) { draftNode = "" }
                Button("添加") {
                    model.addNode(draftNode)
                    draftNode = ""
                }
            } message: {
                Text("只填节点 IP，上报端口固定 1082")
            }
        }
    }

    // MARK: - 订阅节点

    private var nodeSection: some View {
        Section {
            ForEach(model.nodes, id: \.self) { ip in
                Button {
                    model.selectNode(ip)
                } label: {
                    HStack {
                        Text(ip)
                            .font(.body.monospaced())
                            .foregroundStyle(.primary)
                        Spacer()
                        if ip == model.selectedHost {
                            Image(systemName: "checkmark")
                                .foregroundStyle(Color.accentColor)
                        }
                    }
                }
                .swipeActions(edge: .trailing) {
                    Button("删除", role: .destructive) { model.removeNode(ip) }
                }
            }

            Button {
                draftNode = ""
                showAddNode = true
            } label: {
                Label("添加节点", systemImage: "plus")
            }
        } header: {
            Text("订阅节点")
        } footer: {
            Text("点一行即选中为上报节点，左滑删除；至少保留一个节点。")
        }
    }

    // MARK: - 房间 KEY

    private var keySection: some View {
        Section {
            TextField("32 位十六进制", text: $model.roomKeyText)
                .font(.body.monospaced())
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
        } header: {
            Text("房间 KEY")
        } footer: {
            Text("既是预共享密钥也是房间号；不填节点会拒绝鉴权。")
        }
    }

    // MARK: - 监听端口

    private var portSection: some View {
        Section {
            TextField("1010", text: $model.portText)
                .font(.body.monospacedDigit())
                .keyboardType(.numberPad)
                .disabled(model.isRunning)
        } header: {
            Text("监听端口")
        } footer: {
            Text(model.isRunning ? "监听中不能修改端口。" : "热点设备把 http/socks 代理指到本机这个端口。")
        }
    }

    // MARK: - 关于

    private var aboutSection: some View {
        Section("关于") {
            LabeledContent("应用", value: "GORaDar")
            LabeledContent("版本", value: version)
        }
    }

    private var version: String {
        let info = Bundle.main.infoDictionary
        let short = info?["CFBundleShortVersionString"] as? String ?? "1.0"
        let build = info?["CFBundleVersion"] as? String ?? "1"
        return "\(short) (\(build))"
    }
}
