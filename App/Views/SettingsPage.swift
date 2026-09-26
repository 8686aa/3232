import SwiftUI

/// 设置页：订阅节点、雷达账号、房间 KEY、监听端口。
struct SettingsPage: View {
    @ObservedObject var model: EngineViewModel

    @State private var showAddNode = false
    @State private var draftNode = ""
    /// 密码只在本次运行里存在，不进 UserDefaults
    @State private var accountPass = ""
    @State private var showAccess = false

    var body: some View {
        NavigationStack {
            Form {
                nodeSection
                accountSection
                keySection
                portSection
                accessSection
                aboutSection
            }
            .readableFrame()
            .navigationTitle("设置")
            .sheet(isPresented: $showAccess) {
                AccessConfigSheet(model: model)
            }
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

    // MARK: - 雷达账号

    private var accountSection: some View {
        Section {
            TextField("账号", text: $model.accountUser)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()

            SecureField("密码", text: $accountPass)

            Button {
                model.loginAccount(password: accountPass)
            } label: {
                Label("登录并获取 KEY", systemImage: "person.badge.key")
            }
            .disabled(model.accountState == .busy
                      || model.accountUser.trimmingCharacters(in: .whitespaces).isEmpty
                      || accountPass.isEmpty)

            accountStatus
        } header: {
            Text("雷达账号")
        } footer: {
            Text(model.currentNode.isEmpty
                 ? "先在上面添加并选中一个节点，登录会打到该节点的雷达服务。"
                 : "向节点 \(model.currentNode) 的雷达服务登录，成功即把该账号的 KEY 填到下面的「房间 KEY」。"
                   + "密码不会保存；KEY 改完要重新开始监听才生效。")
        }
    }

    @ViewBuilder
    private var accountStatus: some View {
        switch model.accountState {
        case .idle:
            EmptyView()
        case .busy:
            HStack(spacing: 8) {
                ProgressView()
                Text("登录中…")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        case .ok(let text):
            Label(text, systemImage: "checkmark.circle.fill")
                .font(.footnote)
                .foregroundStyle(Color.green)
        case .fail(let text):
            Label(text, systemImage: "exclamationmark.triangle.fill")
                .font(.footnote)
                .foregroundStyle(Color.red)
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

    // MARK: - 接入配置

    private var accessSection: some View {
        Section {
            Button {
                showAccess = true
            } label: {
                Label("一键生成接入配置", systemImage: "square.and.arrow.up.on.square")
            }
        } header: {
            Text("接入配置")
        } footer: {
            Text("生成 Shadowrocket / sing-box / NekoBox 三类配置，代理都指向本机 "
                 + "\(model.localIp):\(model.portText)。游戏设备导入后就不用再手填字段。")
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
