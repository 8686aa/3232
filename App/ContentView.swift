import SwiftUI
import StarRadarCore

struct ContentView: View {
    @ObservedObject var model: EngineViewModel

    var body: some View {
        NavigationStack {
            Form {
                listenSection
                statsSection
                materialSection
                logSection
                hintSection
            }
            .navigationTitle("中间人")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(model.isRunning ? "停止" : "启动") {
                        model.isRunning ? model.stop() : model.start()
                    }
                    .bold()
                    .tint(model.isRunning ? .red : .accentColor)
                }
            }
            .alert("出错了", isPresented: errorBinding) {
                Button("好", role: .cancel) { model.errorMessage = nil }
            } message: {
                Text(model.errorMessage ?? "")
            }
        }
    }

    // MARK: - 配置

    private var listenSection: some View {
        Section {
            LabeledContent("监听端口") {
                TextField("1080", text: $model.portText)
                    .keyboardType(.numberPad)
                    .multilineTextAlignment(.trailing)
                    .disabled(model.isRunning)
            }
            LabeledContent("拦截端口") {
                TextField("158", text: $model.interceptPortsText)
                    .keyboardType(.numbersAndPunctuation)
                    .multilineTextAlignment(.trailing)
                    .disabled(model.isRunning)
            }
            LabeledContent("对外地址") {
                TextField("自动探测", text: $model.advertisedHost)
                    .multilineTextAlignment(.trailing)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .disabled(model.isRunning)
            }
        } header: {
            Text("配置")
        } footer: {
            Text("对外地址是告诉小火箭「UDP 往哪发」的地址。自动探测不准（比如走热点）时必须手工填本机在同一个网段里的 IP。")
        }
    }

    // MARK: - 状态

    private var statsSection: some View {
        Section("状态") {
            LabeledContent("运行", value: model.isRunning ? model.listenSummary : "未启动")
            LabeledContent("CONNECT", value: "\(model.stats.connectAccepted)")
            LabeledContent("UDP ASSOCIATE", value: "\(model.stats.udpAssociateAccepted)")
            LabeledContent("中间人会话 / 纯转发", value: "\(model.stats.middlemanSessions) / \(model.stats.relaySessions)")
            LabeledContent("ClientHello / ServerHello", value: "\(model.stats.clientHelloSeen) / \(model.stats.serverHelloSeen)")
            LabeledContent("已翻译帧 / 失败", value: "\(model.stats.translatedFrames) / \(model.stats.translateFailures)")
            LabeledContent("UDP 上行 / 下行", value: "\(model.stats.udpDatagramsToUpstream) / \(model.stats.udpDatagramsFromUpstream)")
            LabeledContent("UDP 流", value: "\(model.stats.udpFlows)")
            if let lastError = model.stats.lastError {
                Text(lastError).font(.footnote).foregroundStyle(.red)
            }
        }
    }

    // MARK: - 候选密钥

    private var materialSection: some View {
        Section("候选密钥") {
            LabeledContent("候选数", value: "\(model.stats.cryptoCandidates)")
            if let hex = model.latestMaterialHex {
                Text(hex)
                    .font(.system(.caption2, design: .monospaced))
                    .textSelection(.enabled)
                Button("复制最近的 128 字节材料") { model.copyLatestMaterial() }
            } else {
                Text("尚未从 0x4013 指令里捞到候选材料")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
    }

    // MARK: - 日志

    private var logSection: some View {
        Section("事件日志") {
            if model.logLines.isEmpty {
                Text("暂无事件").font(.footnote).foregroundStyle(.secondary)
            } else {
                // 倒序显示尾部，免去滚动定位
                ForEach(Array(model.logLines.suffix(60).reversed()), id: \.self) { line in
                    Text(line)
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private var hintSection: some View {
        Section("小火箭侧") {
            Text("1. 代理类型选 SOCKS5，指向本机 端口 \(model.portText)")
            Text("2. 全局路由设为「代理」，否则游戏 UDP 会被规则直连放走")
            Text("3. 保持本 App 在前台，iOS 会挂起后台应用")
        }
        .font(.footnote)
    }

    private var errorBinding: Binding<Bool> {
        Binding(
            get: { model.errorMessage != nil },
            set: { if !$0 { model.errorMessage = nil } }
        )
    }
}
