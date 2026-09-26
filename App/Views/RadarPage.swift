import Combine
import Foundation
import SwiftUI
import WebKit

// ============================================================================
// 内置雷达页：内嵌浏览器加载一个可自定义的服务器地址
// 首页「开始监听」成功后先向 <节点IP>:666 校验房间Key，取回分享链接再跳到这里；
// 地址栏内容持久化，重启后仍是上次填写的地址。
// ============================================================================

/// 雷达服务（HTTP）端口，固定不可改；与转发器上报端口(ws 1082)部署在同一台机器、同一个 IP
let radarHTTPPort = 666

/// 旧版本拿它当地址栏默认值。它已经写进老用户的 UserDefaults，
/// 不认出来就会一直用一个和雷达无关的页面当首页。
private let legacyRadarPlaceholder = "http://baidu.com"

/// 一次「跳到内置雷达」请求。每次都用新的 id，保证同一请求重复触发也能被 onChange 收到。
struct RadarOpenRequest: Equatable {
    let id = UUID()
    /// nil = 沿用雷达页自己保存的地址
    var url: String? = nil
}

/// 首页在开始监听成功后调用 openShare()；根视图与雷达页各自监听同一个发布者，
/// 不依赖调用顺序（Tab 子页可能在切到该 Tab 时才构建，故页面 onAppear 里补收一次）。
final class RadarRouter: ObservableObject {
    static let shared = RadarRouter()
    @Published var request: RadarOpenRequest?

    /// 日志出口。由 EngineViewModel 在启动时接上，未接上时静默丢弃。
    var log: ((String) -> Void)?

    private init() {}

    func open(url: String? = nil) { request = RadarOpenRequest(url: url) }
}

// MARK: - 雷达服务地址推导
//
// 转发器(ws 1082)与雷达服务(http 666)部署在同一台机器、同一个 IP，只是端口不同。
// 这里按约定把节点 IP 换算成雷达服务地址，避免再为每个节点多配一个字段。
// 若服务端改了 666 端口，需同步改 radarHTTPPort。
extension RadarRouter {
    /// 雷达服务基址：ws://host:1082 -> http://host:666
    func radarBaseURL(host: String) -> URL? {
        let h = host.trimmingCharacters(in: .whitespaces)
        guard !h.isEmpty else { return nil }
        var c = URLComponents()
        c.scheme = "http"
        c.host = h
        c.port = radarHTTPPort
        return c.url
    }

    /// 校验 key 并取回分享链接的接口地址：GET /api/share/by_key?key=<32位hex>
    func shareByKeyURL(host: String, apiKey: String) -> URL? {
        guard let base = radarBaseURL(host: host),
              var c = URLComponents(url: base.appendingPathComponent("api/share/by_key"),
                                    resolvingAgainstBaseURL: false) else { return nil }
        c.queryItems = [URLQueryItem(name: "key", value: apiKey)]
        return c.url
    }

    /// 账号登录接口地址：POST /api/auth/login，body 为 {"username":…,"password":…}
    func loginURL(host: String) -> URL? {
        guard let base = radarBaseURL(host: host) else { return nil }
        return base.appendingPathComponent("api/auth/login")
    }

    /// 开始监听后调用：向 <节点IP>:666 校验房间Key，服务端回 {"ok":true,"url":"…"} 时打开该链接。
    func openShare(host: String, apiKey: String) {
        guard !apiKey.isEmpty else {
            log?("[雷达] 房间未配置，不自动打开雷达页")
            return
        }
        guard let url = shareByKeyURL(host: host, apiKey: apiKey) else {
            log?("[雷达] 无法从节点 \(host) 推导雷达服务地址，跳过自动打开")
            return
        }
        log?("[雷达] 正在向节点校验房间…")
        var req = URLRequest(url: url)
        req.timeoutInterval = 6
        req.cachePolicy = .reloadIgnoringLocalCacheData
        URLSession.shared.dataTask(with: req) { [weak self] data, response, error in
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            var link: String?
            var message: String
            if let error = error {
                message = "校验失败：\(error.localizedDescription)"
            } else if let data = data,
                      let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] {
                if (obj["ok"] as? Bool) == true, let text = obj["url"] as? String {
                    link = text
                    let name = obj["username"] as? String ?? ""
                    let code = obj["code"] as? String ?? ""
                    message = "校验通过（\(name) / \(code)），打开雷达页"
                } else {
                    message = "校验失败：\(obj["error"] as? String ?? "未知错误")"
                }
            } else if status == 404 {
                // 服务端对无效 KEY 直接回 404 且响应体为空，不单独认出来就会误报成「无响应」
                message = "校验失败：KEY 无效，或该账号还没有共享码"
            } else if status != 0, status != 200 {
                message = "校验失败：雷达服务返回 HTTP \(status)"
            } else {
                message = "校验失败：雷达服务无响应"
            }
            DispatchQueue.main.async {
                self?.log?("[雷达] \(message)")
                if let link = link { RadarRouter.shared.open(url: link) }
            }
        }.resume()
    }
}

/// 供刷新按钮持有的 WebView 引用
private final class WebBox {
    weak var web: WKWebView?
}

private struct RadarWebView: UIViewRepresentable {
    let url: URL
    /// 每次「前往」自增。光比地址不够：地址没变、但用户就是想重载（白屏后重试）时，
    /// 只比 url 会把这次点击当成「例行刷新」吞掉，界面上就是「点了没反应」。
    let token: Int
    let box: WebBox

    /// 既是 SwiftUI 的 Coordinator，也当 WKNavigationDelegate。
    /// 加代理只为一件事：把加载失败写进日志 —— WKWebView 的失败默认是静默的，
    /// 界面只表现为「没反应」，事后无从判断是压根没发起加载、还是加载挂了。
    final class Coordinator: NSObject, WKNavigationDelegate {
        /// 记录已加载的地址 + 版本号，用于区分「用户主动加载」和「SwiftUI 例行刷新」
        var loadedURL: URL?
        var loadedToken = Int.min

        func webView(_ webView: WKWebView, didStartProvisionalNavigation navigation: WKNavigation!) {
            RadarRouter.shared.log?("[雷达] 正在加载 \(webView.url?.absoluteString ?? "")")
        }

        func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!,
                     withError error: Error) {
            RadarRouter.shared.log?("[雷达] 加载失败：\(error.localizedDescription)")
        }

        func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
            RadarRouter.shared.log?("[雷达] 加载失败：\(error.localizedDescription)")
        }

        /// 内存吃紧时系统会回收网页内容进程，表现就是整页空白、之后点哪都没反应
        func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
            RadarRouter.shared.log?("[雷达] 网页进程被系统回收，点刷新可重载")
        }
    }

    func makeCoordinator() -> Coordinator { Coordinator() }

    func makeUIView(context: Context) -> WKWebView {
        let w = WKWebView()
        w.isOpaque = false
        w.backgroundColor = .clear
        w.navigationDelegate = context.coordinator
        box.web = w
        context.coordinator.loadedURL = url
        context.coordinator.loadedToken = token
        w.load(URLRequest(url: url))
        return w
    }

    func updateUIView(_ uiView: WKWebView, context: Context) {
        // 只有用户主动改过地址或点了「前往」才重新加载，
        // 否则每次界面刷新都会把页面重载一遍（3D 视图的镜头会被重置掉）
        guard context.coordinator.loadedURL != url || context.coordinator.loadedToken != token else { return }
        context.coordinator.loadedURL = url
        context.coordinator.loadedToken = token
        uiView.load(URLRequest(url: url))
    }
}

/// 内置雷达页（Tab 5）：顶部原生地址栏 + 刷新，下方内嵌浏览器
struct RadarTabPage: View {
    @ObservedObject var model: EngineViewModel

    @State private var box = WebBox()
    /// 地址栏文本（持久化：重启后仍是上次填写的地址）
    @AppStorage("radar_url") private var urlText = ""
    /// 当前已加载的地址；nil = 还没决定加载什么，界面显示占位提示而不是空白网页
    @State private var url: URL?
    /// 「前往」的版本号：同一地址重复点也要真的重载，详见 RadarWebView.token
    @State private var loadToken = 0

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                addressBar
                Divider()
                browser
            }
            .navigationTitle("雷达")
            .navigationBarTitleDisplayMode(.inline)
            .onAppear {
                // TabView 的子页可能在切到该 Tab 时才构建，此时收不到已发出的请求，这里补一次
                if let req = RadarRouter.shared.request {
                    open(req)
                } else {
                    restore()
                }
            }
            .onReceive(RadarRouter.shared.$request.compactMap { $0 }) { req in
                open(req)
            }
        }
    }

    @ViewBuilder
    private var browser: some View {
        if let url {
            RadarWebView(url: url, token: loadToken, box: box)
        } else {
            VStack(spacing: 10) {
                Image(systemName: "network.slash")
                    .font(.largeTitle)
                    .foregroundStyle(.secondary)
                Text("先在「设置」里添加并选中一个节点")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private var addressBar: some View {
        HStack(spacing: 10) {
            Image(systemName: "network")
                .font(.footnote)
                .foregroundStyle(.secondary)

            TextField("输入服务器地址", text: $urlText)
                .textFieldStyle(.roundedBorder)
                .font(.footnote)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled(true)
                .keyboardType(.URL)
                .submitLabel(.go)
                .onSubmit { go() }

            Button(action: go) {
                Image(systemName: "arrow.right.circle.fill")
                    .font(.title3)
            }
            .disabled(urlText.trimmingCharacters(in: .whitespaces).isEmpty)

            Button { box.web?.reload() } label: {
                Image(systemName: "arrow.clockwise")
                    .font(.body)
            }
            .disabled(url == nil)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(.bar)
    }

    /// 页面首次出现时决定加载什么：优先上次用过的地址，其次当前节点的雷达服务。
    /// 两者都没有（还没配节点）就留空，由 browser 出提示。
    private func restore() {
        guard url == nil else { return }

        let saved = urlText.trimmingCharacters(in: .whitespacesAndNewlines)
        if !saved.isEmpty, saved != legacyRadarPlaceholder,
           let u = URL(string: saved), u.host != nil {
            url = u
            return
        }
        guard let base = RadarRouter.shared.radarBaseURL(host: model.currentNode) else { return }
        urlText = base.absoluteString
        url = base
    }

    /// 地址栏提交：未带协议头时自动补 http://
    private func go() {
        var t = urlText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !t.isEmpty else { return }
        if !t.lowercased().hasPrefix("http://") && !t.lowercased().hasPrefix("https://") {
            t = "http://" + t
        }
        guard let u = URL(string: t), u.host != nil else {
            RadarRouter.shared.log?("[雷达] 地址无法解析：\(t)")
            return
        }
        urlText = u.absoluteString   // 回填规范化后的地址
        url = u
        loadToken += 1               // 地址没变也要真加载一次（白屏后重复点「前往」即重试）
    }

    /// 载入外部请求的地址；请求未带地址时沿用当前地址（只做跳转，不重载）
    private func open(_ req: RadarOpenRequest) {
        guard let text = req.url, let u = URL(string: text), u.host != nil else { return }
        urlText = u.absoluteString
        // 地址没变就不重载：切 Tab 会重放一次同一个请求，不能把已经渲染好的页面刷掉
        if u != url { loadToken += 1 }
        url = u
    }
}
