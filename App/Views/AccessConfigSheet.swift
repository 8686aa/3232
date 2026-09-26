import CoreImage.CIFilterBuiltins
import SwiftUI
import UIKit

// ============================================================================
// 接入配置：把「本机这个 SOCKS5 监听」翻译成各家客户端能直接导入的配置。
//
// 场景：游戏设备通过热点接到本机，本机跑一个无认证的 SOCKS5（端口就是设置页的
// 「监听端口」）。原先要在游戏设备上逐字段手填，这里按客户端类型一键生成。
//
// 按「怎么导入」分两类，不是一家一套格式：
//   · 分享链接（socks://…) —— Shadowrocket 与 NekoBox 都吃，可扫码或剪贴板导入，
//     但两家解析方式不同：Shadowrocket 认 base64 形态，NekoBox 只认明文 host:port；
//   · JSON 配置 —— sing-box 官方 App 只认这个，它不吃分享链接。
// ============================================================================

/// 一处接入点：客户端要连的就是本机内网地址 + 监听端口
struct AccessEndpoint {
    let host: String
    let port: UInt16
    /// 订阅里显示的名字
    let name = "GORaDar-本机"

    var hostPort: String { "\(host):\(port)" }
}

/// 目标客户端
enum AccessClient: String, CaseIterable, Identifiable {
    case shadowrocket
    case singbox
    case nekobox

    var id: String { rawValue }

    var title: String {
        switch self {
        case .shadowrocket: return "Shadowrocket"
        case .singbox:      return "sing-box"
        case .nekobox:      return "NekoBox"
        }
    }

    /// 生成出来的配置文本
    func config(for endpoint: AccessEndpoint) -> String {
        switch self {
        case .shadowrocket:
            // Shadowrocket 的 socks 链接是 v2rayN 那一套：socks://base64(host:port)#备注
            return Self.base64Link(endpoint)
        case .nekobox:
            // NekoBox 只认明文：它的 parseSOCKS 直接拿 okhttp HttpUrl 读 host/port
            return Self.plainLink(endpoint)
        case .singbox:
            // sing-box 官方 App 不吃分享链接，只认完整 JSON：tun 入口 + SOCKS5 出口
            return Self.json(endpoint)
        }
    }

    /// 是不是分享链接形态，决定出不出二维码：
    /// JSON 上千字符二维码塞不下也扫不动，而 sing-box 官方 App 本来也不扫码导入。
    var isLink: Bool { self == .shadowrocket || self == .nekobox }

    /// 导入说明
    var hint: String {
        switch self {
        case .shadowrocket:
            return "游戏设备上打开 Shadowrocket，扫二维码，或复制链接后打开 App 会自动识别。"
                + "扫码不认时，按上面的「接入参数」手动添加一条 SOCKS5 节点。"
        case .singbox:
            return "存成 .json 文件后在 sing-box 里「配置 → 新建 → 从文件导入」，也可以复制后从剪贴板导入。"
        case .nekobox:
            return "扫二维码，或复制链接后在 NekoBox 里「配置 → 新建配置 → 从剪贴板导入」（扫码需 1.4.0 及以上）。"
        }
    }

    /// v2rayN 形态的 SOCKS5 链接：socks://<base64(host:port)>#备注。
    /// 本机不校验账号密码，所以 userinfo 段直接省掉。
    private static func base64Link(_ endpoint: AccessEndpoint) -> String {
        let payload = Data(endpoint.hostPort.utf8).base64EncodedString()
        return "socks://\(payload)#\(fragment(endpoint))"
    }

    /// 明文形态：socks://host:port#备注。
    ///
    /// NekoBox 的 parseSOCKS 是 `("http://" + link).toHttpUrlOrNull()` 之后取
    /// `url.host` / `url.port`，所以 base64 塞进来会被整个当成主机名（顺带被小写化），
    /// 端口取不到就落到 HttpUrl 的默认 80 —— 必须给它明文。
    private static func plainLink(_ endpoint: AccessEndpoint) -> String {
        "socks://\(endpoint.hostPort)#\(fragment(endpoint))"
    }

    /// 链接尾部的备注，非 ASCII 要转义
    private static func fragment(_ endpoint: AccessEndpoint) -> String {
        endpoint.name.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? endpoint.name
    }

    /// sing-box 的 JSON：tun 收全量流量，出口是本机 SOCKS5；内网地址走直连，
    /// 免得连热点本身也被塞进隧道里。
    private static func json(_ endpoint: AccessEndpoint) -> String {
        """
        {
          "log": { "level": "info" },
          "inbounds": [
            {
              "type": "tun",
              "tag": "tun-in",
              "address": ["172.19.0.1/30"],
              "auto_route": true,
              "stack": "system"
            }
          ],
          "outbounds": [
            {
              "type": "socks",
              "tag": "goradar",
              "server": "\(endpoint.host)",
              "server_port": \(endpoint.port),
              "version": "5"
            },
            { "type": "direct", "tag": "direct" }
          ],
          "route": {
            "rules": [
              {
                "ip_cidr": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
                "outbound": "direct"
              }
            ],
            "final": "goradar"
          }
        }
        """
    }
}

/// 接入配置面板：选客户端 → 看配置 → 复制 / 分享 / 扫码
struct AccessConfigSheet: View {
    @ObservedObject var model: EngineViewModel

    @Environment(\.dismiss) private var dismiss
    @State private var client: AccessClient = .shadowrocket
    @State private var copied = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    picker
                    if let endpoint {
                        configBox(endpoint)
                        actions(endpoint)
                        if client.isLink { qrBox(endpoint) }
                        params(endpoint)
                        tip
                    } else {
                        unavailable
                    }
                }
                .padding(16)
            }
            .navigationTitle("接入配置")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("完成") { dismiss() }
                }
            }
        }
    }

    // MARK: - 派生

    /// 客户端要连的地址：优先用引擎对外公布的那个，没有就用本机内网地址
    private var endpoint: AccessEndpoint? {
        let advertised = model.advertisedHost.trimmingCharacters(in: .whitespaces)
        let host = advertised.isEmpty ? model.localIp : advertised
        guard host != "—", !host.isEmpty else { return nil }
        guard let port = UInt16(model.portText.trimmingCharacters(in: .whitespaces)), port > 0 else {
            return nil
        }
        return AccessEndpoint(host: host, port: port)
    }

    // MARK: - 各块

    private var picker: some View {
        Picker("客户端", selection: $client) {
            ForEach(AccessClient.allCases) { item in
                Text(item.title).tag(item)
            }
        }
        .pickerStyle(.segmented)
        .onChange(of: client) { _ in copied = false }
    }

    private func configBox(_ endpoint: AccessEndpoint) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("配置内容").font(.footnote).foregroundStyle(.secondary)
            Text(client.config(for: endpoint))
                .font(.system(.footnote, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(12)
                .background(Color(.secondarySystemBackground))
                .clipShape(RoundedRectangle(cornerRadius: 10))
        }
    }

    private func actions(_ endpoint: AccessEndpoint) -> some View {
        let text = client.config(for: endpoint)
        return HStack(spacing: 12) {
            Button {
                UIPasteboard.general.string = text
                copied = true
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
            } label: {
                Label(copied ? "已复制" : "复制", systemImage: copied ? "checkmark" : "doc.on.doc")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)

            ShareLink(item: text, subject: Text("GORaDar 接入配置"), message: Text(client.hint)) {
                Label("分享", systemImage: "square.and.arrow.up")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
        }
        .controlSize(.large)
    }

    private func qrBox(_ endpoint: AccessEndpoint) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("二维码").font(.footnote).foregroundStyle(.secondary)
            HStack {
                Spacer()
                if let image = Self.qrImage(client.config(for: endpoint)) {
                    Image(uiImage: image)
                        .interpolation(.none)
                        .resizable()
                        .scaledToFit()
                        .frame(width: 200, height: 200)
                        .padding(10)
                        .background(Color.white)
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                } else {
                    Text("二维码生成失败，用「复制」把链接发过去即可")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
        }
    }

    private func params(_ endpoint: AccessEndpoint) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("接入参数").font(.footnote).foregroundStyle(.secondary)
            VStack(spacing: 0) {
                paramRow("类型", "SOCKS5")
                Divider()
                paramRow("服务器", endpoint.host)
                Divider()
                paramRow("端口", "\(endpoint.port)")
                Divider()
                paramRow("认证", "无")
            }
            .background(Color(.secondarySystemBackground))
            .clipShape(RoundedRectangle(cornerRadius: 10))
        }
    }

    private func paramRow(_ label: String, _ value: String) -> some View {
        HStack {
            Text(label)
            Spacer()
            Text(value).font(.body.monospaced())
        }
        .font(.subheadline)
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
    }

    private var tip: some View {
        Text(client.hint)
            .font(.footnote)
            .foregroundStyle(.secondary)
    }

    private var unavailable: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("暂时生成不了", systemImage: "exclamationmark.triangle.fill")
                .font(.subheadline)
                .foregroundStyle(Color.orange)
            Text("没拿到本机内网地址，或「监听端口」不是 1–65535 的整数。"
                + "确认手机已连上 Wi-Fi/热点，并在设置里检查监听端口。")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(.secondarySystemBackground))
        .clipShape(RoundedRectangle(cornerRadius: 10))
    }

    // MARK: - 二维码

    /// 把文本画成二维码位图（放大 8 倍保证扫码时足够清晰）
    private static func qrImage(_ text: String) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        // M 级纠错：20% 冗余，贴屏幕上扫足够，二维码也不会太密
        filter.correctionLevel = "M"
        guard let output = filter.outputImage else { return nil }
        let scaled = output.transformed(by: CGAffineTransform(scaleX: 8, y: 8))
        guard let cgImage = CIContext().createCGImage(scaled, from: scaled.extent) else { return nil }
        return UIImage(cgImage: cgImage)
    }
}
