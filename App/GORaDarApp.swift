import Combine
import SwiftUI

@main
struct GORaDarApp: App {
    @StateObject private var model = EngineViewModel()

    var body: some Scene {
        WindowGroup {
            RootTabView(model: model)
        }
    }
}

/// 底部导航：概览 / 链路 / 数据 / 设置 / 雷达，每页只放一类信息。
struct RootTabView: View {
    @ObservedObject var model: EngineViewModel
    @State private var tab = 0

    var body: some View {
        TabView(selection: $tab) {
            OverviewPage(model: model)
                .tabItem { Label("概览", systemImage: "speedometer") }
                .tag(0)

            LinkPage(model: model)
                .tabItem { Label("链路", systemImage: "network") }
                .tag(1)

            DataPage(model: model)
                .tabItem { Label("数据", systemImage: "list.bullet") }
                .tag(2)

            SettingsPage(model: model)
                .tabItem { Label("设置", systemImage: "gearshape") }
                .tag(3)

            RadarTabPage(model: model)
                .tabItem { Label("雷达", systemImage: "safari") }
                .tag(4)
        }
        // 开始监听成功 → RadarRouter 取到分享链接 → 自动切到内置雷达页
        .onReceive(RadarRouter.shared.$request.compactMap { $0 }) { _ in
            tab = 4
        }
    }
}
