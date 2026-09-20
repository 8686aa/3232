import Combine
import SwiftUI

@main
struct StarRadarApp: App {
    @StateObject private var model = EngineViewModel()

    var body: some Scene {
        WindowGroup {
            RootTabView(model: model)
                .preferredColorScheme(.dark)
        }
    }
}

/// 底部导航：Tab 0 = 首页（采集与上报全部功能），Tab 1 = 内置雷达（内嵌浏览器）
struct RootTabView: View {
    @ObservedObject var model: EngineViewModel
    @State private var tab = 0

    var body: some View {
        TabView(selection: $tab) {
            ContentView(model: model)
                .tabItem { Label("首页", systemImage: "house.fill") }
                .tag(0)

            RadarTabPage()
                .tabItem { Label("内置雷达", systemImage: "dot.radiowaves.left.and.right") }
                .tag(1)
        }
        .tint(P.color(P.CYAN))
        // 首页开始监听成功 -> 自动跳到内置雷达页
        .onReceive(RadarRouter.shared.$request.compactMap { $0 }) { _ in
            tab = 1
        }
    }
}
