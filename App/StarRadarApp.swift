import SwiftUI

@main
struct StarRadarApp: App {
    @StateObject private var model = EngineViewModel()

    var body: some Scene {
        WindowGroup {
            ContentView(model: model)
        }
    }
}
