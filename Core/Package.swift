// swift-tools-version: 5.9
import PackageDescription

// 方案 A 的可复用核心：SOCKS5 中间人 + TGCP/RawDH 协议移植。
// 这一层不依赖 UIKit，可以在 macOS 上直接 `swift test` 验证纯逻辑；
// ios/App/ 下的 SwiftUI 壳需要单独建一个 iOS App target 来引用本包。
let package = Package(
    name: "StarRadarCore",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
    ],
    products: [
        .library(name: "StarRadarCore", targets: ["StarRadarCore"]),
    ],
    targets: [
        .target(name: "StarRadarCore"),
        .testTarget(
            name: "StarRadarCoreTests",
            dependencies: ["StarRadarCore"]
        ),
    ]
)
