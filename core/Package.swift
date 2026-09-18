// swift-tools-version:5.9
import PackageDescription

// Shared by the macOS agent and the iOS app. The envelope must not exist twice in
// Swift: two copies drift, and a drifted receiver is a security bug, not a bug.
let package = Package(
    name: "BatonPassCore",
    platforms: [.macOS(.v13), .iOS(.v17)],
    products: [.library(name: "BatonPassCore", targets: ["BatonPassCore"])],
    targets: [
        .target(name: "BatonPassCore", path: "Sources/BatonPassCore"),
        .testTarget(name: "BatonPassCoreTests", dependencies: ["BatonPassCore"], path: "Tests/BatonPassCoreTests")
    ]
)
