// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "BatonPass",
    platforms: [.macOS(.v13)],
    dependencies: [.package(path: "../../core")],
    targets: [
        .executableTarget(
            name: "BatonPass",
            dependencies: [.product(name: "BatonPassCore", package: "core")],
            path: "Sources/BatonPass"
        )
    ]
)
