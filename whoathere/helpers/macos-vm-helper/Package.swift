// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "WhoaThereMacosVmHelper",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(name: "WhoaThereMacosVmHelperCore", targets: ["WhoaThereMacosVmHelperCore"]),
        .executable(name: "whoathere-macos-vm-helper", targets: ["WhoaThereMacosVmHelper"])
    ],
    targets: [
        .target(name: "WhoaThereMacosVmHelperCore"),
        .executableTarget(
            name: "WhoaThereMacosVmHelper",
            dependencies: ["WhoaThereMacosVmHelperCore"]
        ),
        .testTarget(
            name: "WhoaThereMacosVmHelperCoreTests",
            dependencies: ["WhoaThereMacosVmHelperCore"]
        )
    ]
)
