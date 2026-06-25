// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "WhoaThereTimer",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(name: "WhoaThereTimerCore", targets: ["WhoaThereTimerCore"]),
        .executable(name: "whoathere-timer", targets: ["WhoaThereTimer"])
    ],
    targets: [
        .target(name: "WhoaThereTimerCore"),
        .executableTarget(
            name: "WhoaThereTimer",
            dependencies: ["WhoaThereTimerCore"]
        ),
        .testTarget(
            name: "WhoaThereTimerCoreTests",
            dependencies: ["WhoaThereTimerCore"]
        )
    ]
)
