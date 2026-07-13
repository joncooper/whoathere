// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "WhoaThereMacosVmHelper",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(name: "WhoaThereMacosVmHelperCore", targets: ["WhoaThereMacosVmHelperCore"]),
        .executable(name: "whoathere-macos-vm-helper", targets: ["WhoaThereMacosVmHelper"]),
        .executable(
            name: "whoathere-linux-vz-conformance",
            targets: ["WhoaThereLinuxVzConformance"]
        ),
        .executable(
            name: "whoathere-linux-vz-identity-verify",
            targets: ["WhoaThereLinuxVzIdentityVerify"]
        ),
        .executable(
            name: "whoathere-linux-vz-signed-conformance",
            targets: ["WhoaThereLinuxVzSignedConformance"]
        ),
        .executable(
            name: "whoathere-linux-vz-host-keygen",
            targets: ["WhoaThereLinuxVzHostKeygen"]
        ),
        .executable(
            name: "whoathere-linux-vz-package-runtime-identity-verify",
            targets: ["WhoaThereLinuxVzPackageRuntimeIdentityVerify"]
        ),
        .executable(
            name: "whoathere-linux-vz-runtime-qualification",
            targets: ["WhoaThereLinuxVzRuntimeQualification"]
        )
    ],
    targets: [
        .target(name: "WhoaThereMacosVmHelperCore"),
        .executableTarget(
            name: "WhoaThereMacosVmHelper",
            dependencies: ["WhoaThereMacosVmHelperCore"]
        ),
        .executableTarget(
            name: "WhoaThereLinuxVzConformance",
            dependencies: ["WhoaThereMacosVmHelperCore"]
        ),
        .executableTarget(
            name: "WhoaThereLinuxVzIdentityVerify",
            dependencies: ["WhoaThereMacosVmHelperCore"]
        ),
        .executableTarget(
            name: "WhoaThereLinuxVzSignedConformance",
            dependencies: ["WhoaThereMacosVmHelperCore"]
        ),
        .executableTarget(
            name: "WhoaThereLinuxVzHostKeygen"
        ),
        .executableTarget(
            name: "WhoaThereLinuxVzPackageRuntimeIdentityVerify",
            dependencies: ["WhoaThereMacosVmHelperCore"]
        ),
        .executableTarget(
            name: "WhoaThereLinuxVzRuntimeQualification",
            dependencies: ["WhoaThereMacosVmHelperCore"]
        ),
        .testTarget(
            name: "WhoaThereMacosVmHelperCoreTests",
            dependencies: ["WhoaThereMacosVmHelperCore"]
        )
    ]
)
