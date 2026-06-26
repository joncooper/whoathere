import Darwin
import Foundation
import Virtualization
import WhoaThereMacosVmHelperCore

@main
struct WhoaThereMacosVmHelper {
    static func main() {
        do {
            let options = try parseArguments(Array(CommandLine.arguments.dropFirst()))
            run(options)
        } catch {
            emit(
                fields: [
                    "schema_version": bundleSchemaVersion,
                    "helper_version": helperVersion,
                    "status": "error",
                    "reason_codes": [String(describing: error)],
                    "exit_code": 64
                ],
                exitCode: 64
            )
        }
    }

    private static func run(_ options: HelperOptions) {
        switch options.command {
        case .version:
            version()
        case .status:
            status(options)
        case .`init`:
            initialize(options)
        case .start:
            start(options)
        case .run:
            runPersistentVm(options)
        case .suspend:
            suspend(options)
        case .reset:
            reset(options)
        case .prune:
            prune(options)
        case .health:
            health(options)
        }
    }

    private static func version() {
        emit(
            fields: baseFields(status: "ok").merging([
                "virtualization_framework_linked": virtualizationFrameworkLinked(),
                "host_supported": hostSupported()
            ]) { _, new in new },
            exitCode: 0
        )
    }

    private static func status(_ options: HelperOptions) {
        let layout = BundleLayout(stateDir: stateDirURL(from: options))
        let reasonCodes = statusReasons(layout: layout)
        let readyForLifecycle = reasonCodes.isEmpty
        let runtimePID = readRuntimePID(layout)
        let runtimeAlive = runtimePID.map(processIsAlive) ?? false
        emit(
            fields: baseFields(status: readyForLifecycle ? "ok" : "fail_closed").merging([
                "state_dir": layout.stateDir.path,
                "bundle_dir": layout.bundleDir.path,
                "host_supported": hostSupported(),
                "virtualization_framework_linked": virtualizationFrameworkLinked(),
                "bundle_present": fileExists(layout.bundleDir),
                "config_present": fileExists(layout.configPath),
                "manifest_present": fileExists(layout.manifestPath),
                "disk_present": fileExists(layout.diskPath),
                "auxiliary_storage_present": fileExists(layout.auxiliaryStoragePath),
                "hardware_model_present": fileExists(layout.hardwareModelPath),
                "machine_identifier_present": fileExists(layout.machineIdentifierPath),
                "runtime_state_present": fileExists(layout.runtimeStatePath),
                "health_proof_present": fileExists(layout.healthProofPath),
                "runtime_pid_present": fileExists(layout.runtimePidPath),
                "runtime_pid_alive": runtimeAlive,
                "ready_for_lifecycle": readyForLifecycle,
                "high_risk_package_execution_enabled": false,
                "reason_codes": reasonCodes,
                "exit_code": readyForLifecycle ? 0 : 20
            ]) { _, new in new },
            exitCode: readyForLifecycle ? 0 : 20
        )
    }

    private static func initialize(_ options: HelperOptions) {
        let layout = BundleLayout(stateDir: stateDirURL(from: options))
        if !options.execute {
            emit(
                fields: baseFields(status: "dry_run").merging([
                    "mutation": false,
                    "state_dir": layout.stateDir.path,
                    "bundle_dir": layout.bundleDir.path,
                    "required_inputs": ["--image <installed-macos-disk.img>", "--restore-image <macos-restore.ipsw>"],
                    "reason_codes": ["execute_required_for_mutation"],
                    "exit_code": 0
                ]) { _, new in new },
                exitCode: 0
            )
        }

        guard hostSupported() else {
            emit(
                fields: failClosedFields(layout: layout, reasons: ["host_not_apple_silicon_macos"], exitCode: 20),
                exitCode: 20
            )
        }
        guard virtualizationFrameworkLinked() else {
            emit(
                fields: failClosedFields(layout: layout, reasons: ["virtualization_framework_unavailable"], exitCode: 20),
                exitCode: 20
            )
        }

        if let restoreImagePath = options.restoreImagePath {
            emit(
                fields: failClosedFields(
                    layout: layout,
                    reasons: [
                        "restore_image_install_path_not_implemented",
                        "use_explicit_installed_disk_image_for_current_goal_slice"
                    ],
                    exitCode: 20
                ).merging([
                    "mutation": true,
                    "restore_image": restoreImagePath
                ]) { _, new in new },
                exitCode: 20
            )
        }

        guard let imagePath = options.imagePath else {
            emit(
                fields: failClosedFields(
                    layout: layout,
                    reasons: ["image_or_restore_image_required"],
                    exitCode: 64
                ).merging([
                    "required_inputs": ["--image <installed-macos-disk.img>", "--restore-image <macos-restore.ipsw>"]
                ]) { _, new in new },
                exitCode: 64
            )
        }

        let imageURL = URL(fileURLWithPath: imagePath)
        guard imageURL.path.hasPrefix("/") else {
            emit(
                fields: failClosedFields(layout: layout, reasons: ["image_path_not_absolute"], exitCode: 64)
                    .merging(["image": imagePath]) { _, new in new },
                exitCode: 64
            )
        }
        guard fileExists(imageURL) else {
            emit(
                fields: failClosedFields(layout: layout, reasons: ["image_path_not_found"], exitCode: 64)
                    .merging(["image": imagePath]) { _, new in new },
                exitCode: 64
            )
        }
        guard isRegularFile(imageURL) else {
            emit(
                fields: failClosedFields(layout: layout, reasons: ["image_path_not_regular_file"], exitCode: 64)
                    .merging(["image": imagePath]) { _, new in new },
                exitCode: 64
            )
        }
        guard imageURL.standardizedFileURL.path != layout.diskPath.standardizedFileURL.path else {
            emit(
                fields: failClosedFields(layout: layout, reasons: ["image_source_matches_managed_destination"], exitCode: 64),
                exitCode: 64
            )
        }

        do {
            try createManagedDirectories(layout)
            try replaceFile(source: imageURL, destination: layout.diskPath)
            let digest = try sha256Digest(path: layout.diskPath.path)
            try writeManifest(layout: layout, options: options, imageDigest: digest)
            try writeConfig(layout: layout, options: options, imageDigest: digest)
            emit(
                fields: baseFields(status: "ok").merging([
                    "mutation": true,
                    "state_dir": layout.stateDir.path,
                    "bundle_dir": layout.bundleDir.path,
                    "disk_path": layout.diskPath.path,
                    "image_digest": "sha256:\(digest)",
                    "ready_for_lifecycle": false,
                    "reason_codes": [
                        "auxiliary_storage_or_virtualization_metadata_required",
                        "virtualization_metadata_missing",
                        "signature_verification_not_implemented"
                    ],
                    "exit_code": 0
                ]) { _, new in new },
                exitCode: 0
            )
        } catch {
            emit(
                fields: failClosedFields(
                    layout: layout,
                    reasons: ["init_failed", sanitizedReason(error)],
                    exitCode: 70
                ),
                exitCode: 70
            )
        }
    }

    private static func start(_ options: HelperOptions) {
        lifecycleBlocked(options, operation: "start")
    }

    private static func suspend(_ options: HelperOptions) {
        lifecycleBlocked(options, operation: "suspend")
    }

    private static func runPersistentVm(_ options: HelperOptions) {
        let layout = BundleLayout(stateDir: stateDirURL(from: options))
        emit(
            fields: failClosedFields(
                layout: layout,
                reasons: ["persistent_vm_runtime_not_implemented"],
                exitCode: 20
            ).merging([
                "operation": "run",
                "mutation": false,
                "high_risk_package_execution_enabled": false
            ]) { _, new in new },
            exitCode: 20
        )
    }

    private static func lifecycleBlocked(_ options: HelperOptions, operation: String) {
        let layout = BundleLayout(stateDir: stateDirURL(from: options))
        if !options.execute {
            emit(
                fields: baseFields(status: "dry_run").merging([
                    "operation": operation,
                    "mutation": false,
                    "state_dir": layout.stateDir.path,
                    "reason_codes": ["execute_required_for_mutation"],
                    "exit_code": 0
                ]) { _, new in new },
                exitCode: 0
            )
        }
        let reasons = statusReasons(layout: layout)
        let finalReasons = reasons.isEmpty
            ? ["vm_start_runtime_not_implemented_for_persistent_cli_process"]
            : reasons
        emit(
            fields: failClosedFields(layout: layout, reasons: finalReasons, exitCode: 20)
                .merging([
                    "operation": operation,
                    "mutation": false,
                    "high_risk_package_execution_enabled": false
                ]) { _, new in new },
            exitCode: 20
        )
    }

    private static func reset(_ options: HelperOptions) {
        let layout = BundleLayout(stateDir: stateDirURL(from: options))
        if !options.execute {
            emit(
                fields: baseFields(status: "dry_run").merging([
                    "operation": "reset",
                    "mutation": false,
                    "state_dir": layout.stateDir.path,
                    "reason_codes": ["execute_required_for_mutation"],
                    "exit_code": 0
                ]) { _, new in new },
                exitCode: 0
            )
        }
        do {
            try removeIfPresent(layout.runtimeStatePath)
            try removeIfPresent(layout.healthProofPath)
            emit(
                fields: baseFields(status: "ok").merging([
                    "operation": "reset",
                    "mutation": true,
                    "state_dir": layout.stateDir.path,
                    "removed_runtime_state": true,
                    "high_risk_package_execution_enabled": false,
                    "exit_code": 0
                ]) { _, new in new },
                exitCode: 0
            )
        } catch {
            emit(fields: failClosedFields(layout: layout, reasons: ["reset_failed", sanitizedReason(error)], exitCode: 70), exitCode: 70)
        }
    }

    private static func prune(_ options: HelperOptions) {
        let layout = BundleLayout(stateDir: stateDirURL(from: options))
        if !options.execute {
            emit(
                fields: baseFields(status: "dry_run").merging([
                    "operation": "prune",
                    "mutation": false,
                    "state_dir": layout.stateDir.path,
                    "reason_codes": ["execute_required_for_mutation"],
                    "exit_code": 0
                ]) { _, new in new },
                exitCode: 0
            )
        }
        do {
            try removeIfPresent(layout.bundleDir)
            emit(
                fields: baseFields(status: "ok").merging([
                    "operation": "prune",
                    "mutation": true,
                    "state_dir": layout.stateDir.path,
                    "removed_bundle": true,
                    "exit_code": 0
                ]) { _, new in new },
                exitCode: 0
            )
        } catch {
            emit(fields: failClosedFields(layout: layout, reasons: ["prune_failed", sanitizedReason(error)], exitCode: 70), exitCode: 70)
        }
    }

    private static func health(_ options: HelperOptions) {
        let layout = BundleLayout(stateDir: stateDirURL(from: options))
        emit(
            fields: failClosedFields(
                layout: layout,
                reasons: ["guest_health_proof_not_implemented"],
                exitCode: 20
            ).merging([
                "health_proven": false,
                "high_risk_package_execution_enabled": false
            ]) { _, new in new },
            exitCode: 20
        )
    }

    private static func statusReasons(layout: BundleLayout) -> [String] {
        var reasons: [String] = []
        if !hostSupported() {
            reasons.append("host_not_apple_silicon_macos")
        }
        if !virtualizationFrameworkLinked() {
            reasons.append("virtualization_framework_unavailable")
        }
        if !fileExists(layout.bundleDir) {
            reasons.append("bundle_missing")
        }
        if !fileExists(layout.configPath) {
            reasons.append("config_missing")
        }
        if !fileExists(layout.manifestPath) {
            reasons.append("manifest_missing")
        }
        if !fileExists(layout.diskPath) {
            reasons.append("disk_missing")
        }
        if !fileExists(layout.auxiliaryStoragePath) {
            reasons.append("auxiliary_storage_missing")
        }
        if !fileExists(layout.hardwareModelPath) {
            reasons.append("hardware_model_missing")
        }
        if !fileExists(layout.machineIdentifierPath) {
            reasons.append("machine_identifier_missing")
        }
        reasons.append("signature_verification_not_implemented")
        return reasonArray(reasons)
    }

    private static func baseFields(status: String) -> [String: Any] {
        [
            "schema_version": bundleSchemaVersion,
            "helper_version": helperVersion,
            "status": status
        ]
    }

    private static func failClosedFields(layout: BundleLayout, reasons: [String], exitCode: Int) -> [String: Any] {
        baseFields(status: "fail_closed").merging([
            "state_dir": layout.stateDir.path,
            "bundle_dir": layout.bundleDir.path,
            "ready_for_lifecycle": false,
            "reason_codes": reasonArray(reasons),
            "exit_code": exitCode
        ]) { _, new in new }
    }

    private static func createManagedDirectories(_ layout: BundleLayout) throws {
        for directory in layout.managedDirectories() {
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        }
    }

    private static func replaceFile(source: URL, destination: URL) throws {
        try removeIfPresent(destination)
        try FileManager.default.copyItem(at: source, to: destination)
    }

    private static func writeManifest(layout: BundleLayout, options: HelperOptions, imageDigest: String) throws {
        let body = [
            "schema_version=whoathere.macos_vm_image.v1",
            "image_id=local-imported-disk",
            "macos_version=unknown",
            "architecture=arm64",
            "image_digest=sha256:\(imageDigest)",
            "signature_status=signature_verification_not_implemented",
            "helper_version=\(helperVersion)"
        ].joined(separator: "\n") + "\n"
        try body.write(to: layout.manifestPath, atomically: true, encoding: .utf8)
    }

    private static func writeConfig(layout: BundleLayout, options: HelperOptions, imageDigest: String) throws {
        let config: [String: Any] = [
            "schema_version": bundleSchemaVersion,
            "helper_version": helperVersion,
            "memory_mib": options.memoryMiB,
            "disk_gib": options.diskGiB,
            "disk_path": layout.diskPath.path,
            "image_digest": "sha256:\(imageDigest)",
            "high_risk_package_execution_enabled": false
        ]
        let data = try JSONSerialization.data(withJSONObject: config, options: [.prettyPrinted, .sortedKeys])
        try data.write(to: layout.configPath, options: [.atomic])
    }

    private static func manifestSignatureStatus(layout: BundleLayout) -> String? {
        guard let contents = try? String(contentsOf: layout.manifestPath, encoding: .utf8) else {
            return nil
        }
        for line in contents.split(separator: "\n") {
            if line.starts(with: "signature_status=") {
                return String(line.dropFirst("signature_status=".count))
            }
        }
        return nil
    }

    private static func virtualizationFrameworkLinked() -> Bool {
        if #available(macOS 13.0, *) {
            _ = VZVirtualMachineConfiguration.self
            _ = VZMacOSBootLoader.self
            return true
        }
        return false
    }

    private static func hostSupported() -> Bool {
        #if os(macOS) && arch(arm64)
        return true
        #else
        return false
        #endif
    }

    private static func fileExists(_ url: URL) -> Bool {
        FileManager.default.fileExists(atPath: url.path)
    }

    private static func isRegularFile(_ url: URL) -> Bool {
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory), !isDirectory.boolValue else {
            return false
        }
        guard let values = try? url.resourceValues(forKeys: [.isRegularFileKey]) else {
            return false
        }
        return values.isRegularFile == true
    }

    private static func readRuntimePID(_ layout: BundleLayout) -> pid_t? {
        guard let contents = try? String(contentsOf: layout.runtimePidPath, encoding: .utf8) else {
            return nil
        }
        guard let pid = Int32(contents.trimmingCharacters(in: .whitespacesAndNewlines)) else {
            return nil
        }
        return pid
    }

    private static func processIsAlive(_ pid: pid_t) -> Bool {
        pid > 0 && kill(pid, 0) == 0
    }

    private static func removeIfPresent(_ url: URL) throws {
        if fileExists(url) {
            try FileManager.default.removeItem(at: url)
        }
    }

    private static func sha256Digest(path: String) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/shasum")
        process.arguments = ["-a", "256", path]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw NSError(domain: "whoathere.helper", code: Int(process.terminationStatus), userInfo: [
                NSLocalizedDescriptionKey: "shasum_failed"
            ])
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(decoding: data, as: UTF8.self)
        guard let digest = output.split(whereSeparator: { $0 == " " || $0 == "\t" || $0 == "\n" }).first else {
            throw NSError(domain: "whoathere.helper", code: 1, userInfo: [
                NSLocalizedDescriptionKey: "shasum_output_invalid"
            ])
        }
        return String(digest)
    }

    private static func sanitizedReason(_ error: Error) -> String {
        String(describing: error)
            .replacingOccurrences(of: "\n", with: "_")
            .replacingOccurrences(of: "\r", with: "_")
            .replacingOccurrences(of: " ", with: "_")
    }

    private static func emit(fields: [String: Any], exitCode: Int32) -> Never {
        let data = (try? JSONSerialization.data(withJSONObject: fields, options: [.prettyPrinted, .sortedKeys]))
            ?? Data("{\"status\":\"error\",\"reason_codes\":[\"json_encoding_failed\"],\"exit_code\":70}".utf8)
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data("\n".utf8))
        exit(exitCode)
    }
}
