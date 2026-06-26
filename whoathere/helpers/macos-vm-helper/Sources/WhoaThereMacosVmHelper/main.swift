import Darwin
import CryptoKit
import Foundation
import Security
@preconcurrency import Virtualization
import WhoaThereMacosVmHelperCore

private let guestReadinessPort: UInt32 = 47078
private let guestReadinessProtocol = "whoathere.guest_ready.v1"

private final class LockedResultBox<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var result: Result<Value, Error>?

    func store(_ result: Result<Value, Error>) {
        lock.lock()
        self.result = result
        lock.unlock()
    }

    func load() -> Result<Value, Error>? {
        lock.lock()
        let current = result
        lock.unlock()
        return current
    }
}

private final class RuntimeStopState: @unchecked Sendable {
    private let lock = NSLock()
    private var stopRequested = false

    func claimStop() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if stopRequested {
            return false
        }
        stopRequested = true
        return true
    }
}

private struct UncheckedSendableBox<Value>: @unchecked Sendable {
    var value: Value
}

private struct ManifestValidationResult {
    var fields: [String: String]
    var reasonCodes: [String]

    var signatureStatus: String {
        fields["signature_status"] ?? "missing"
    }
}

private final class RuntimeReferences {
    let virtualMachine: VZVirtualMachine
    let socketListener: VZVirtioSocketListener
    let delegate: GuestReadinessListener
    let signalSource: DispatchSourceSignal

    init(
        virtualMachine: VZVirtualMachine,
        socketListener: VZVirtioSocketListener,
        delegate: GuestReadinessListener,
        signalSource: DispatchSourceSignal
    ) {
        self.virtualMachine = virtualMachine
        self.socketListener = socketListener
        self.delegate = delegate
        self.signalSource = signalSource
    }
}

private final class GuestReadinessListener: NSObject, VZVirtioSocketListenerDelegate {
    private let layout: BundleLayout
    private let sessionID: String
    private let challenge: String

    init(layout: BundleLayout, sessionID: String, challenge: String) {
        self.layout = layout
        self.sessionID = sessionID
        self.challenge = challenge
    }

    func listener(
        _ listener: VZVirtioSocketListener,
        shouldAcceptNewConnection connection: VZVirtioSocketConnection,
        from socketDevice: VZVirtioSocketDevice
    ) -> Bool {
        let listenerBox = UncheckedSendableBox(value: self)
        let connectionBox = UncheckedSendableBox(value: connection)
        DispatchQueue.global(qos: .utility).async {
            listenerBox.value.handle(connectionBox.value)
        }
        return true
    }

    private func handle(_ connection: VZVirtioSocketConnection) {
        defer {
            connection.close()
        }
        let challengeBody: [String: Any] = [
            "protocol": guestReadinessProtocol,
            "challenge": challenge,
            "helper_version": helperVersion,
            "port": Int(guestReadinessPort)
        ]
        guard writeJSONLine(challengeBody, to: connection.fileDescriptor) else {
            return
        }
        guard let responseData = readFileDescriptor(connection.fileDescriptor, timeoutSeconds: 10, maxBytes: 4096),
              let response = try? JSONSerialization.jsonObject(with: responseData) as? [String: Any],
              response["protocol"] as? String == guestReadinessProtocol,
              response["challenge"] as? String == challenge,
              response["status"] as? String == "ready" else {
            return
        }
        let proof: [String: Any] = [
            "schema_version": bundleSchemaVersion,
            "helper_version": helperVersion,
            "runtime_pid": Int(getpid()),
            "vm_session_id": sessionID,
            "image_digest": imageDigestForProof(layout),
            "health_proof_type": "guest_vsock_readiness",
            "host_vm_started": true,
            "guest_health_proven": true,
            "guest_agent_version": response["agent_version"] as? String ?? "unknown",
            "guest_readiness_protocol": guestReadinessProtocol,
            "guest_readiness_port": Int(guestReadinessPort),
            "guest_readiness_challenge_sha256": sha256Hex(challenge),
            "source_port": Int(connection.sourcePort),
            "destination_port": Int(connection.destinationPort),
            "created_at": ISO8601DateFormatter().string(from: Date()),
            "high_risk_package_execution_enabled": false
        ]
        try? JSONSerialization.data(withJSONObject: proof, options: [.prettyPrinted, .sortedKeys])
            .write(to: layout.guestHealthProofPath, options: [.atomic])
    }
}

private func randomHex(byteCount: Int) throws -> String {
    var bytes = [UInt8](repeating: 0, count: byteCount)
    let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
    guard status == errSecSuccess else {
        throw NSError(domain: "whoathere.helper", code: Int(status), userInfo: [
            NSLocalizedDescriptionKey: "secure_random_failed"
        ])
    }
    return bytes.map { String(format: "%02x", $0) }.joined()
}

private func writeJSONLine(_ fields: [String: Any], to fd: Int32) -> Bool {
    guard JSONSerialization.isValidJSONObject(fields),
          var data = try? JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys]) else {
        return false
    }
    data.append(Data("\n".utf8))
    return data.withUnsafeBytes { buffer in
        guard let baseAddress = buffer.baseAddress else {
            return false
        }
        var written = 0
        while written < data.count {
            let result = Darwin.write(fd, baseAddress.advanced(by: written), data.count - written)
            if result < 0 {
                if errno == EINTR {
                    continue
                }
                return false
            }
            if result == 0 {
                return false
            }
            written += result
        }
        return true
    }
}

private func readFileDescriptor(_ fd: Int32, timeoutSeconds: Int32, maxBytes: Int) -> Data? {
    let deadline = Date().addingTimeInterval(TimeInterval(timeoutSeconds))
    var output = Data()
    while Date() < deadline && output.count < maxBytes {
        let remainingMilliseconds = max(1, min(250, Int(deadline.timeIntervalSinceNow * 1000)))
        var pollDescriptor = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        let pollResult = Darwin.poll(&pollDescriptor, 1, Int32(remainingMilliseconds))
        if pollResult < 0 {
            if errno == EINTR {
                continue
            }
            return nil
        }
        if pollResult == 0 {
            continue
        }
        if pollDescriptor.revents & Int16(POLLIN) == 0 {
            return nil
        }
        var buffer = [UInt8](repeating: 0, count: min(1024, maxBytes - output.count))
        let count = Darwin.read(fd, &buffer, buffer.count)
        if count < 0 {
            if errno == EINTR {
                continue
            }
            return nil
        }
        if count == 0 {
            break
        }
        output.append(contentsOf: buffer.prefix(count))
        if output.last == UInt8(ascii: "\n") {
            break
        }
    }
    guard !output.isEmpty, output.count <= maxBytes else {
        return nil
    }
    if output.last == UInt8(ascii: "\n") {
        output.removeLast()
    }
    return output
}

private func imageDigestForProof(_ layout: BundleLayout) -> String {
    guard let config = readJSONObject(layout.configPath) else {
        return "unknown"
    }
    if let digest = config["image_digest"] as? String {
        return digest
    }
    if let digest = config["restore_image_digest"] as? String {
        return digest
    }
    return "unknown"
}

private func sha256Hex(_ string: String) -> String {
    SHA256.hash(data: Data(string.utf8)).map { String(format: "%02x", $0) }.joined()
}

private func readJSONObject(_ url: URL) -> [String: Any]? {
    guard let data = try? Data(contentsOf: url),
          let object = try? JSONSerialization.jsonObject(with: data),
          let fields = object as? [String: Any] else {
        return nil
    }
    return fields
}

private func intField(_ fields: [String: Any], _ key: String) -> Int? {
    if let value = fields[key] as? Int {
        return value
    }
    if let value = fields[key] as? NSNumber {
        return value.intValue
    }
    return nil
}

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
        let runtimeAlive = runtimePID.map(runtimeProcessIsAlive) ?? false
        let manifestValidation = validateManifest(layout: layout, includeSignatureReason: true)
        emit(
            fields: baseFields(status: readyForLifecycle ? "ok" : "fail_closed").merging([
                "state_dir": layout.stateDir.path,
                "bundle_dir": layout.bundleDir.path,
                "host_supported": hostSupported(),
                "virtualization_framework_linked": virtualizationFrameworkLinked(),
                "bundle_present": fileExists(layout.bundleDir),
                "config_present": fileExists(layout.configPath),
                "manifest_present": fileExists(layout.manifestPath),
                "manifest_signature_status": manifestValidation.signatureStatus,
                "manifest_validation_reason_codes": manifestValidation.reasonCodes,
                "disk_present": fileExists(layout.diskPath),
                "auxiliary_storage_present": fileExists(layout.auxiliaryStoragePath),
                "hardware_model_present": fileExists(layout.hardwareModelPath),
                "machine_identifier_present": fileExists(layout.machineIdentifierPath),
                "runtime_state_present": fileExists(layout.runtimeStatePath),
                "health_proof_present": fileExists(layout.healthProofPath),
                "guest_health_proof_present": fileExists(layout.guestHealthProofPath),
                "guest_provisioning_receipt_present": fileExists(layout.guestProvisioningReceiptPath),
                "guest_tools_image_present": fileExists(layout.guestToolsImagePath),
                "runtime_shutdown_present": fileExists(layout.runtimeShutdownPath),
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
                    "required_inputs": [
                        "--image <installed-macos-disk.img>",
                        "--restore-image <macos-restore.ipsw>",
                        "--fetch-latest-restore-image"
                    ],
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

        let sourceCount = [
            options.imagePath != nil,
            options.restoreImagePath != nil,
            options.fetchLatestRestoreImage
        ].filter { $0 }.count
        guard sourceCount <= 1 else {
            emit(
                fields: failClosedFields(layout: layout, reasons: ["multiple_image_sources_configured"], exitCode: 64)
                    .merging([
                        "required_inputs": [
                            "--image <installed-macos-disk.img>",
                            "--restore-image <macos-restore.ipsw>",
                            "--fetch-latest-restore-image"
                        ]
                    ]) { _, new in new },
                exitCode: 64
            )
        }

        if let restoreImagePath = options.restoreImagePath {
            initializeFromRestoreImage(path: restoreImagePath, layout: layout, options: options)
        }
        if options.fetchLatestRestoreImage {
            initializeFromLatestSupportedRestoreImage(layout: layout, options: options)
        }

        guard let imagePath = options.imagePath else {
            emit(
                fields: failClosedFields(
                    layout: layout,
                    reasons: ["image_or_restore_image_required"],
                    exitCode: 64
                ).merging([
                    "required_inputs": [
                        "--image <installed-macos-disk.img>",
                        "--restore-image <macos-restore.ipsw>",
                        "--fetch-latest-restore-image"
                    ]
                ]) { _, new in new },
                exitCode: 64
            )
        }

        guard imagePath.hasPrefix("/") else {
            emit(
                fields: failClosedFields(layout: layout, reasons: ["image_path_not_absolute"], exitCode: 64)
                    .merging(["image": imagePath]) { _, new in new },
                exitCode: 64
            )
        }
        let imageURL = URL(fileURLWithPath: imagePath)
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

    private static func initializeFromRestoreImage(path: String, layout: BundleLayout, options: HelperOptions) -> Never {
        guard path.hasPrefix("/") else {
            emit(
                fields: failClosedFields(layout: layout, reasons: ["restore_image_path_not_absolute"], exitCode: 64)
                    .merging(["restore_image": path]) { _, new in new },
                exitCode: 64
            )
        }
        let restoreURL = URL(fileURLWithPath: path)
        guard fileExists(restoreURL) else {
            emit(
                fields: failClosedFields(layout: layout, reasons: ["restore_image_path_not_found"], exitCode: 64)
                    .merging(["restore_image": path]) { _, new in new },
                exitCode: 64
            )
        }
        guard isRegularFile(restoreURL) else {
            emit(
                fields: failClosedFields(layout: layout, reasons: ["restore_image_path_not_regular_file"], exitCode: 64)
                    .merging(["restore_image": path]) { _, new in new },
                exitCode: 64
            )
        }
        guard !bundleHasInstalledState(layout) else {
            emit(
                fields: failClosedFields(layout: layout, reasons: ["bundle_already_initialized"], exitCode: 20),
                exitCode: 20
            )
        }

        do {
            let restoreDigest = try sha256Digest(path: restoreURL.path)
            let restoreImage = try loadRestoreImage(restoreURL)
            guard restoreImage.isSupported else {
                emit(
                    fields: failClosedFields(layout: layout, reasons: ["restore_image_not_supported_on_host"], exitCode: 20),
                    exitCode: 20
                )
            }
            guard let requirements = restoreImage.mostFeaturefulSupportedConfiguration else {
                emit(
                    fields: failClosedFields(layout: layout, reasons: ["restore_image_no_supported_configuration"], exitCode: 20),
                    exitCode: 20
                )
            }

            try createManagedDirectories(layout)
            let installSummary = try installMacOSFromRestoreImage(
                restoreImage: restoreImage,
                requirements: requirements,
                restoreURL: restoreURL,
                restoreDigest: restoreDigest,
                layout: layout,
                options: options
            )
            emit(
                fields: baseFields(status: "ok").merging([
                    "mutation": true,
                    "state_dir": layout.stateDir.path,
                    "bundle_dir": layout.bundleDir.path,
                    "disk_path": layout.diskPath.path,
                    "restore_image": path,
                    "restore_image_digest": "sha256:\(restoreDigest)",
                    "macos_build_version": restoreImage.buildVersion,
                    "macos_version": operatingSystemVersionString(restoreImage.operatingSystemVersion),
                    "cpu_count": installSummary.cpuCount,
                    "memory_mib": installSummary.memoryMiB,
                    "disk_gib": options.diskGiB,
                    "ready_for_lifecycle": false,
                    "reason_codes": [
                        "signature_verification_not_implemented",
                        "guest_readiness_agent_not_provisioned"
                    ],
                    "exit_code": 0
                ]) { _, new in new },
                exitCode: 0
            )
        } catch {
            emit(
                fields: failClosedFields(
                    layout: layout,
                    reasons: ["restore_image_install_failed", sanitizedReason(error)],
                    exitCode: 70
                ).merging([
                    "restore_image": path
                ]) { _, new in new },
                exitCode: 70
            )
        }
    }

    private static func initializeFromLatestSupportedRestoreImage(layout: BundleLayout, options: HelperOptions) -> Never {
        guard !bundleHasInstalledState(layout) else {
            emit(
                fields: failClosedFields(layout: layout, reasons: ["bundle_already_initialized"], exitCode: 20),
                exitCode: 20
            )
        }

        do {
            try createManagedDirectories(layout)
            let fetchedRestoreImage = try fetchLatestSupportedRestoreImage()
            guard fetchedRestoreImage.url.scheme == "https" else {
                emit(
                    fields: failClosedFields(layout: layout, reasons: ["latest_restore_image_url_not_https"], exitCode: 20),
                    exitCode: 20
                )
            }
            let cachedURL = layout.cacheDir.appendingPathComponent("latest-supported-restore.ipsw")
            try downloadRestoreImage(from: fetchedRestoreImage.url, to: cachedURL)
            let restoreDigest = try sha256Digest(path: cachedURL.path)
            let restoreImage = try loadRestoreImage(cachedURL)
            guard restoreImage.isSupported else {
                emit(
                    fields: failClosedFields(layout: layout, reasons: ["restore_image_not_supported_on_host"], exitCode: 20),
                    exitCode: 20
                )
            }
            guard let requirements = restoreImage.mostFeaturefulSupportedConfiguration else {
                emit(
                    fields: failClosedFields(layout: layout, reasons: ["restore_image_no_supported_configuration"], exitCode: 20),
                    exitCode: 20
                )
            }

            let installSummary = try installMacOSFromRestoreImage(
                restoreImage: restoreImage,
                requirements: requirements,
                restoreURL: cachedURL,
                restoreDigest: restoreDigest,
                layout: layout,
                options: options
            )
            emit(
                fields: baseFields(status: "ok").merging([
                    "mutation": true,
                    "state_dir": layout.stateDir.path,
                    "bundle_dir": layout.bundleDir.path,
                    "disk_path": layout.diskPath.path,
                    "restore_image_source": "latest_supported_network",
                    "restore_image_cache_path": cachedURL.path,
                    "restore_image_url": fetchedRestoreImage.url.absoluteString,
                    "restore_image_digest": "sha256:\(restoreDigest)",
                    "macos_build_version": restoreImage.buildVersion,
                    "macos_version": operatingSystemVersionString(restoreImage.operatingSystemVersion),
                    "cpu_count": installSummary.cpuCount,
                    "memory_mib": installSummary.memoryMiB,
                    "disk_gib": options.diskGiB,
                    "ready_for_lifecycle": false,
                    "reason_codes": [
                        "signature_verification_not_implemented",
                        "guest_readiness_agent_not_provisioned"
                    ],
                    "exit_code": 0
                ]) { _, new in new },
                exitCode: 0
            )
        } catch {
            emit(
                fields: failClosedFields(
                    layout: layout,
                    reasons: ["latest_restore_image_install_failed", sanitizedReason(error)],
                    exitCode: 70
                ),
                exitCode: 70
            )
        }
    }

    private static func start(_ options: HelperOptions) {
        let layout = BundleLayout(stateDir: stateDirURL(from: options))
        if !options.execute {
            emit(
                fields: baseFields(status: "dry_run").merging([
                    "operation": "start",
                    "mutation": false,
                    "state_dir": layout.stateDir.path,
                    "reason_codes": ["execute_required_for_mutation"],
                    "exit_code": 0
                ]) { _, new in new },
                exitCode: 0
            )
        }
        if let pid = readRuntimePID(layout), runtimeProcessIsAlive(pid) {
            emit(
                fields: baseFields(status: "ok").merging([
                    "operation": "start",
                    "mutation": false,
                    "state_dir": layout.stateDir.path,
                    "runtime_pid": Int(pid),
                    "runtime_pid_alive": true,
                    "high_risk_package_execution_enabled": false,
                    "exit_code": 0
                ]) { _, new in new },
                exitCode: 0
            )
        }
        let reasons = runtimeStartReasons(layout: layout)
        if !reasons.isEmpty {
            emit(
                fields: failClosedFields(layout: layout, reasons: reasons, exitCode: 20)
                    .merging([
                        "operation": "start",
                        "mutation": false,
                        "high_risk_package_execution_enabled": false
                    ]) { _, new in new },
                exitCode: 20
            )
        }
        do {
            try createManagedDirectories(layout)
            try removeIfPresent(layout.runtimeStatePath)
            try removeIfPresent(layout.healthProofPath)
            try removeIfPresent(layout.guestHealthProofPath)
            try removeIfPresent(layout.runtimeShutdownPath)
            try removeIfPresent(layout.runtimePidPath)
            let process = try spawnRuntimeProcess(layout: layout)
            try "\(process.processIdentifier)\n".write(to: layout.runtimePidPath, atomically: true, encoding: .utf8)
            let status = waitForRuntimeStart(layout: layout, pid: process.processIdentifier, process: process)
            emit(
                fields: baseFields(status: status.status).merging([
                    "operation": "start",
                    "mutation": true,
                    "state_dir": layout.stateDir.path,
                    "runtime_pid": Int(process.processIdentifier),
                    "runtime_pid_alive": runtimeProcessIsAlive(process.processIdentifier),
                    "health_proof_present": fileExists(layout.healthProofPath),
                    "guest_health_proof_present": fileExists(layout.guestHealthProofPath),
                    "guest_health_proven": false,
                    "high_risk_package_execution_enabled": false,
                    "reason_codes": status.reasonCodes,
                    "exit_code": status.exitCode
                ]) { _, new in new },
                exitCode: status.exitCode
            )
        } catch {
            emit(
                fields: failClosedFields(layout: layout, reasons: ["runtime_start_failed", sanitizedReason(error)], exitCode: 70),
                exitCode: 70
            )
        }
    }

    private static func suspend(_ options: HelperOptions) {
        let layout = BundleLayout(stateDir: stateDirURL(from: options))
        if !options.execute {
            emit(
                fields: baseFields(status: "dry_run").merging([
                    "operation": "suspend",
                    "mutation": false,
                    "state_dir": layout.stateDir.path,
                    "reason_codes": ["execute_required_for_mutation"],
                    "exit_code": 0
                ]) { _, new in new },
                exitCode: 0
            )
        }
        guard let pid = readRuntimePID(layout), runtimeProcessIsAlive(pid) else {
            emit(
                fields: failClosedFields(layout: layout, reasons: ["runtime_process_not_running"], exitCode: 20)
                    .merging([
                        "operation": "suspend",
                        "mutation": false
                    ]) { _, new in new },
                exitCode: 20
            )
        }
        do {
            try removeIfPresent(layout.runtimeShutdownPath)
            _ = kill(pid, SIGTERM)
            let stopped = waitForRuntimeProcessExit(pid, timeoutSeconds: 30)
            if !stopped {
                _ = kill(pid, SIGKILL)
                _ = waitForRuntimeProcessExit(pid, timeoutSeconds: 5)
                try removeRuntimeProofFiles(layout)
                emit(
                    fields: failClosedFields(
                        layout: layout,
                        reasons: ["runtime_stop_timeout_forced_kill"],
                        exitCode: 70
                    ).merging([
                        "operation": "suspend",
                        "mutation": true,
                        "runtime_pid": Int(pid),
                        "suspend_semantics": "signal_runtime_guest_stop_request",
                        "runtime_stop_observed": false,
                        "high_risk_package_execution_enabled": false
                    ]) { _, new in new },
                    exitCode: 70
                )
            }
            let shutdown = readJSONObject(layout.runtimeShutdownPath)
            let shutdownStatus = shutdown?["status"] as? String
            guard shutdownStatus == "ok" else {
                try removeRuntimeProofFiles(layout)
                emit(
                    fields: failClosedFields(
                        layout: layout,
                        reasons: ["runtime_shutdown_proof_missing_or_failed"],
                        exitCode: 70
                    ).merging([
                        "operation": "suspend",
                        "mutation": true,
                        "runtime_pid": Int(pid),
                        "suspend_semantics": "signal_runtime_guest_stop_request",
                        "runtime_stop_observed": true,
                        "runtime_shutdown_present": shutdown != nil,
                        "runtime_shutdown_status": shutdownStatus ?? "missing",
                        "high_risk_package_execution_enabled": false
                    ]) { _, new in new },
                    exitCode: 70
                )
            }
            try removeRuntimeProofFiles(layout)
            emit(
                fields: baseFields(status: "ok").merging([
                    "operation": "suspend",
                    "mutation": true,
                    "state_dir": layout.stateDir.path,
                    "runtime_pid": Int(pid),
                    "suspend_semantics": shutdown?["stop_method"] as? String ?? "signal_runtime_guest_stop_request",
                    "runtime_stop_observed": true,
                    "runtime_shutdown_present": true,
                    "high_risk_package_execution_enabled": false,
                    "exit_code": 0
                ]) { _, new in new },
                exitCode: 0
            )
        } catch {
            emit(
                fields: failClosedFields(layout: layout, reasons: ["suspend_cleanup_failed", sanitizedReason(error)], exitCode: 70),
                exitCode: 70
            )
        }
    }

    private static func runPersistentVm(_ options: HelperOptions) {
        let layout = BundleLayout(stateDir: stateDirURL(from: options))
        let reasons = runtimeStartReasons(layout: layout)
        if !reasons.isEmpty {
            emit(
                fields: failClosedFields(layout: layout, reasons: reasons, exitCode: 20)
                    .merging([
                        "operation": "run",
                        "mutation": false,
                        "high_risk_package_execution_enabled": false
                    ]) { _, new in new },
                exitCode: 20
            )
        }
        do {
            let configuration = try loadInstalledMacOSConfiguration(layout: layout)
            try startAndHoldVirtualMachine(configuration: configuration, layout: layout)
        } catch {
            emit(
                fields: failClosedFields(layout: layout, reasons: ["runtime_vm_start_failed", sanitizedReason(error)], exitCode: 70),
                exitCode: 70
            )
        }
    }

    private struct RestoreInstallSummary {
        var cpuCount: Int
        var memoryMiB: UInt64
    }

    private static func installMacOSFromRestoreImage(
        restoreImage: VZMacOSRestoreImage,
        requirements: VZMacOSConfigurationRequirements,
        restoreURL: URL,
        restoreDigest: String,
        layout: BundleLayout,
        options: HelperOptions
    ) throws -> RestoreInstallSummary {
        let hardwareModel = requirements.hardwareModel
        guard hardwareModel.isSupported else {
            throw helperError("hardware_model_not_supported")
        }
        guard options.diskGiB >= minimumRestoreDiskGiB else {
            throw helperError("restore_disk_below_minimum_\(minimumRestoreDiskGiB)_gib")
        }

        let machineIdentifier = VZMacMachineIdentifier()
        try createRawDiskImage(at: layout.diskPath, diskGiB: options.diskGiB)
        let auxiliaryStorage = try VZMacAuxiliaryStorage(
            creatingStorageAt: layout.auxiliaryStoragePath,
            hardwareModel: hardwareModel,
            options: []
        )
        try hardwareModel.dataRepresentation.write(to: layout.hardwareModelPath, options: [.atomic])
        try machineIdentifier.dataRepresentation.write(to: layout.machineIdentifierPath, options: [.atomic])

        let memoryBytes = try requestedMemoryBytes(options: options, requirements: requirements)
        let cpuCount = try requestedCPUCount(requirements: requirements)
        let configuration = try buildMacOSConfiguration(
            layout: layout,
            hardwareModel: hardwareModel,
            machineIdentifier: machineIdentifier,
            auxiliaryStorage: auxiliaryStorage,
            cpuCount: cpuCount,
            memoryBytes: memoryBytes
        )
        try runMacOSInstaller(configuration: configuration, restoreURL: restoreURL)
        try writeRestoreManifest(
            layout: layout,
            restoreImage: restoreImage,
            restoreDigest: restoreDigest,
            cpuCount: cpuCount,
            memoryBytes: memoryBytes
        )
        try writeRestoreConfig(
            layout: layout,
            options: options,
            restoreDigest: restoreDigest,
            cpuCount: cpuCount,
            memoryBytes: memoryBytes
        )

        return RestoreInstallSummary(cpuCount: cpuCount, memoryMiB: memoryBytes / 1_048_576)
    }

    private static func loadRestoreImage(_ url: URL) throws -> VZMacOSRestoreImage {
        let semaphore = DispatchSemaphore(value: 0)
        let resultBox = LockedResultBox<VZMacOSRestoreImage>()
        VZMacOSRestoreImage.load(from: url) { result in
            resultBox.store(result.mapError { $0 })
            semaphore.signal()
        }
        semaphore.wait()
        guard let result = resultBox.load() else {
            throw helperError("restore_image_load_returned_no_result")
        }
        return try result.get()
    }

    private static func fetchLatestSupportedRestoreImage() throws -> VZMacOSRestoreImage {
        let semaphore = DispatchSemaphore(value: 0)
        let resultBox = LockedResultBox<VZMacOSRestoreImage>()
        VZMacOSRestoreImage.fetchLatestSupported { result in
            resultBox.store(result.mapError { $0 })
            semaphore.signal()
        }
        semaphore.wait()
        guard let result = resultBox.load() else {
            throw helperError("latest_restore_image_fetch_returned_no_result")
        }
        return try result.get()
    }

    private static func downloadRestoreImage(from sourceURL: URL, to destinationURL: URL) throws {
        let semaphore = DispatchSemaphore(value: 0)
        let resultBox = LockedResultBox<Void>()
        let destinationBox = UncheckedSendableBox(value: destinationURL)
        let task = URLSession.shared.downloadTask(with: sourceURL) { temporaryURL, response, error in
            if let error {
                resultBox.store(.failure(error))
                semaphore.signal()
                return
            }
            if let httpResponse = response as? HTTPURLResponse,
               !(200..<300).contains(httpResponse.statusCode) {
                resultBox.store(.failure(helperError("latest_restore_image_download_http_\(httpResponse.statusCode)")))
                semaphore.signal()
                return
            }
            guard let temporaryURL else {
                resultBox.store(.failure(helperError("latest_restore_image_download_missing_file")))
                semaphore.signal()
                return
            }
            do {
                let destination = destinationBox.value
                try FileManager.default.createDirectory(
                    at: destination.deletingLastPathComponent(),
                    withIntermediateDirectories: true,
                    attributes: [.posixPermissions: 0o700]
                )
                try removeIfPresent(destination)
                try FileManager.default.moveItem(at: temporaryURL, to: destination)
                let attributes = try FileManager.default.attributesOfItem(atPath: destination.path)
                let size = (attributes[.size] as? NSNumber)?.uint64Value ?? 0
                guard size > 0 else {
                    throw helperError("latest_restore_image_download_empty")
                }
                resultBox.store(.success(()))
            } catch {
                resultBox.store(.failure(error))
            }
            semaphore.signal()
        }
        task.resume()
        semaphore.wait()
        guard let result = resultBox.load() else {
            throw helperError("latest_restore_image_download_returned_no_result")
        }
        try result.get()
    }

    private static func buildMacOSConfiguration(
        layout: BundleLayout,
        hardwareModel: VZMacHardwareModel,
        machineIdentifier: VZMacMachineIdentifier,
        auxiliaryStorage: VZMacAuxiliaryStorage,
        cpuCount: Int,
        memoryBytes: UInt64,
        attachGuestTools: Bool = false
    ) throws -> VZVirtualMachineConfiguration {
        let platform = VZMacPlatformConfiguration()
        platform.hardwareModel = hardwareModel
        platform.machineIdentifier = machineIdentifier
        platform.auxiliaryStorage = auxiliaryStorage

        let diskAttachment = try VZDiskImageStorageDeviceAttachment(url: layout.diskPath, readOnly: false)
        let storage = VZVirtioBlockDeviceConfiguration(attachment: diskAttachment)
        var storageDevices: [VZStorageDeviceConfiguration] = [storage]
        if attachGuestTools && fileExists(layout.guestToolsImagePath) {
            let toolsAttachment = try VZDiskImageStorageDeviceAttachment(url: layout.guestToolsImagePath, readOnly: true)
            storageDevices.append(VZUSBMassStorageDeviceConfiguration(attachment: toolsAttachment))
        }
        let network = VZVirtioNetworkDeviceConfiguration()
        network.attachment = VZNATNetworkDeviceAttachment()
        let graphics = VZMacGraphicsDeviceConfiguration()
        graphics.displays = [
            VZMacGraphicsDisplayConfiguration(widthInPixels: 1024, heightInPixels: 768, pixelsPerInch: 80)
        ]

        let configuration = VZVirtualMachineConfiguration()
        configuration.platform = platform
        configuration.bootLoader = VZMacOSBootLoader()
        configuration.cpuCount = cpuCount
        configuration.memorySize = memoryBytes
        configuration.storageDevices = storageDevices
        configuration.networkDevices = [network]
        configuration.graphicsDevices = [graphics]
        configuration.socketDevices = [VZVirtioSocketDeviceConfiguration()]
        configuration.keyboards = [VZUSBKeyboardConfiguration()]
        configuration.pointingDevices = [VZUSBScreenCoordinatePointingDeviceConfiguration()]
        try configuration.validate()
        return configuration
    }

    private static func runMacOSInstaller(configuration: VZVirtualMachineConfiguration, restoreURL: URL) throws {
        let queue = DispatchQueue(label: "whoathere.macos.vm.install")
        let semaphore = DispatchSemaphore(value: 0)
        let resultBox = LockedResultBox<Void>()
        let configurationBox = UncheckedSendableBox(value: configuration)
        queue.async {
            let virtualMachine = VZVirtualMachine(configuration: configurationBox.value, queue: queue)
            let installer = VZMacOSInstaller(virtualMachine: virtualMachine, restoringFromImageAt: restoreURL)
            installer.install { result in
                resultBox.store(result.mapError { $0 })
                semaphore.signal()
            }
        }
        semaphore.wait()
        guard let result = resultBox.load() else {
            throw helperError("restore_image_install_returned_no_result")
        }
        try result.get()
    }

    private static func requestedMemoryBytes(
        options: HelperOptions,
        requirements: VZMacOSConfigurationRequirements
    ) throws -> UInt64 {
        let (requested, overflow) = options.memoryMiB.multipliedReportingOverflow(by: 1_048_576)
        guard !overflow else {
            throw helperError("requested_memory_overflow")
        }
        let minimum = max(VZVirtualMachineConfiguration.minimumAllowedMemorySize, requirements.minimumSupportedMemorySize)
        let memory = max(requested, minimum)
        guard memory <= VZVirtualMachineConfiguration.maximumAllowedMemorySize else {
            throw helperError("requested_memory_exceeds_host_limit")
        }
        return memory
    }

    private static func requestedCPUCount(requirements: VZMacOSConfigurationRequirements) throws -> Int {
        let minimum = max(VZVirtualMachineConfiguration.minimumAllowedCPUCount, requirements.minimumSupportedCPUCount)
        let cpuCount = max(minimum, 2)
        guard cpuCount <= VZVirtualMachineConfiguration.maximumAllowedCPUCount else {
            throw helperError("requested_cpu_count_exceeds_host_limit")
        }
        return cpuCount
    }

    private struct RuntimeStartStatus {
        var status: String
        var reasonCodes: [String]
        var exitCode: Int32
    }

    private static func runtimeStartReasons(layout: BundleLayout) -> [String] {
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
        } else {
            reasons.append(contentsOf: validateManifest(layout: layout, includeSignatureReason: false).reasonCodes)
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
        if !fileExists(layout.guestProvisioningReceiptPath) {
            reasons.append("guest_readiness_agent_not_provisioned")
        }
        return reasonArray(reasons)
    }

    private static func spawnRuntimeProcess(layout: BundleLayout) throws -> Process {
        try FileManager.default.createDirectory(at: layout.logsDir, withIntermediateDirectories: true)
        let stdoutURL = layout.logsDir.appendingPathComponent("runtime.stdout.log")
        let stderrURL = layout.logsDir.appendingPathComponent("runtime.stderr.log")
        FileManager.default.createFile(atPath: stdoutURL.path, contents: nil)
        FileManager.default.createFile(atPath: stderrURL.path, contents: nil)
        let stdout = try FileHandle(forWritingTo: stdoutURL)
        let stderr = try FileHandle(forWritingTo: stderrURL)
        defer {
            try? stdout.close()
            try? stderr.close()
        }

        let executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
        let process = Process()
        process.executableURL = executableURL
        process.arguments = [
            "run",
            "--state-dir", layout.stateDir.path,
            "--json"
        ]
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        process.standardOutput = stdout
        process.standardError = stderr
        try process.run()
        return process
    }

    private static func waitForRuntimeStart(layout: BundleLayout, pid: pid_t, process: Process) -> RuntimeStartStatus {
        let deadline = Date().addingTimeInterval(15)
        while Date() < deadline {
            if fileExists(layout.healthProofPath), processIsAlive(pid) {
                return RuntimeStartStatus(status: "ok", reasonCodes: [], exitCode: 0)
            }
            if !process.isRunning {
                return RuntimeStartStatus(
                    status: "fail_closed",
                    reasonCodes: ["runtime_process_exited_before_health"],
                    exitCode: 20
                )
            }
            Thread.sleep(forTimeInterval: 0.2)
        }
        return RuntimeStartStatus(
            status: "starting",
            reasonCodes: ["runtime_health_pending"],
            exitCode: 0
        )
    }

    private static func loadInstalledMacOSConfiguration(layout: BundleLayout) throws -> VZVirtualMachineConfiguration {
        let hardwareData = try Data(contentsOf: layout.hardwareModelPath)
        guard let hardwareModel = VZMacHardwareModel(dataRepresentation: hardwareData) else {
            throw helperError("hardware_model_data_invalid")
        }
        guard hardwareModel.isSupported else {
            throw helperError("hardware_model_not_supported")
        }
        let machineData = try Data(contentsOf: layout.machineIdentifierPath)
        guard let machineIdentifier = VZMacMachineIdentifier(dataRepresentation: machineData) else {
            throw helperError("machine_identifier_data_invalid")
        }
        let auxiliaryStorage = VZMacAuxiliaryStorage(url: layout.auxiliaryStoragePath)
        let config = readBundleConfig(layout)
        let cpuCount = intConfig(config, key: "cpu_count", defaultValue: 2)
        let memoryMiB = uint64Config(config, key: "memory_mib", defaultValue: 6144)
        let attachGuestTools = boolConfig(config, key: "guest_tools_attach_enabled", defaultValue: false)
        let (memoryBytes, overflow) = memoryMiB.multipliedReportingOverflow(by: 1_048_576)
        guard !overflow else {
            throw helperError("configured_memory_overflow")
        }
        return try buildMacOSConfiguration(
            layout: layout,
            hardwareModel: hardwareModel,
            machineIdentifier: machineIdentifier,
            auxiliaryStorage: auxiliaryStorage,
            cpuCount: cpuCount,
            memoryBytes: memoryBytes,
            attachGuestTools: attachGuestTools
        )
    }

    private static func startAndHoldVirtualMachine(configuration: VZVirtualMachineConfiguration, layout: BundleLayout) throws -> Never {
        let queue = DispatchQueue(label: "whoathere.macos.vm.runtime")
        let semaphore = DispatchSemaphore(value: 0)
        let resultBox = LockedResultBox<Void>()
        let sessionID = try randomHex(byteCount: 16)
        let challenge = try randomHex(byteCount: 32)
        let virtualMachine = VZVirtualMachine(configuration: configuration, queue: queue)
        guard let socketDevice = virtualMachine.socketDevices.first as? VZVirtioSocketDevice else {
            throw helperError("guest_readiness_socket_device_missing")
        }
        let readinessDelegate = GuestReadinessListener(layout: layout, sessionID: sessionID, challenge: challenge)
        let socketListener = VZVirtioSocketListener()
        socketListener.delegate = readinessDelegate
        queue.sync {
            socketDevice.setSocketListener(socketListener, forPort: guestReadinessPort)
        }
        let stopState = RuntimeStopState()
        let signalSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: queue)
        signal(SIGTERM, SIG_IGN)
        let runtimeLayoutBox = UncheckedSendableBox(value: layout)
        let runtimeVirtualMachineBox = UncheckedSendableBox(value: virtualMachine)
        signalSource.setEventHandler {
            guard stopState.claimStop() else {
                return
            }
            requestRuntimeShutdown(
                virtualMachine: runtimeVirtualMachineBox.value,
                layout: runtimeLayoutBox.value,
                queue: queue,
                reason: "sigterm"
            )
        }
        signalSource.resume()
        let runtimeReferences = RuntimeReferences(
            virtualMachine: virtualMachine,
            socketListener: socketListener,
            delegate: readinessDelegate,
            signalSource: signalSource
        )
        let virtualMachineBox = UncheckedSendableBox(value: virtualMachine)
        queue.async {
            virtualMachineBox.value.start { result in
                resultBox.store(result.mapError { $0 })
                semaphore.signal()
            }
        }
        semaphore.wait()
        guard let result = resultBox.load() else {
            throw helperError("runtime_start_returned_no_result")
        }
        try result.get()
        try writeRuntimeProof(layout: layout, pid: getpid(), sessionID: sessionID, challenge: challenge)
        writeJSONFields(baseFields(status: "ok").merging([
            "operation": "run",
            "state_dir": layout.stateDir.path,
            "runtime_pid": Int(getpid()),
            "vm_session_id": sessionID,
            "guest_readiness_port": Int(guestReadinessPort),
            "health_proof_type": "host_vm_start_only",
            "host_runtime_health_proven": true,
            "guest_health_proven": false,
            "high_risk_package_execution_enabled": false,
            "exit_code": 0
        ]) { _, new in new })
        withExtendedLifetime(runtimeReferences) {
            dispatchMain()
        }
    }

    private static func requestRuntimeShutdown(
        virtualMachine: VZVirtualMachine,
        layout: BundleLayout,
        queue: DispatchQueue,
        reason: String
    ) {
        let virtualMachineBox = UncheckedSendableBox(value: virtualMachine)
        let layoutBox = UncheckedSendableBox(value: layout)

        @Sendable func finish(status: String, stopMethod: String, reasonCodes: [String], exitCode: Int32) {
            try? writeRuntimeShutdownProof(
                layout: layoutBox.value,
                pid: getpid(),
                status: status,
                stopMethod: stopMethod,
                reasonCodes: reasonCodes
            )
            try? removeRuntimeProofFiles(layoutBox.value)
            writeJSONFields(baseFields(status: status).merging([
                "operation": "run_shutdown",
                "runtime_pid": Int(getpid()),
                "stop_method": stopMethod,
                "reason_codes": reasonArray(reasonCodes),
                "high_risk_package_execution_enabled": false,
                "exit_code": Int(exitCode)
            ]) { _, new in new })
            exit(exitCode)
        }

        @Sendable func forceStop(reasonCode: String) {
            guard virtualMachineBox.value.canStop else {
                finish(
                    status: "error",
                    stopMethod: "stop_unavailable",
                    reasonCodes: [reasonCode, "vm_cannot_stop"],
                    exitCode: 70
                )
                return
            }
            virtualMachineBox.value.stop { error in
                if let error {
                    finish(
                        status: "error",
                        stopMethod: "force_stop",
                        reasonCodes: [reasonCode, "vm_force_stop_failed", sanitizedReason(error)],
                        exitCode: 70
                    )
                } else {
                    finish(
                        status: "ok",
                        stopMethod: "force_stop",
                        reasonCodes: [reasonCode],
                        exitCode: 0
                    )
                }
            }
        }

        @Sendable func observeGuestStop(deadline: Date) {
            if virtualMachineBox.value.state == .stopped {
                finish(
                    status: "ok",
                    stopMethod: "guest_requested_stop",
                    reasonCodes: [reason],
                    exitCode: 0
                )
                return
            }
            guard Date() < deadline else {
                forceStop(reasonCode: "guest_stop_timeout")
                return
            }
            queue.asyncAfter(deadline: .now() + .milliseconds(250)) {
                observeGuestStop(deadline: deadline)
            }
        }

        if virtualMachineBox.value.canRequestStop {
            do {
                try virtualMachineBox.value.requestStop()
                observeGuestStop(deadline: Date().addingTimeInterval(20))
            } catch {
                forceStop(reasonCode: "guest_stop_request_failed_\(sanitizedReason(error))")
            }
        } else {
            forceStop(reasonCode: "guest_stop_unavailable")
        }
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
            try removeIfPresent(layout.guestHealthProofPath)
            try removeIfPresent(layout.runtimePidPath)
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
        if let pid = readRuntimePID(layout), runtimeProcessIsAlive(pid) {
            emit(
                fields: failClosedFields(layout: layout, reasons: ["runtime_process_running"], exitCode: 20)
                    .merging([
                        "operation": "prune",
                        "mutation": false,
                        "runtime_pid": Int(pid)
                    ]) { _, new in new },
                exitCode: 20
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
        guard let pid = readRuntimePID(layout), runtimeProcessIsAlive(pid) else {
            emit(
                fields: failClosedFields(
                    layout: layout,
                    reasons: ["runtime_process_not_running"],
                    exitCode: 20
                ).merging([
                    "host_runtime_health_proven": false,
                    "health_proven": false,
                    "guest_health_proven": false,
                    "high_risk_package_execution_enabled": false
                ]) { _, new in new },
                exitCode: 20
            )
        }
        guard fileExists(layout.healthProofPath),
              let runtimeState = readJSONObject(layout.runtimeStatePath),
              let hostProof = readJSONObject(layout.healthProofPath),
              intField(runtimeState, "runtime_pid") == Int(pid),
              intField(hostProof, "runtime_pid") == Int(pid),
              let sessionID = runtimeState["vm_session_id"] as? String,
              hostProof["vm_session_id"] as? String == sessionID else {
            emit(
                fields: failClosedFields(
                    layout: layout,
                    reasons: ["host_runtime_health_proof_missing_or_mismatched"],
                    exitCode: 20
                ).merging([
                    "runtime_pid": Int(pid),
                    "runtime_pid_alive": true,
                    "host_runtime_health_proven": false,
                    "health_proven": false,
                    "guest_health_proven": false,
                    "guest_health_proof_present": fileExists(layout.guestHealthProofPath),
                    "high_risk_package_execution_enabled": false
                ]) { _, new in new },
                exitCode: 20
            )
        }
        guard let guestProof = readJSONObject(layout.guestHealthProofPath) else {
            emit(
                fields: failClosedFields(
                    layout: layout,
                    reasons: ["guest_health_proof_missing_or_mismatched"],
                    exitCode: 20
                ).merging([
                    "runtime_pid": Int(pid),
                    "runtime_pid_alive": true,
                    "vm_session_id": sessionID,
                    "host_runtime_health_proven": true,
                    "health_proof_type": "host_vm_start_only",
                    "health_proven": false,
                    "guest_health_proven": false,
                    "guest_health_proof_present": fileExists(layout.guestHealthProofPath),
                    "high_risk_package_execution_enabled": false
                ]) { _, new in new },
                exitCode: 20
            )
        }
        let guestProofReasons = validateGuestHealthProof(
            runtimeState: runtimeState,
            hostProof: hostProof,
            guestProof: guestProof,
            runtimePID: Int(pid),
            expectedHelperVersion: helperVersion,
            expectedProtocol: guestReadinessProtocol,
            expectedPort: Int(guestReadinessPort)
        )
        guard guestProofReasons.isEmpty else {
            emit(
                fields: failClosedFields(
                    layout: layout,
                    reasons: guestProofReasons,
                    exitCode: 20
                ).merging([
                    "runtime_pid": Int(pid),
                    "runtime_pid_alive": true,
                    "vm_session_id": sessionID,
                    "host_runtime_health_proven": true,
                    "health_proof_type": "host_vm_start_only",
                    "health_proven": false,
                    "guest_health_proven": false,
                    "guest_health_proof_present": true,
                    "high_risk_package_execution_enabled": false
                ]) { _, new in new },
                exitCode: 20
            )
        }
        emit(
            fields: baseFields(status: "ok").merging([
                "state_dir": layout.stateDir.path,
                "bundle_dir": layout.bundleDir.path,
                "runtime_pid": Int(pid),
                "runtime_pid_alive": true,
                "vm_session_id": sessionID,
                "host_runtime_health_proven": true,
                "health_proven": true,
                "health_proof_type": "guest_vsock_readiness",
                "guest_health_proven": true,
                "guest_health_proof_present": true,
                "guest_readiness_protocol": guestReadinessProtocol,
                "guest_readiness_port": Int(guestReadinessPort),
                "image_digest": guestProof["image_digest"] as? String ?? "unknown",
                "high_risk_package_execution_enabled": false,
                "exit_code": 0
            ]) { _, new in new },
            exitCode: 0
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
        } else {
            reasons.append(contentsOf: validateManifest(layout: layout, includeSignatureReason: true).reasonCodes)
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
        if !fileExists(layout.guestProvisioningReceiptPath) {
            reasons.append("guest_readiness_agent_not_provisioned")
        }
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

    private static func createRawDiskImage(at url: URL, diskGiB: UInt64) throws {
        let (diskBytes, overflow) = diskGiB.multipliedReportingOverflow(by: 1_073_741_824)
        guard !overflow, diskBytes >= 1_073_741_824 else {
            throw helperError("disk_size_invalid")
        }
        guard diskBytes % 512 == 0 else {
            throw helperError("disk_size_not_block_aligned")
        }
        try removeIfPresent(url)
        guard FileManager.default.createFile(atPath: url.path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
            throw helperError("disk_image_create_failed")
        }
        let handle = try FileHandle(forWritingTo: url)
        try handle.truncate(atOffset: diskBytes)
        try handle.close()
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
            "guest_tools_attach_enabled": false,
            "high_risk_package_execution_enabled": false
        ]
        let data = try JSONSerialization.data(withJSONObject: config, options: [.prettyPrinted, .sortedKeys])
        try data.write(to: layout.configPath, options: [.atomic])
    }

    private static func writeRestoreManifest(
        layout: BundleLayout,
        restoreImage: VZMacOSRestoreImage,
        restoreDigest: String,
        cpuCount: Int,
        memoryBytes: UInt64
    ) throws {
        let body = [
            "schema_version=whoathere.macos_vm_image.v1",
            "image_id=local-restore-image-install",
            "macos_version=\(operatingSystemVersionString(restoreImage.operatingSystemVersion))",
            "macos_build_version=\(restoreImage.buildVersion)",
            "architecture=arm64",
            "restore_image_digest=sha256:\(restoreDigest)",
            "cpu_count=\(cpuCount)",
            "memory_mib=\(memoryBytes / 1_048_576)",
            "signature_status=signature_verification_not_implemented",
            "helper_version=\(helperVersion)"
        ].joined(separator: "\n") + "\n"
        try body.write(to: layout.manifestPath, atomically: true, encoding: .utf8)
    }

    private static func writeRestoreConfig(
        layout: BundleLayout,
        options: HelperOptions,
        restoreDigest: String,
        cpuCount: Int,
        memoryBytes: UInt64
    ) throws {
        let config: [String: Any] = [
            "schema_version": bundleSchemaVersion,
            "helper_version": helperVersion,
            "memory_mib": memoryBytes / 1_048_576,
            "requested_memory_mib": options.memoryMiB,
            "cpu_count": cpuCount,
            "disk_gib": options.diskGiB,
            "disk_path": layout.diskPath.path,
            "auxiliary_storage_path": layout.auxiliaryStoragePath.path,
            "hardware_model_path": layout.hardwareModelPath.path,
            "machine_identifier_path": layout.machineIdentifierPath.path,
            "restore_image_digest": "sha256:\(restoreDigest)",
            "guest_tools_attach_enabled": false,
            "high_risk_package_execution_enabled": false
        ]
        let data = try JSONSerialization.data(withJSONObject: config, options: [.prettyPrinted, .sortedKeys])
        try data.write(to: layout.configPath, options: [.atomic])
    }

    private static func writeRuntimeProof(layout: BundleLayout, pid: pid_t, sessionID: String, challenge: String) throws {
        let timestamp = ISO8601DateFormatter().string(from: Date())
        let runtimeState: [String: Any] = [
            "schema_version": bundleSchemaVersion,
            "helper_version": helperVersion,
            "runtime_pid": Int(pid),
            "vm_session_id": sessionID,
            "state": "running",
            "started_at": timestamp,
            "image_digest": imageDigestForProof(layout),
            "guest_readiness_protocol": guestReadinessProtocol,
            "guest_readiness_port": Int(guestReadinessPort),
            "guest_readiness_challenge_sha256": sha256Hex(challenge),
            "guest_tools_image_attached": guestToolsAttachEnabled(layout),
            "high_risk_package_execution_enabled": false
        ]
        let healthProof: [String: Any] = [
            "schema_version": bundleSchemaVersion,
            "helper_version": helperVersion,
            "runtime_pid": Int(pid),
            "vm_session_id": sessionID,
            "image_digest": imageDigestForProof(layout),
            "health_proof_type": "host_vm_start_only",
            "host_vm_started": true,
            "host_runtime_health_proven": true,
            "guest_health_proven": false,
            "guest_readiness_protocol": guestReadinessProtocol,
            "guest_readiness_port": Int(guestReadinessPort),
            "guest_readiness_challenge_sha256": sha256Hex(challenge),
            "guest_tools_image_attached": guestToolsAttachEnabled(layout),
            "created_at": timestamp,
            "high_risk_package_execution_enabled": false
        ]
        try JSONSerialization.data(withJSONObject: runtimeState, options: [.prettyPrinted, .sortedKeys])
            .write(to: layout.runtimeStatePath, options: [.atomic])
        try JSONSerialization.data(withJSONObject: healthProof, options: [.prettyPrinted, .sortedKeys])
            .write(to: layout.healthProofPath, options: [.atomic])
        try "\(pid)\n".write(to: layout.runtimePidPath, atomically: true, encoding: .utf8)
    }

    private static func writeRuntimeShutdownProof(
        layout: BundleLayout,
        pid: pid_t,
        status: String,
        stopMethod: String,
        reasonCodes: [String]
    ) throws {
        let shutdown: [String: Any] = [
            "schema_version": bundleSchemaVersion,
            "helper_version": helperVersion,
            "runtime_pid": Int(pid),
            "status": status,
            "stop_method": stopMethod,
            "reason_codes": reasonArray(reasonCodes),
            "created_at": ISO8601DateFormatter().string(from: Date()),
            "high_risk_package_execution_enabled": false
        ]
        try JSONSerialization.data(withJSONObject: shutdown, options: [.prettyPrinted, .sortedKeys])
            .write(to: layout.runtimeShutdownPath, options: [.atomic])
    }

    private static func removeRuntimeProofFiles(_ layout: BundleLayout) throws {
        try removeIfPresent(layout.runtimePidPath)
        try removeIfPresent(layout.runtimeStatePath)
        try removeIfPresent(layout.healthProofPath)
        try removeIfPresent(layout.guestHealthProofPath)
        try removeIfPresent(layout.savedStatePath)
    }

    private static func readBundleConfig(_ layout: BundleLayout) -> [String: Any] {
        guard let data = try? Data(contentsOf: layout.configPath),
              let object = try? JSONSerialization.jsonObject(with: data),
              let config = object as? [String: Any] else {
            return [:]
        }
        return config
    }

    private static func intConfig(_ config: [String: Any], key: String, defaultValue: Int) -> Int {
        if let value = config[key] as? Int {
            return value
        }
        if let value = config[key] as? NSNumber {
            return value.intValue
        }
        return defaultValue
    }

    private static func uint64Config(_ config: [String: Any], key: String, defaultValue: UInt64) -> UInt64 {
        if let value = config[key] as? UInt64 {
            return value
        }
        if let value = config[key] as? Int, value >= 0 {
            return UInt64(value)
        }
        if let value = config[key] as? NSNumber {
            return value.uint64Value
        }
        return defaultValue
    }

    private static func boolConfig(_ config: [String: Any], key: String, defaultValue: Bool) -> Bool {
        if let value = config[key] as? Bool {
            return value
        }
        if let value = config[key] as? NSNumber {
            return value.boolValue
        }
        return defaultValue
    }

    private static func guestToolsAttachEnabled(_ layout: BundleLayout) -> Bool {
        boolConfig(readBundleConfig(layout), key: "guest_tools_attach_enabled", defaultValue: false)
            && fileExists(layout.guestToolsImagePath)
    }

    private static func validateManifest(layout: BundleLayout, includeSignatureReason: Bool) -> ManifestValidationResult {
        guard fileExists(layout.manifestPath) else {
            return ManifestValidationResult(fields: [:], reasonCodes: ["manifest_missing"])
        }
        var fields: [String: String] = [:]
        var reasons: [String] = []
        guard let contents = try? String(contentsOf: layout.manifestPath, encoding: .utf8) else {
            return ManifestValidationResult(fields: [:], reasonCodes: ["manifest_unreadable"])
        }
        for rawLine in contents.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.isEmpty || line.hasPrefix("#") {
                continue
            }
            guard let separator = line.firstIndex(of: "=") else {
                reasons.append("manifest_line_invalid")
                continue
            }
            let key = String(line[..<separator]).trimmingCharacters(in: .whitespacesAndNewlines)
            let value = String(line[line.index(after: separator)...]).trimmingCharacters(in: .whitespacesAndNewlines)
            if key.isEmpty || value.isEmpty {
                reasons.append("manifest_key_or_value_empty")
                continue
            }
            if fields[key] != nil {
                reasons.append("manifest_key_duplicate")
                continue
            }
            fields[key] = value
        }

        if fields["schema_version"] != "whoathere.macos_vm_image.v1" {
            reasons.append("manifest_schema_invalid")
        }
        if fields["image_id", default: ""].isEmpty {
            reasons.append("manifest_image_id_missing")
        }
        if fields["macos_version", default: ""].isEmpty {
            reasons.append("manifest_macos_version_missing")
        }
        let architecture = fields["architecture", default: ""]
        if architecture != "arm64" && architecture != "aarch64" {
            reasons.append("manifest_architecture_not_arm64")
        }
        if fields["helper_version"] != helperVersion {
            reasons.append("manifest_helper_version_mismatch")
        }

        let imageDigest = fields["image_digest"]
        let restoreDigest = fields["restore_image_digest"]
        if imageDigest == nil && restoreDigest == nil {
            reasons.append("manifest_digest_missing")
        }
        if let imageDigest, !validSha256Digest(imageDigest) {
            reasons.append("manifest_image_digest_invalid")
        }
        if let restoreDigest, !validSha256Digest(restoreDigest) {
            reasons.append("manifest_restore_image_digest_invalid")
        }

        let signatureStatus = fields["signature_status"]
        if includeSignatureReason {
            if signatureStatus == "signature_verification_not_implemented" {
                reasons.append("signature_verification_not_implemented")
            } else if signatureStatus != "verified" {
                reasons.append("manifest_signature_not_verified")
            }
        }

        return ManifestValidationResult(fields: fields, reasonCodes: reasonArray(reasons))
    }

    private static func validSha256Digest(_ digest: String) -> Bool {
        guard digest.hasPrefix("sha256:") else {
            return false
        }
        let hex = digest.dropFirst("sha256:".count)
        return hex.count == 64 && hex.allSatisfy { character in
            character.isNumber || ("a"..."f").contains(character) || ("A"..."F").contains(character)
        }
    }

    private static func bundleHasInstalledState(_ layout: BundleLayout) -> Bool {
        fileExists(layout.diskPath)
            || fileExists(layout.auxiliaryStoragePath)
            || fileExists(layout.hardwareModelPath)
            || fileExists(layout.machineIdentifierPath)
    }

    private static func operatingSystemVersionString(_ version: OperatingSystemVersion) -> String {
        "\(version.majorVersion).\(version.minorVersion).\(version.patchVersion)"
    }

    private static func helperError(_ reason: String) -> NSError {
        NSError(domain: "whoathere.helper", code: 1, userInfo: [
            NSLocalizedDescriptionKey: reason
        ])
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

    private static func runtimeProcessIsAlive(_ pid: pid_t) -> Bool {
        guard processIsAlive(pid),
              let processPath = executablePath(for: pid) else {
            return false
        }
        return canonicalPath(processPath) == canonicalPath(absoluteExecutablePath(CommandLine.arguments[0]))
    }

    private static func waitForRuntimeProcessExit(_ pid: pid_t, timeoutSeconds: TimeInterval) -> Bool {
        let deadline = Date().addingTimeInterval(timeoutSeconds)
        while Date() < deadline {
            if !runtimeProcessIsAlive(pid) {
                return true
            }
            Thread.sleep(forTimeInterval: 0.2)
        }
        return !runtimeProcessIsAlive(pid)
    }

    private static func executablePath(for pid: pid_t) -> String? {
        var buffer = [CChar](repeating: 0, count: 4096)
        let capacity = buffer.count
        let length = buffer.withUnsafeMutableBufferPointer { pointer -> Int32 in
            guard let baseAddress = pointer.baseAddress else {
                return 0
            }
            return proc_pidpath(pid, baseAddress, UInt32(capacity))
        }
        guard length > 0 else {
            return nil
        }
        let bytes = buffer
            .prefix(Int(length))
            .prefix { $0 != 0 }
            .map { UInt8(bitPattern: $0) }
        return String(decoding: bytes, as: UTF8.self)
    }

    private static func absoluteExecutablePath(_ path: String) -> String {
        if path.hasPrefix("/") {
            return path
        }
        return URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent(path)
            .path
    }

    private static func canonicalPath(_ path: String) -> String {
        URL(fileURLWithPath: path)
            .standardizedFileURL
            .resolvingSymlinksInPath()
            .path
    }

    private static func removeIfPresent(_ url: URL) throws {
        if fileExists(url) {
            try FileManager.default.removeItem(at: url)
        }
    }

    private static func sha256Digest(path: String) throws -> String {
        let handle = try FileHandle(forReadingFrom: URL(fileURLWithPath: path))
        var hasher = SHA256()
        while true {
            let chunk = try handle.read(upToCount: 1024 * 1024) ?? Data()
            if chunk.isEmpty {
                break
            }
            hasher.update(data: chunk)
        }
        try handle.close()
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    private static func sanitizedReason(_ error: Error) -> String {
        String(describing: error)
            .replacingOccurrences(of: "\n", with: "_")
            .replacingOccurrences(of: "\r", with: "_")
            .replacingOccurrences(of: " ", with: "_")
    }

    private static func emit(fields: [String: Any], exitCode: Int32) -> Never {
        writeJSONFields(fields)
        exit(exitCode)
    }

    private static func writeJSONFields(_ fields: [String: Any]) {
        let data = (try? JSONSerialization.data(withJSONObject: fields, options: [.prettyPrinted, .sortedKeys]))
            ?? Data("{\"status\":\"error\",\"reason_codes\":[\"json_encoding_failed\"],\"exit_code\":70}".utf8)
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data("\n".utf8))
    }
}
