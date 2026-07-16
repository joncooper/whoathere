import CryptoKit
import Darwin
import Foundation
@preconcurrency import Virtualization
import WhoaThereMacosVmHelperCore

private struct UncheckedSendableBox<Value>: @unchecked Sendable {
    let value: Value
}

private final class LockedBox<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Value?

    func store(_ value: Value) {
        lock.lock()
        self.value = value
        lock.unlock()
    }

    func load() -> Value? {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

private final class ExecutionProgress {
    var cloneCreated = false
    var cloneDestroyed = false
    var vmStartAttempted = false
    var vmStarted = false
    var vmStopped = false
    var runtimeTerminal: String?
    var rawFrameEvidenceSHA256: String?
}

private enum NpmEnvironment: String {
    case ciTrue = "ci_true"
    case ciFalse = "ci_false"
}

private enum PackageExecutionHarnessError: Error, CustomStringConvertible {
    case usage
    case invalidInput(String)
    case builder(String)
    case socketPair
    case vmStart(String)
    case vmStop
    case timeout
    case verification(String)

    var description: String {
        switch self {
        case .usage: return "usage"
        case .invalidInput(let value): return "invalid_input_\(value)"
        case .builder(let value): return "builder_\(value)"
        case .socketPair: return "raw_frame_socket_pair_failed"
        case .vmStart(let value): return "vm_start_\(value)"
        case .vmStop: return "vm_stop_unproven"
        case .timeout: return "execution_timeout"
        case .verification(let value): return "verification_\(value)"
        }
    }
}

private struct Options {
    let artifact: URL
    let environment: NpmEnvironment
    let kernel: URL
    let baseInitramfs: URL
    let runtimeDirectory: URL
    let bundleBuilder: URL
    let imageBuilder: URL
    let backendIdentity: URL
    let qualifiedBackend: URL
    let qualificationRecord: URL
    let guestPublicKey: URL
    let hostPublicKey: URL
    let grantPublicKey: URL
    let grantSigningSeed: URL
    let guestSigningSeed: URL
    let outputDirectory: URL
    let timeoutSeconds: Int

    init(arguments: [String]) throws {
        let accepted = Set([
            "--artifact", "--environment", "--kernel", "--base-initramfs",
            "--runtime-directory", "--bundle-builder",
            "--image-builder", "--backend-identity", "--qualified-backend",
            "--qualification-record", "--guest-public-key", "--host-public-key",
            "--grant-public-key", "--grant-signing-seed", "--guest-signing-seed",
            "--output-directory", "--timeout-seconds",
        ])
        var values = [String: String]()
        var index = 1
        while index < arguments.count {
            let key = arguments[index]
            guard accepted.contains(key), values[key] == nil, index + 1 < arguments.count else {
                throw PackageExecutionHarnessError.usage
            }
            values[key] = arguments[index + 1]
            index += 2
        }
        let pathArguments = accepted.subtracting(["--environment", "--timeout-seconds"])
        guard pathArguments.allSatisfy({ values[$0]?.hasPrefix("/") == true }),
              let environment = values["--environment"].flatMap(NpmEnvironment.init(rawValue:)),
              let timeout = Int(values["--timeout-seconds"] ?? "180"),
              timeout >= 30, timeout <= 600 else {
            throw PackageExecutionHarnessError.usage
        }
        artifact = URL(fileURLWithPath: values["--artifact"]!)
        self.environment = environment
        kernel = URL(fileURLWithPath: values["--kernel"]!)
        baseInitramfs = URL(fileURLWithPath: values["--base-initramfs"]!)
        runtimeDirectory = URL(
            fileURLWithPath: values["--runtime-directory"]!, isDirectory: true
        )
        bundleBuilder = URL(fileURLWithPath: values["--bundle-builder"]!)
        imageBuilder = URL(fileURLWithPath: values["--image-builder"]!)
        backendIdentity = URL(fileURLWithPath: values["--backend-identity"]!)
        qualifiedBackend = URL(fileURLWithPath: values["--qualified-backend"]!)
        qualificationRecord = URL(fileURLWithPath: values["--qualification-record"]!)
        guestPublicKey = URL(fileURLWithPath: values["--guest-public-key"]!)
        hostPublicKey = URL(fileURLWithPath: values["--host-public-key"]!)
        grantPublicKey = URL(fileURLWithPath: values["--grant-public-key"]!)
        grantSigningSeed = URL(fileURLWithPath: values["--grant-signing-seed"]!)
        guestSigningSeed = URL(fileURLWithPath: values["--guest-signing-seed"]!)
        outputDirectory = URL(
            fileURLWithPath: values["--output-directory"]!, isDirectory: true
        )
        timeoutSeconds = timeout
    }
}

private struct ExecutionImage: Equatable {
    let manifestData: Data
    let manifestSHA256: String
    let initramfs: URL
    let initramfsSHA256: String
    let authorityRequestSHA256: String
    let executionGrantSHA256: String
    let artifactSHA256: String
    let cloneBindingSHA256: String
    let rootfsSHA256: String
    let runtimeManifestSHA256: String
    let packageRunnerSHA256: String
    let qualifiedBackendSHA256: String
    let guestPublicKeySHA256: String
    let hostPublicKeySHA256: String
    let expiresAtUnixSeconds: UInt64
}

@main
private enum PackageExecutionMain {
    static func main() {
        _ = umask(0o077)
        let progress = ExecutionProgress()
        do {
            let options = try Options(arguments: CommandLine.arguments)
            let result = try run(options, progress: progress)
            emitJSON(result)
            exit(0)
        } catch PackageExecutionHarnessError.usage {
            fputs(
                "usage: whoathere-linux-vz-package-execution --artifact PATH --environment ci_true|ci_false --kernel PATH --base-initramfs PATH --runtime-directory PATH --bundle-builder PATH --image-builder PATH --backend-identity PATH --qualified-backend PATH --qualification-record PATH --guest-public-key PATH --host-public-key PATH --grant-public-key PATH --grant-signing-seed PATH --guest-signing-seed PATH --output-directory PATH [--timeout-seconds 180]\n",
                stderr
            )
            emitFailure(reason: "usage", exitCode: 64, progress: progress)
            exit(64)
        } catch {
            emitFailure(reason: String(describing: error), exitCode: 70, progress: progress)
            exit(70)
        }
    }

    private static func run(
        _ options: Options,
        progress: ExecutionProgress
    ) throws -> [String: Any] {
        try requireEmptySecureDirectory(options.outputDirectory)
        for (name, url) in [
            ("artifact", options.artifact),
            ("kernel", options.kernel),
            ("base_initramfs", options.baseInitramfs),
            ("bundle_builder", options.bundleBuilder),
            ("image_builder", options.imageBuilder),
            ("backend_identity", options.backendIdentity),
            ("qualified_backend", options.qualifiedBackend),
            ("qualification_record", options.qualificationRecord),
            ("guest_public_key", options.guestPublicKey),
            ("host_public_key", options.hostPublicKey),
            ("grant_public_key", options.grantPublicKey),
            ("grant_signing_seed", options.grantSigningSeed),
            ("guest_signing_seed", options.guestSigningSeed),
        ] where !(try regularNonSymlink(url)) {
            throw PackageExecutionHarnessError.invalidInput(name)
        }

        let qualifiedData = try readBoundedRegularFile(
            options.qualifiedBackend, maximum: 16 * 1024 * 1024
        )
        let qualified = try decodeLinuxVzTelemetryQualificationRecord(qualifiedData)
        let backendData = try readBoundedRegularFile(
            options.backendIdentity, maximum: maximumLinuxVzTelemetryBackendIdentityBytesV1
        )
        let backend = try decodeUnqualifiedLinuxVzTelemetryBackendIdentity(
            backendData,
            expectedTelemetryRequirementsSHA256: qualified.telemetryRequirementsSHA256
        )
        let kernelSHA256 = try fileSHA256(options.kernel)
        guard backend.identitySHA256 == qualified.backendIdentitySHA256,
              backend.kernelImageSHA256 == kernelSHA256,
              backend.kernelRelease == "6.18.35-0-virt" else {
            throw PackageExecutionHarnessError.verification("backend_kernel_binding")
        }

        let layout = LinuxVzPackageRuntimeBaseLayout(
            runtimeDirectory: options.runtimeDirectory
        )
        let runtimeManifestData = try readBoundedRegularFile(
            layout.runtimeManifestURL,
            maximum: maximumLinuxVzPackageExecutionRuntimeManifestBytesV1
        )
        let runtimeManifest = try decodeLinuxVzPackageExecutionRuntimeManifest(
            runtimeManifestData
        )
        let base = try verifyAndLockLinuxVzPackageExecutionRuntimeBase(
            layout: layout,
            expectedRootfsSHA256: runtimeManifest.rootfsSHA256,
            expectedRootfsByteLength: runtimeManifest.rootfsByteLength,
            expectedRuntimeManifestSHA256: runtimeManifest.manifestSHA256,
            expectedPackageRunnerSHA256: runtimeManifest.packageRunnerSHA256
        )
        let clone = try base.createDisposableClone()
        progress.cloneCreated = true
        var virtualMachine: VZVirtualMachine?
        var vmQueue: DispatchQueue?
        var vmStopped = true
        var cloneDestroyed = false
        defer {
            if !vmStopped, let virtualMachine, let vmQueue {
                vmStopped = bestEffortStop(virtualMachine, queue: vmQueue)
            }
            if vmStopped, !cloneDestroyed {
                if (try? clone.cleanup()) != nil { cloneDestroyed = true }
            } else if !vmStopped {
                clone.preserveUntilVerifiedVMStop()
            }
            progress.vmStopped = progress.vmStarted && vmStopped
            progress.cloneDestroyed = cloneDestroyed
        }

        let cloneBinding = options.outputDirectory.appendingPathComponent(
            "runtime-clone-binding.json"
        )
        try writeNewPrivateFile(cloneBinding, data: clone.cloneBindingCanonicalJSON)
        let bundleDirectory = options.outputDirectory.appendingPathComponent(
            "execution-bundle", isDirectory: true
        )
        try createPrivateDirectory(bundleDirectory)
        try invoke(
            options.bundleBuilder,
            arguments: [
                "--backend-identity", options.backendIdentity.path,
                "--qualified-backend", options.qualifiedBackend.path,
                "--qualification-record", options.qualificationRecord.path,
                "--guest-public-key", options.guestPublicKey.path,
                "--host-public-key", options.hostPublicKey.path,
                "--grant-public-key", options.grantPublicKey.path,
                "--grant-signing-seed", options.grantSigningSeed.path,
                "--clone-binding", cloneBinding.path,
                "--artifact", options.artifact.path,
                "--environment", options.environment.rawValue,
                "--output-directory", bundleDirectory.path,
            ],
            name: "execution_bundle"
        )
        let authorityData = try readBoundedRegularFile(
            bundleDirectory.appendingPathComponent("package-authority-request.json"),
            maximum: maximumLinuxVzPackageAuthorityRequestBytesV1
        )
        let authority = try decodeLinuxVzPackageAuthorityRequest(authorityData)
        let grantURL = bundleDirectory.appendingPathComponent("execution-grant.json")
        let grantSHA256 = try fileSHA256(grantURL)
        let artifactSHA256 = try fileSHA256(
            bundleDirectory.appendingPathComponent("artifact.tgz")
        )
        let inputArtifactSHA256 = try fileSHA256(options.artifact)
        guard authority.cloneBindingSHA256 == clone.cloneBindingSHA256,
              authority.artifactKind == "npm_tarball",
              authority.artifactSHA256 == artifactSHA256,
              artifactSHA256 == inputArtifactSHA256,
              !authority.packageExecutionAuthorityPermitted,
              !authority.syncBackPermitted else {
            throw PackageExecutionHarnessError.verification("authority_binding")
        }

        let imageDirectory = options.outputDirectory.appendingPathComponent(
            "execution-image", isDirectory: true
        )
        try invoke(
            options.imageBuilder,
            arguments: [
                options.baseInitramfs.path,
                layout.runtimeManifestURL.path,
                bundleDirectory.path,
                options.guestSigningSeed.path,
                imageDirectory.path,
            ],
            name: "execution_image"
        )
        let image = try loadExecutionImage(
            imageDirectory,
            baseInitramfs: options.baseInitramfs,
            runtime: base,
            clone: clone,
            authority: authority,
            executionGrantSHA256: grantSHA256,
            qualifiedBackendSHA256: qualified.recordSHA256,
            guestPublicKey: options.guestPublicKey,
            hostPublicKey: options.hostPublicKey
        )
        let now = UInt64(Date().timeIntervalSince1970)
        guard now <= image.expiresAtUnixSeconds else {
            throw PackageExecutionHarnessError.verification("grant_expired_before_boot")
        }

        let serialLog = options.outputDirectory.appendingPathComponent("serial.log")
        let serialOutput = try openNewPrivateFileHandle(serialLog)
        defer { try? serialOutput.close() }
        var sockets = [Int32](repeating: -1, count: 2)
        guard socketpair(AF_UNIX, SOCK_DGRAM, 0, &sockets) == 0 else {
            throw PackageExecutionHarnessError.socketPair
        }
        defer {
            if sockets[0] >= 0 { close(sockets[0]) }
            if sockets[1] >= 0 { close(sockets[1]) }
        }
        let collector = try LinuxVzBoundedHostRawFrameCollector(capacity: 64)
        let collectionBox = LockedBox<LinuxVzBoundedHostRawFrameCollection>()
        let collectionDone = DispatchSemaphore(value: 0)
        var collectionFinished = false
        let hostFrameDescriptor = sockets[1]
        DispatchQueue.global(qos: .userInitiated).async {
            collectionBox.store(collector.collect(fileDescriptor: hostFrameDescriptor))
            collectionDone.signal()
        }
        defer {
            if !collectionFinished {
                collector.requestStop()
                _ = collectionDone.wait(timeout: .now() + .seconds(3))
            }
        }

        let networkHandle = FileHandle(fileDescriptor: sockets[0], closeOnDealloc: false)
        let configuration = try buildLinuxVzPackageExecutionVMConfiguration(
            kernelURL: options.kernel,
            initramfsURL: image.initramfs,
            clone: clone,
            serialInput: nil,
            serialOutput: serialOutput,
            rawFrameSocket: networkHandle
        )
        let contract = try linuxVzPackageExecutionVMConfigurationContract(
            kernelURL: options.kernel,
            initramfsURL: image.initramfs,
            clone: clone
        )
        guard contract.rootfsReadOnly, contract.storageDeviceCount == 1,
              contract.writableStorageDeviceCount == 0,
              contract.networkDeviceCount == 1, contract.socketDeviceCount == 0,
              contract.directoryShareCount == 0,
              contract.cloneBindingSHA256 == clone.cloneBindingSHA256 else {
            throw PackageExecutionHarnessError.verification("vm_contract")
        }
        let queue = DispatchQueue(label: "whoathere.linux-vz.package-execution")
        let machine = VZVirtualMachine(configuration: configuration, queue: queue)
        virtualMachine = machine
        vmQueue = queue
        vmStopped = false
        progress.vmStartAttempted = true
        try startVirtualMachine(machine, queue: queue)
        progress.vmStarted = true
        try waitForStop(
            machine,
            queue: queue,
            deadline: Date().addingTimeInterval(TimeInterval(options.timeoutSeconds))
        )
        vmStopped = true
        progress.vmStopped = true
        collector.requestStop()
        guard collectionDone.wait(timeout: .now() + .seconds(3)) == .success,
              let collection = collectionBox.load() else {
            throw PackageExecutionHarnessError.verification("raw_frame_collector_completion")
        }
        collectionFinished = true
        try serialOutput.synchronize()
        try serialOutput.close()

        let rawFrameEvidence = try hostRawFrameEvidence(collection)
        let rawFrameEvidenceSHA256 = dataSHA256(rawFrameEvidence)
        progress.rawFrameEvidenceSHA256 = rawFrameEvidenceSHA256
        try writeNewPrivateFile(
            options.outputDirectory.appendingPathComponent("host-raw-frame-observation.json"),
            data: rawFrameEvidence
        )
        guard collection.healthy,
              collection.terminal == "drained_after_stop",
              collection.droppedFrameCount == 0,
              collection.truncatedFrameCount == 0 else {
            throw PackageExecutionHarnessError.verification("raw_frame_evidence_incomplete")
        }
        let serialData = try readBoundedRegularFile(
            serialLog, maximum: maximumLinuxVzPackageExecutionSerialBytesV1
        )
        let serialEvidence = try parseLinuxVzPackageExecutionSerialEvidenceV1(serialData)
        let runtimeResult = try parseLinuxVzPackageRootRuntimeResultV1(serialEvidence.result)
        progress.runtimeTerminal = runtimeResult.terminal
        guard ["complete", "process_failed"].contains(runtimeResult.terminal),
              runtimeResult.actions.count == 1,
              runtimeResult.executionRequestSHA256 == authority.requestSHA256,
              runtimeResult.executionGrantSHA256 == grantSHA256,
              runtimeResult.artifactSHA256 == artifactSHA256,
              runtimeResult.rootEvidenceAuthenticated,
              runtimeResult.hostCompositionRequired,
              !runtimeResult.authoritativeVerdictPermitted,
              !runtimeResult.publicNetworkRoutePresent,
              runtimeResult.packageExecution,
              !runtimeResult.syncBackPermitted else {
            throw PackageExecutionHarnessError.verification("runtime_result_binding")
        }
        try writeNewPrivateFile(
            options.outputDirectory.appendingPathComponent("runtime-result.bin"),
            data: serialEvidence.result
        )
        if let childLog = serialEvidence.childLog {
            try writeNewPrivateFile(
                options.outputDirectory.appendingPathComponent("child.log"), data: childLog
            )
        }
        try clone.verifyReadyForAttachment()
        let finalImage = try loadExecutionImage(
            imageDirectory,
            baseInitramfs: options.baseInitramfs,
            runtime: base,
            clone: clone,
            authority: authority,
            executionGrantSHA256: grantSHA256,
            qualifiedBackendSHA256: qualified.recordSHA256,
            guestPublicKey: options.guestPublicKey,
            hostPublicKey: options.hostPublicKey
        )
        guard finalImage == image,
              try fileSHA256(options.kernel) == kernelSHA256 else {
            throw PackageExecutionHarnessError.verification("image_identity_changed")
        }
        try clone.cleanup()
        cloneDestroyed = true
        progress.cloneDestroyed = true

        let action = runtimeResult.actions[0]
        let runStatus: String
        if runtimeResult.terminal == "process_failed" {
            runStatus = "package_process_failed_evidence_preserved"
        } else if !serialEvidence.guestExecutionComplete {
            runStatus = "guest_incomplete_evidence_preserved"
        } else {
            runStatus = "package_process_complete_evidence_pending_host_composition"
        }
        var result: [String: Any] = [
            "schema_version": "whoathere.linux_vz_package_execution_result.v1",
            "status": runStatus,
            "environment": options.environment.rawValue,
            "artifact_sha256": artifactSHA256,
            "authority_request_sha256": authority.requestSHA256,
            "execution_grant_sha256": grantSHA256,
            "clone_binding_sha256": clone.cloneBindingSHA256,
            "execution_initramfs_sha256": image.initramfsSHA256,
            "runtime_result_sha256": serialEvidence.resultSHA256,
            "transcript_sha256": runtimeResult.transcriptSHA256,
            "root_receipt_sha256": dataSHA256(action.rootReceipt),
            "process_evidence_sha256": dataSHA256(action.process),
            "file_evidence_sha256": dataSHA256(action.file),
            "network_evidence_sha256": dataSHA256(action.network),
            "serial_log_sha256": dataSHA256(serialData),
            "host_raw_frame_observation_sha256": rawFrameEvidenceSHA256,
            "raw_frame_count": String(collection.ingressFrameCount),
            "retained_raw_frame_count": String(collection.retainedFrameCount),
            "vm_started": true,
            "vm_stopped": true,
            "clone_destroyed": true,
            "image_identity_stable": true,
            "guest_root_receipt_independently_verified": false,
            "host_raw_frame_observation_authenticated": false,
            "host_composition_complete": false,
            "authoritative_verdict_permitted": false,
            "public_network_route_present": false,
            "package_execution": true,
            "package_execution_terminal": runtimeResult.terminal,
            "package_process_succeeded": runtimeResult.terminal == "complete",
            "guest_execution_complete": serialEvidence.guestExecutionComplete,
            "sync_back": false,
        ]
        if let reason = serialEvidence.guestFailureReason {
            result["guest_failure_reason"] = reason
        }
        try writeNewPrivateFile(
            options.outputDirectory.appendingPathComponent("execution-run.json"),
            data: try localCanonicalJSONData(result)
        )
        return result
    }

    private static func loadExecutionImage(
        _ directory: URL,
        baseInitramfs: URL,
        runtime: LockedLinuxVzPackageExecutionRuntimeBase,
        clone: DisposableLinuxVzPackageRuntimeClone,
        authority: ParsedLinuxVzPackageAuthorityRequest,
        executionGrantSHA256: String,
        qualifiedBackendSHA256: String,
        guestPublicKey: URL,
        hostPublicKey: URL
    ) throws -> ExecutionImage {
        let manifestURL = directory.appendingPathComponent("manifest.json")
        let manifestData = try readBoundedRegularFile(manifestURL, maximum: 4 * 1024 * 1024)
        guard let value = try? JSONSerialization.jsonObject(with: manifestData) as? [String: Any]
        else {
            throw PackageExecutionHarnessError.invalidInput("execution_image_manifest")
        }
        var canonical = try localCanonicalJSONData(value)
        canonical.append(0x0a)
        let keys = Set([
            "architecture", "artifact_sha256", "authority_request_sha256",
            "backend_identity_sha256", "base_initramfs_sha256", "builder_source_sha256",
            "bundle_manifest_sha256", "candidate_runtime_manifest_sha256",
            "candidate_runtime_rootfs_byte_length", "candidate_runtime_rootfs_sha256",
            "clone_binding_sha256", "execution_authority_issued",
            "execution_descriptor_launcher_sha256",
            "execution_descriptor_launcher_source_sha256",
            "execution_grant_expires_at_unix_seconds",
            "execution_grant_issued_at_unix_seconds", "execution_grant_sha256",
            "execution_init_sha256", "execution_init_source_sha256",
            "execution_initramfs_sha256", "execution_overlay_cpio_gzip_sha256",
            "execution_overlay_cpio_sha256", "external_network",
            "guest_evidence_public_key_sha256", "host_evidence_public_key_sha256",
            "package_execution", "package_execution_runtime_sha256",
            "qualification_record_sha256", "qualified_telemetry_backend_sha256",
            "rootfs_attachment", "scenario_plan_sha256", "scenario_template_sha256",
            "schema_version", "sync_back", "writer_source_sha256",
        ])
        guard canonical == manifestData, Set(value.keys) == keys,
              value["schema_version"] as? String
                == "whoathere.linux_vz_package_execution_image_manifest.v1",
              value["architecture"] as? String == "aarch64",
              value["execution_authority_issued"] as? Bool == true,
              value["package_execution"] as? Bool == true,
              value["sync_back"] as? Bool == false,
              value["external_network"] as? String
                == "host_raw_frame_sinkhole_no_external_route",
              value["rootfs_attachment"] as? String
                == "disposable_clone_virtio_block_read_only" else {
            throw PackageExecutionHarnessError.verification("execution_image_schema")
        }
        let digestKeys = keys.filter { $0.hasSuffix("_sha256") }
        guard digestKeys.allSatisfy({ validSHA256(value[$0] as? String) }) else {
            throw PackageExecutionHarnessError.verification("execution_image_digest")
        }
        func digest(_ key: String) throws -> String {
            guard let digest = value[key] as? String, validSHA256(digest) else {
                throw PackageExecutionHarnessError.verification("execution_image_\(key)")
            }
            return digest
        }
        guard let rootfsByteLength = decimal(value["candidate_runtime_rootfs_byte_length"]),
              let issuedAt = decimal(value["execution_grant_issued_at_unix_seconds"]),
              let expiresAt = decimal(value["execution_grant_expires_at_unix_seconds"]),
              issuedAt < expiresAt, expiresAt - issuedAt <= 600 else {
            throw PackageExecutionHarnessError.verification("execution_image_time")
        }
        let initramfs = directory.appendingPathComponent(
            "whoathere-package-execution-initramfs-virt"
        )
        let image = ExecutionImage(
            manifestData: manifestData,
            manifestSHA256: dataSHA256(manifestData),
            initramfs: initramfs,
            initramfsSHA256: try digest("execution_initramfs_sha256"),
            authorityRequestSHA256: try digest("authority_request_sha256"),
            executionGrantSHA256: try digest("execution_grant_sha256"),
            artifactSHA256: try digest("artifact_sha256"),
            cloneBindingSHA256: try digest("clone_binding_sha256"),
            rootfsSHA256: try digest("candidate_runtime_rootfs_sha256"),
            runtimeManifestSHA256: try digest("candidate_runtime_manifest_sha256"),
            packageRunnerSHA256: try digest("package_execution_runtime_sha256"),
            qualifiedBackendSHA256: try digest("qualified_telemetry_backend_sha256"),
            guestPublicKeySHA256: try digest("guest_evidence_public_key_sha256"),
            hostPublicKeySHA256: try digest("host_evidence_public_key_sha256"),
            expiresAtUnixSeconds: expiresAt
        )
        guard try fileSHA256(baseInitramfs) == digest("base_initramfs_sha256"),
              try fileSHA256(initramfs) == image.initramfsSHA256,
              image.authorityRequestSHA256 == authority.requestSHA256,
              image.executionGrantSHA256 == executionGrantSHA256,
              image.artifactSHA256 == authority.artifactSHA256,
              image.cloneBindingSHA256 == clone.cloneBindingSHA256,
              image.rootfsSHA256 == runtime.measurement.rootfsSHA256,
              rootfsByteLength == runtime.measurement.rootfsByteLength,
              image.runtimeManifestSHA256 == runtime.measurement.runtimeManifestSHA256,
              image.packageRunnerSHA256 == runtime.measurement.packageRunnerSHA256,
              image.qualifiedBackendSHA256 == qualifiedBackendSHA256,
              try fileSHA256(guestPublicKey) == image.guestPublicKeySHA256,
              try fileSHA256(hostPublicKey) == image.hostPublicKeySHA256 else {
            throw PackageExecutionHarnessError.verification("execution_image_binding")
        }
        return image
    }

    private static func invoke(_ executable: URL, arguments: [String], name: String) throws {
        guard try regularNonSymlink(executable) else {
            throw PackageExecutionHarnessError.invalidInput(name)
        }
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        var environment = [
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": ProcessInfo.processInfo.environment["PATH"]
                ?? "/usr/bin:/bin:/usr/sbin:/sbin",
        ]
        for key in ["TMPDIR", "ZIG_GLOBAL_CACHE_DIR", "ZIG_LOCAL_CACHE_DIR"] {
            if let value = ProcessInfo.processInfo.environment[key] { environment[key] = value }
        }
        process.environment = environment
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do { try process.run() } catch {
            throw PackageExecutionHarnessError.builder("\(name)_launch")
        }
        process.waitUntilExit()
        guard process.terminationReason == .exit, process.terminationStatus == 0 else {
            throw PackageExecutionHarnessError.builder(
                "\(name)_exit_\(process.terminationStatus)"
            )
        }
    }

    private static func startVirtualMachine(
        _ machine: VZVirtualMachine,
        queue: DispatchQueue
    ) throws {
        let resultBox = LockedBox<Result<Void, Error>>()
        let completion = DispatchSemaphore(value: 0)
        let machineBox = UncheckedSendableBox(value: machine)
        queue.async {
            machineBox.value.start { result in
                resultBox.store(result.mapError { $0 })
                completion.signal()
            }
        }
        guard completion.wait(timeout: .now() + .seconds(30)) == .success,
              let result = resultBox.load() else {
            throw PackageExecutionHarnessError.vmStart("timeout")
        }
        do { try result.get() } catch {
            throw PackageExecutionHarnessError.vmStart(String(describing: error))
        }
    }

    private static func waitForStop(
        _ machine: VZVirtualMachine,
        queue: DispatchQueue,
        deadline: Date
    ) throws {
        while Date() < deadline {
            if queue.sync(execute: { machine.state == .stopped }) { return }
            Thread.sleep(forTimeInterval: 0.05)
        }
        throw PackageExecutionHarnessError.timeout
    }

    private static func bestEffortStop(
        _ machine: VZVirtualMachine,
        queue: DispatchQueue
    ) -> Bool {
        if queue.sync(execute: { machine.state == .stopped }) { return true }
        let completion = DispatchSemaphore(value: 0)
        let machineBox = UncheckedSendableBox(value: machine)
        queue.async {
            guard machineBox.value.canStop else {
                completion.signal()
                return
            }
            machineBox.value.stop { _ in completion.signal() }
        }
        guard completion.wait(timeout: .now() + .seconds(20)) == .success else {
            return false
        }
        return queue.sync(execute: { machine.state == .stopped })
    }

    private static func hostRawFrameEvidence(
        _ collection: LinuxVzBoundedHostRawFrameCollection
    ) throws -> Data {
        let frames: [[String: Any]] = collection.retainedFrames.enumerated().map { index, frame in
            [
                "frame_index": String(index),
                "byte_length": String(frame.count),
                "sha256": dataSHA256(frame),
                "base64": frame.base64EncodedString(),
            ]
        }
        return try localCanonicalJSONData([
            "authenticated": false,
            "dropped_frame_count": String(collection.droppedFrameCount),
            "healthy": collection.healthy,
            "ingress_frame_count": String(collection.ingressFrameCount),
            "retained_frame_count": String(collection.retainedFrameCount),
            "retained_frames": frames,
            "schema_version": "whoathere.linux_vz_package_execution_raw_frame_observation.v1",
            "terminal": collection.terminal,
            "truncated_frame_count": String(collection.truncatedFrameCount),
        ])
    }

    private static func readBoundedRegularFile(_ url: URL, maximum: Int) throws -> Data {
        let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else {
            throw PackageExecutionHarnessError.invalidInput(url.lastPathComponent)
        }
        defer { close(descriptor) }
        var before = stat()
        guard fstat(descriptor, &before) == 0,
              before.st_mode & S_IFMT == S_IFREG,
              before.st_size > 0,
              UInt64(before.st_size) <= UInt64(maximum) else {
            throw PackageExecutionHarnessError.invalidInput(url.lastPathComponent)
        }
        var data = Data()
        data.reserveCapacity(Int(before.st_size))
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while data.count < Int(before.st_size) {
            let wanted = min(buffer.count, Int(before.st_size) - data.count)
            let count = Darwin.read(descriptor, &buffer, wanted)
            if count > 0 {
                data.append(contentsOf: buffer.prefix(count))
                continue
            }
            if count < 0 && errno == EINTR { continue }
            throw PackageExecutionHarnessError.invalidInput(url.lastPathComponent)
        }
        var extra: UInt8 = 0
        var extraCount: Int
        repeat { extraCount = Darwin.read(descriptor, &extra, 1) }
        while extraCount < 0 && errno == EINTR
        var after = stat()
        guard extraCount == 0, fstat(descriptor, &after) == 0,
              before.st_dev == after.st_dev, before.st_ino == after.st_ino,
              before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec else {
            throw PackageExecutionHarnessError.invalidInput(url.lastPathComponent)
        }
        return data
    }

    private static func fileSHA256(_ url: URL) throws -> String {
        let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else {
            throw PackageExecutionHarnessError.invalidInput(url.lastPathComponent)
        }
        defer { close(descriptor) }
        var before = stat()
        guard fstat(descriptor, &before) == 0,
              before.st_mode & S_IFMT == S_IFREG,
              before.st_size > 0 else {
            throw PackageExecutionHarnessError.invalidInput(url.lastPathComponent)
        }
        var hasher = SHA256()
        var total: Int64 = 0
        var buffer = [UInt8](repeating: 0, count: 1024 * 1024)
        while true {
            let count = Darwin.read(descriptor, &buffer, buffer.count)
            if count > 0 {
                hasher.update(data: Data(buffer.prefix(count)))
                total += Int64(count)
                continue
            }
            if count == 0 { break }
            if errno == EINTR { continue }
            throw PackageExecutionHarnessError.invalidInput(url.lastPathComponent)
        }
        var after = stat()
        guard fstat(descriptor, &after) == 0, total == before.st_size,
              before.st_dev == after.st_dev, before.st_ino == after.st_ino,
              before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec else {
            throw PackageExecutionHarnessError.invalidInput(url.lastPathComponent)
        }
        return "sha256:" + hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    private static func regularNonSymlink(_ url: URL) throws -> Bool {
        var status = stat()
        return lstat(url.path, &status) == 0 && status.st_mode & S_IFMT == S_IFREG
    }

    private static func requireEmptySecureDirectory(_ url: URL) throws {
        var status = stat()
        guard lstat(url.path, &status) == 0,
              status.st_mode & S_IFMT == S_IFDIR,
              status.st_uid == geteuid(), status.st_mode & 0o777 == 0o700,
              try FileManager.default.contentsOfDirectory(atPath: url.path).isEmpty else {
            throw PackageExecutionHarnessError.invalidInput("output_directory")
        }
    }

    private static func createPrivateDirectory(_ url: URL) throws {
        guard mkdir(url.path, 0o700) == 0 else {
            throw PackageExecutionHarnessError.invalidInput("output_directory")
        }
    }

    private static func writeNewPrivateFile(_ url: URL, data: Data) throws {
        let descriptor = open(
            url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600
        )
        guard descriptor >= 0 else {
            throw PackageExecutionHarnessError.invalidInput("output_file")
        }
        defer { close(descriptor) }
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(
                    descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset
                )
                if count > 0 { offset += count; continue }
                if count < 0 && errno == EINTR { continue }
                throw PackageExecutionHarnessError.invalidInput("output_file")
            }
        }
        guard fsync(descriptor) == 0 else {
            throw PackageExecutionHarnessError.invalidInput("output_file")
        }
    }

    private static func openNewPrivateFileHandle(_ url: URL) throws -> FileHandle {
        let descriptor = open(
            url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600
        )
        guard descriptor >= 0 else {
            throw PackageExecutionHarnessError.invalidInput("serial_log")
        }
        return FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    }

    private static func emitFailure(
        reason: String,
        exitCode: Int32,
        progress: ExecutionProgress
    ) {
        var result: [String: Any] = [
            "schema_version": "whoathere.linux_vz_package_execution_result.v1",
            "status": "failed_closed",
            "reason": reason,
            "authoritative_verdict_permitted": false,
            "public_network_route_present": false,
            "package_execution_state": progress.runtimeTerminal
                ?? (progress.vmStarted ? "attempted_unverified" : "not_attempted"),
            "vm_start_attempted": progress.vmStartAttempted,
            "vm_started": progress.vmStarted,
            "vm_stopped": progress.vmStopped,
            "clone_created": progress.cloneCreated,
            "clone_destroyed": progress.cloneDestroyed,
            "sync_back": false,
            "exit_code": Int(exitCode),
        ]
        if let digest = progress.rawFrameEvidenceSHA256 {
            result["host_raw_frame_observation_sha256"] = digest
        }
        emitJSON(result)
    }

    private static func emitJSON(_ fields: [String: Any]) {
        guard let data = try? JSONSerialization.data(
            withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes]
        ) else { return }
        print(String(decoding: data, as: UTF8.self))
    }
}

private func validSHA256(_ value: String?) -> Bool {
    guard let value else { return false }
    return value.utf8.count == 71 && value.hasPrefix("sha256:")
        && value.dropFirst(7).utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
        }
}

private func decimal(_ value: Any?) -> UInt64? {
    guard let value = value as? String, !value.isEmpty,
          value == "0" || value.first != "0",
          value.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) else { return nil }
    return UInt64(value)
}

private func dataSHA256(_ data: Data) -> String {
    "sha256:" + SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

private func localCanonicalJSONData(_ value: Any) throws -> Data {
    try JSONSerialization.data(
        withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes]
    )
}
