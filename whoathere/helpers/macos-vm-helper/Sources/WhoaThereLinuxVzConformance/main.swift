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

private struct Options {
    let kernel: URL
    let initramfs: URL
    let expectedKernelSHA256: String
    let expectedInitramfsSHA256: String
    let expectedPackageSensorFixtureSHA256: String?
    let expectedRuntimeBTFSHA256: String?
    let expectedTaskExitCodeByteOffset: UInt64?
    let expectedRootCoordinatorProbeSHA256: String?
    let expectedRootCoordinatorPublicKeySHA256: String?
    let expectedExecutionRuntimeSHA256: String?
    let expectedExecutionRuntimePublicKeySHA256: String?
    let executionRuntimeRootfs: URL?
    let executionRuntimeManifest: URL?
    let executionRuntimeQualificationImageManifest: URL?
    let expectedExecutionRuntimeRootfsSHA256: String?
    let expectedExecutionRuntimeManifestSHA256: String?
    let expectedExecutionRuntimeQualificationImageManifestSHA256: String?
    let serialLog: URL
    let timeoutSeconds: Int

    static func parse(_ arguments: [String]) throws -> Self {
        var kernel: URL?
        var initramfs: URL?
        var expectedKernelSHA256: String?
        var expectedInitramfsSHA256: String?
        var expectedPackageSensorFixtureSHA256: String?
        var expectedRuntimeBTFSHA256: String?
        var expectedTaskExitCodeByteOffset: UInt64?
        var expectedRootCoordinatorProbeSHA256: String?
        var expectedRootCoordinatorPublicKeySHA256: String?
        var expectedExecutionRuntimeSHA256: String?
        var expectedExecutionRuntimePublicKeySHA256: String?
        var executionRuntimeRootfs: URL?
        var executionRuntimeManifest: URL?
        var executionRuntimeQualificationImageManifest: URL?
        var expectedExecutionRuntimeRootfsSHA256: String?
        var expectedExecutionRuntimeManifestSHA256: String?
        var expectedExecutionRuntimeQualificationImageManifestSHA256: String?
        var serialLog: URL?
        var timeoutSeconds = 30
        var seenOptions = Set<String>()
        var index = 1
        while index < arguments.count {
            let option = arguments[index]
            guard index + 1 < arguments.count else { throw HarnessError.usage }
            guard seenOptions.insert(option).inserted else { throw HarnessError.usage }
            let value = arguments[index + 1]
            switch option {
            case "--kernel": kernel = URL(fileURLWithPath: value)
            case "--initramfs": initramfs = URL(fileURLWithPath: value)
            case "--expected-kernel-sha256": expectedKernelSHA256 = value
            case "--expected-initramfs-sha256": expectedInitramfsSHA256 = value
            case "--expected-package-sensor-fixture-sha256":
                expectedPackageSensorFixtureSHA256 = value
            case "--expected-runtime-btf-sha256": expectedRuntimeBTFSHA256 = value
            case "--expected-task-exit-code-byte-offset":
                guard let parsed = UInt64(value), value == String(parsed), parsed > 0,
                      parsed <= UInt64(Int32.max) else {
                    throw HarnessError.usage
                }
                expectedTaskExitCodeByteOffset = parsed
            case "--expected-root-coordinator-probe-sha256":
                expectedRootCoordinatorProbeSHA256 = value
            case "--expected-root-coordinator-public-key-sha256":
                expectedRootCoordinatorPublicKeySHA256 = value
            case "--expected-execution-runtime-sha256":
                expectedExecutionRuntimeSHA256 = value
            case "--expected-execution-runtime-public-key-sha256":
                expectedExecutionRuntimePublicKeySHA256 = value
            case "--execution-runtime-rootfs":
                executionRuntimeRootfs = URL(fileURLWithPath: value)
            case "--execution-runtime-manifest":
                executionRuntimeManifest = URL(fileURLWithPath: value)
            case "--execution-runtime-qualification-image-manifest":
                executionRuntimeQualificationImageManifest = URL(fileURLWithPath: value)
            case "--expected-execution-runtime-rootfs-sha256":
                expectedExecutionRuntimeRootfsSHA256 = value
            case "--expected-execution-runtime-manifest-sha256":
                expectedExecutionRuntimeManifestSHA256 = value
            case "--expected-execution-runtime-qualification-image-manifest-sha256":
                expectedExecutionRuntimeQualificationImageManifestSHA256 = value
            case "--serial-log": serialLog = URL(fileURLWithPath: value)
            case "--timeout-seconds":
                guard let parsed = Int(value), parsed >= 5, parsed <= 120 else {
                    throw HarnessError.usage
                }
                timeoutSeconds = parsed
            default: throw HarnessError.usage
            }
            index += 2
        }
        let packageSensorMode = expectedPackageSensorFixtureSHA256 != nil
            && expectedRuntimeBTFSHA256 != nil && expectedTaskExitCodeByteOffset != nil
        let packageSensorOptionsAbsent = expectedPackageSensorFixtureSHA256 == nil
            && expectedRuntimeBTFSHA256 == nil && expectedTaskExitCodeByteOffset == nil
        let rootCoordinatorMode = expectedRootCoordinatorProbeSHA256 != nil
            && expectedRootCoordinatorPublicKeySHA256 != nil
        let rootCoordinatorOptionsAbsent = expectedRootCoordinatorProbeSHA256 == nil
            && expectedRootCoordinatorPublicKeySHA256 == nil
        let executionRuntimeMode = expectedExecutionRuntimeSHA256 != nil
            && expectedExecutionRuntimePublicKeySHA256 != nil
        let executionRuntimeOptionsAbsent = expectedExecutionRuntimeSHA256 == nil
            && expectedExecutionRuntimePublicKeySHA256 == nil
        let executionRuntimeRootfsMode = executionRuntimeRootfs != nil
            && executionRuntimeManifest != nil
            && executionRuntimeQualificationImageManifest != nil
            && expectedExecutionRuntimeRootfsSHA256 != nil
            && expectedExecutionRuntimeManifestSHA256 != nil
            && expectedExecutionRuntimeQualificationImageManifestSHA256 != nil
        let executionRuntimeRootfsOptionsAbsent = executionRuntimeRootfs == nil
            && executionRuntimeManifest == nil
            && executionRuntimeQualificationImageManifest == nil
            && expectedExecutionRuntimeRootfsSHA256 == nil
            && expectedExecutionRuntimeManifestSHA256 == nil
            && expectedExecutionRuntimeQualificationImageManifestSHA256 == nil
        guard let kernel, let initramfs, let expectedKernelSHA256,
              let expectedInitramfsSHA256, let serialLog,
              kernel.path.hasPrefix("/"), initramfs.path.hasPrefix("/"),
              serialLog.path.hasPrefix("/"),
              validSHA256(expectedKernelSHA256), validSHA256(expectedInitramfsSHA256),
              expectedPackageSensorFixtureSHA256.map(validSHA256) ?? true,
              expectedRuntimeBTFSHA256.map(validSHA256) ?? true,
              expectedRootCoordinatorProbeSHA256.map(validSHA256) ?? true,
              expectedRootCoordinatorPublicKeySHA256.map(validSHA256) ?? true,
              expectedExecutionRuntimeSHA256.map(validSHA256) ?? true,
              expectedExecutionRuntimePublicKeySHA256.map(validSHA256) ?? true,
              expectedExecutionRuntimeRootfsSHA256.map(validSHA256) ?? true,
              expectedExecutionRuntimeManifestSHA256.map(validSHA256) ?? true,
              expectedExecutionRuntimeQualificationImageManifestSHA256.map(validSHA256) ?? true,
              executionRuntimeRootfs.map({ $0.path.hasPrefix("/") }) ?? true,
              executionRuntimeManifest.map({ $0.path.hasPrefix("/") }) ?? true,
              executionRuntimeQualificationImageManifest.map({ $0.path.hasPrefix("/") }) ?? true,
              packageSensorOptionsAbsent || packageSensorMode,
              rootCoordinatorOptionsAbsent || rootCoordinatorMode,
              executionRuntimeOptionsAbsent || executionRuntimeMode,
              executionRuntimeRootfsOptionsAbsent || executionRuntimeRootfsMode,
              !executionRuntimeRootfsMode || executionRuntimeMode,
              [packageSensorMode, rootCoordinatorMode, executionRuntimeMode]
                .filter({ $0 }).count <= 1 else {
            throw HarnessError.usage
        }
        return Self(
            kernel: kernel,
            initramfs: initramfs,
            expectedKernelSHA256: expectedKernelSHA256,
            expectedInitramfsSHA256: expectedInitramfsSHA256,
            expectedPackageSensorFixtureSHA256: expectedPackageSensorFixtureSHA256,
            expectedRuntimeBTFSHA256: expectedRuntimeBTFSHA256,
            expectedTaskExitCodeByteOffset: expectedTaskExitCodeByteOffset,
            expectedRootCoordinatorProbeSHA256: expectedRootCoordinatorProbeSHA256,
            expectedRootCoordinatorPublicKeySHA256: expectedRootCoordinatorPublicKeySHA256,
            expectedExecutionRuntimeSHA256: expectedExecutionRuntimeSHA256,
            expectedExecutionRuntimePublicKeySHA256:
                expectedExecutionRuntimePublicKeySHA256,
            executionRuntimeRootfs: executionRuntimeRootfs,
            executionRuntimeManifest: executionRuntimeManifest,
            executionRuntimeQualificationImageManifest:
                executionRuntimeQualificationImageManifest,
            expectedExecutionRuntimeRootfsSHA256: expectedExecutionRuntimeRootfsSHA256,
            expectedExecutionRuntimeManifestSHA256: expectedExecutionRuntimeManifestSHA256,
            expectedExecutionRuntimeQualificationImageManifestSHA256:
                expectedExecutionRuntimeQualificationImageManifestSHA256,
            serialLog: serialLog,
            timeoutSeconds: timeoutSeconds
        )
    }
}

private enum HarnessError: Error {
    case usage
    case socketPair
    case serialLog
    case imageDigestMismatch(String)
    case startTimeout
    case startFailed(String)
    case packetSensor
}

@main
private struct LinuxVzConformanceHarness {
    static func main() {
        do {
            let options = try Options.parse(CommandLine.arguments)
            let exitCode = try run(options)
            exit(exitCode)
        } catch HarnessError.usage {
            fputs(
                "usage: whoathere-linux-vz-conformance --kernel PATH --initramfs PATH --expected-kernel-sha256 SHA256 --expected-initramfs-sha256 SHA256 --serial-log PATH [--expected-package-sensor-fixture-sha256 SHA256 --expected-runtime-btf-sha256 SHA256 --expected-task-exit-code-byte-offset DECIMAL | --expected-root-coordinator-probe-sha256 SHA256 --expected-root-coordinator-public-key-sha256 SHA256 | --expected-execution-runtime-sha256 SHA256 --expected-execution-runtime-public-key-sha256 SHA256 [--execution-runtime-rootfs PATH --execution-runtime-manifest PATH --execution-runtime-qualification-image-manifest PATH --expected-execution-runtime-rootfs-sha256 SHA256 --expected-execution-runtime-manifest-sha256 SHA256 --expected-execution-runtime-qualification-image-manifest-sha256 SHA256]] [--timeout-seconds 30]\n",
                stderr
            )
            exit(64)
        } catch {
            emitJSON([
                "schema_version": "whoathere.linux_vz_inert_boot_result.v4",
                "status": "error",
                "reason": String(describing: error),
                "virtualization_supported": VZVirtualMachine.isSupported,
                "external_route": false,
                "package_execution": false,
                "sync_back": false,
                "exit_code": 70
            ])
            exit(70)
        }
    }

    private static func run(_ options: Options) throws -> Int32 {
        let kernelSHA256 = try fileSHA256(options.kernel)
        let initramfsSHA256 = try fileSHA256(options.initramfs)
        guard kernelSHA256 == options.expectedKernelSHA256 else {
            throw HarnessError.imageDigestMismatch("kernel")
        }
        guard initramfsSHA256 == options.expectedInitramfsSHA256 else {
            throw HarnessError.imageDigestMismatch("initramfs")
        }
        let executionRuntimeManifest: ParsedLinuxVzPackageExecutionRuntimeManifest?
        let executionRuntimeQualificationImageManifest:
            ParsedLinuxVzPackageExecutionRuntimeQualificationImageManifest?
        let executionRuntimeRootfsSHA256: String?
        let executionRuntimeManifestSHA256: String?
        let executionRuntimeQualificationImageManifestSHA256: String?
        if let rootfs = options.executionRuntimeRootfs,
           let manifestURL = options.executionRuntimeManifest,
           let qualificationImageManifestURL =
            options.executionRuntimeQualificationImageManifest,
           let expectedRootfsSHA256 = options.expectedExecutionRuntimeRootfsSHA256,
           let expectedManifestSHA256 = options.expectedExecutionRuntimeManifestSHA256,
           let expectedQualificationImageManifestSHA256 =
            options.expectedExecutionRuntimeQualificationImageManifestSHA256,
           let expectedRuntimeSHA256 = options.expectedExecutionRuntimeSHA256,
           let expectedPublicKeySHA256 = options.expectedExecutionRuntimePublicKeySHA256 {
            guard try regularNonSymlinkFile(manifestURL),
                  try regularNonSymlinkFile(qualificationImageManifestURL) else {
                throw HarnessError.imageDigestMismatch("execution_runtime_manifest_metadata")
            }
            let manifestData = try Data(contentsOf: manifestURL)
            let parsed = try decodeLinuxVzPackageExecutionRuntimeManifest(manifestData)
            let qualificationImageManifestData = try Data(
                contentsOf: qualificationImageManifestURL
            )
            let parsedQualificationImageManifest = try
                decodeLinuxVzPackageExecutionRuntimeQualificationImageManifest(
                    qualificationImageManifestData,
                    runtimeManifest: parsed,
                    expectedGuestEvidencePublicKeySHA256: expectedPublicKeySHA256
                )
            let measuredManifestSHA256 = try fileSHA256(manifestURL)
            let measuredQualificationImageManifestSHA256 = try fileSHA256(
                qualificationImageManifestURL
            )
            let measuredRootfsSHA256 = try fileSHA256(rootfs)
            let rootfsValues = try rootfs.resourceValues(forKeys: [.fileSizeKey])
            guard measuredManifestSHA256 == expectedManifestSHA256,
                  parsed.manifestSHA256 == expectedManifestSHA256,
                  measuredQualificationImageManifestSHA256
                    == expectedQualificationImageManifestSHA256,
                  parsedQualificationImageManifest.manifestSHA256
                    == expectedQualificationImageManifestSHA256,
                  parsedQualificationImageManifest.initramfsSHA256 == initramfsSHA256,
                  measuredRootfsSHA256 == expectedRootfsSHA256,
                  parsed.rootfsSHA256 == expectedRootfsSHA256,
                  rootfsValues.fileSize.map(UInt64.init) == parsed.rootfsByteLength,
                  parsed.packageRunnerSHA256 == expectedRuntimeSHA256,
                  !parsed.executionAuthorityPermitted,
                  !parsed.packageExecutionPermitted,
                  !parsed.syncBackPermitted else {
                throw HarnessError.imageDigestMismatch("execution_runtime_manifest_binding")
            }
            executionRuntimeManifest = parsed
            executionRuntimeQualificationImageManifest = parsedQualificationImageManifest
            executionRuntimeRootfsSHA256 = measuredRootfsSHA256
            executionRuntimeManifestSHA256 = measuredManifestSHA256
            executionRuntimeQualificationImageManifestSHA256 =
                measuredQualificationImageManifestSHA256
        } else {
            executionRuntimeManifest = nil
            executionRuntimeQualificationImageManifest = nil
            executionRuntimeRootfsSHA256 = nil
            executionRuntimeManifestSHA256 = nil
            executionRuntimeQualificationImageManifestSHA256 = nil
        }
        try FileManager.default.createDirectory(
            at: options.serialLog.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        guard FileManager.default.createFile(atPath: options.serialLog.path, contents: nil),
              let serialOutput = try? FileHandle(forWritingTo: options.serialLog) else {
            throw HarnessError.serialLog
        }
        defer { try? serialOutput.close() }

        var sockets = [Int32](repeating: -1, count: 2)
        guard socketpair(AF_UNIX, SOCK_DGRAM, 0, &sockets) == 0 else {
            throw HarnessError.socketPair
        }
        defer {
            if sockets[0] >= 0 { close(sockets[0]) }
            if sockets[1] >= 0 { close(sockets[1]) }
        }
        let rawFrameCollector = try LinuxVzBoundedHostRawFrameCollector(capacity: 512)
        let rawFrameCollectionResult = LockedBox<LinuxVzBoundedHostRawFrameCollection>()
        let rawFrameCollectionDone = DispatchSemaphore(value: 0)
        var rawFrameCollectionFinished = false
        let rawFrameDescriptor = sockets[1]
        DispatchQueue.global(qos: .userInitiated).async {
            rawFrameCollectionResult.store(
                rawFrameCollector.collect(fileDescriptor: rawFrameDescriptor)
            )
            rawFrameCollectionDone.signal()
        }
        defer {
            if !rawFrameCollectionFinished {
                rawFrameCollector.requestStop()
                _ = rawFrameCollectionDone.wait(timeout: .now() + .seconds(2))
            }
        }
        let guestNetworkSocket = FileHandle(fileDescriptor: sockets[0], closeOnDealloc: false)
        let configuration: VZVirtualMachineConfiguration
        if let rootfs = options.executionRuntimeRootfs {
            configuration = try buildLinuxVzPackageExecutionRuntimeQualificationVMConfiguration(
                kernelURL: options.kernel,
                initramfsURL: options.initramfs,
                rootfsURL: rootfs,
                serialInput: nil,
                serialOutput: serialOutput,
                rawFrameSocket: guestNetworkSocket
            )
        } else {
            configuration = try buildLinuxVzInertVMConfiguration(
                kernelURL: options.kernel,
                initramfsURL: options.initramfs,
                serialInput: nil,
                serialOutput: serialOutput,
                rawFrameSocket: guestNetworkSocket
            )
        }

        let queue = DispatchQueue(label: "whoathere.linux-vz.inert-vm")
        let virtualMachine = VZVirtualMachine(configuration: configuration, queue: queue)
        let virtualMachineBox = UncheckedSendableBox(value: virtualMachine)
        let startResult = LockedBox<Result<Void, Error>>()
        let started = DispatchSemaphore(value: 0)
        queue.async {
            virtualMachineBox.value.start { result in
                startResult.store(result.mapError { $0 })
                started.signal()
            }
        }
        guard started.wait(timeout: .now() + .seconds(30)) == .success else {
            throw HarnessError.startTimeout
        }
        guard let result = startResult.load() else {
            throw HarnessError.startFailed("missing_start_result")
        }
        do {
            try result.get()
        } catch {
            throw HarnessError.startFailed(String(describing: error))
        }

        let deadline = Date().addingTimeInterval(TimeInterval(options.timeoutSeconds))
        var stopped = false
        while Date() < deadline {
            stopped = queue.sync { virtualMachine.state == .stopped }
            if stopped { break }
            Thread.sleep(forTimeInterval: 0.1)
        }
        if !stopped {
            let stopCompletion = DispatchSemaphore(value: 0)
            queue.async {
                if virtualMachineBox.value.canStop {
                    virtualMachineBox.value.stop { _ in stopCompletion.signal() }
                } else {
                    stopCompletion.signal()
                }
            }
            _ = stopCompletion.wait(timeout: .now() + .seconds(10))
            stopped = queue.sync { virtualMachine.state == .stopped }
        }
        rawFrameCollector.requestStop()
        guard rawFrameCollectionDone.wait(timeout: .now() + .seconds(2)) == .success,
              let rawFrameCollection = rawFrameCollectionResult.load() else {
            throw HarnessError.packetSensor
        }
        rawFrameCollectionFinished = true
        try? serialOutput.synchronize()

        let serialData = (try? Data(contentsOf: options.serialLog)) ?? Data()
        if let serialText = String(data: serialData, encoding: .utf8) {
            fputs(serialText, stderr)
        }
        let markerPresent = linuxVzInertSerialContainsExactMarker(
            serialData,
            marker: linuxVzInertSuccessMarkerV1
        )
        let missingRequiredMarkers = linuxVzInertMissingRequiredEvidenceMarkersV2(serialData)
        let rawFrameCount = rawFrameCollection.ingressFrameCount
        let finalKernelSHA256 = try fileSHA256(options.kernel)
        let finalInitramfsSHA256 = try fileSHA256(options.initramfs)
        let finalExecutionRuntimeRootfsSHA256 = try options.executionRuntimeRootfs.map {
            try fileSHA256($0)
        }
        let finalExecutionRuntimeManifestSHA256 = try options.executionRuntimeManifest.map {
            try fileSHA256($0)
        }
        let finalExecutionRuntimeQualificationImageManifestSHA256 = try options
            .executionRuntimeQualificationImageManifest.map {
                try fileSHA256($0)
            }
        let imageIdentityStable = finalKernelSHA256 == kernelSHA256
            && finalInitramfsSHA256 == initramfsSHA256
            && finalExecutionRuntimeRootfsSHA256 == executionRuntimeRootfsSHA256
            && finalExecutionRuntimeManifestSHA256 == executionRuntimeManifestSHA256
            && finalExecutionRuntimeQualificationImageManifestSHA256
                == executionRuntimeQualificationImageManifestSHA256
        if let expectedRuntimeSHA256 = options.expectedExecutionRuntimeSHA256,
           let expectedPublicKeySHA256 = options.expectedExecutionRuntimePublicKeySHA256 {
            let evidence = try? decodeLinuxVzPackageExecutionRuntimeQualificationEvidenceV1(
                serialData,
                expectedRuntimeSHA256: expectedRuntimeSHA256,
                expectedPublicKeySHA256: expectedPublicKeySHA256
            )
            let rootfsMode = executionRuntimeManifest != nil
            let rootfsMarkers = [
                "WHOATHERE_CAPABILITY execution_runtime_manifest=verified_exact",
                "WHOATHERE_CAPABILITY execution_runtime_rootfs=verified_exact_read_only",
                "WHOATHERE_CAPABILITY execution_runtime_toolchain=verified_exact_unprivileged",
            ]
            var missingMarkers =
                linuxVzPackageExecutionRuntimeQualificationMissingMarkersV1(serialData)
            if rootfsMode {
                let lines = Set(serialData.split(separator: 0x0a).map { rawLine in
                    var line = Array(rawLine)
                    if line.last == 0x0d { line.removeLast() }
                    return String(decoding: line, as: UTF8.self)
                })
                missingMarkers.append(contentsOf: rootfsMarkers.filter { !lines.contains($0) })
            }
            let failurePresent =
                linuxVzPackageExecutionRuntimeQualificationFailurePresentV1(serialData)
            let success = stopped && evidence != nil && missingMarkers.isEmpty
                && !failurePresent && rawFrameCount == 0
                && rawFrameCollection.droppedFrameCount == 0
                && rawFrameCollection.truncatedFrameCount == 0
                && rawFrameCollection.healthy && imageIdentityStable
            emitJSON([
                "schema_version":
                    rootfsMode
                        ? "whoathere.linux_vz_package_execution_runtime_rootfs_qualification_boot_result.v1"
                        : "whoathere.linux_vz_package_execution_runtime_qualification_boot_result.v1",
                "status": success ? "ok" : "error",
                "operation": rootfsMode
                    ? "linux_vz_package_execution_runtime_rootfs_qualification"
                    : "linux_vz_package_execution_runtime_qualification",
                "kernel_sha256": kernelSHA256,
                "initramfs_sha256": initramfsSHA256,
                "runtime_sha256": expectedRuntimeSHA256,
                "runtime_manifest_sha256":
                    executionRuntimeManifest?.manifestSHA256 ?? "unavailable",
                "runtime_qualification_image_manifest_sha256":
                    executionRuntimeQualificationImageManifest?.manifestSHA256
                        ?? "unavailable",
                "runtime_rootfs_sha256":
                    executionRuntimeManifest?.rootfsSHA256 ?? "unavailable",
                "runtime_rootfs_byte_length": String(
                    executionRuntimeManifest?.rootfsByteLength ?? 0
                ),
                "node_executable_sha256":
                    executionRuntimeManifest?.nodeExecutableSHA256 ?? "unavailable",
                "npm_cli_sha256": executionRuntimeManifest?.npmCLISHA256 ?? "unavailable",
                "python_executable_sha256":
                    executionRuntimeManifest?.pythonExecutableSHA256 ?? "unavailable",
                "pip_entrypoint_sha256":
                    executionRuntimeManifest?.pipEntrypointSHA256 ?? "unavailable",
                "guest_evidence_public_key_sha256": expectedPublicKeySHA256,
                "kernel_command_line": linuxVzInertKernelCommandLineV1,
                "network_topology": "host_raw_frame_sinkhole_no_external_route",
                "virtualization_supported": VZVirtualMachine.isSupported,
                "image_identity_stable": imageIdentityStable,
                "vm_stopped": stopped,
                "evidence_valid": evidence != nil,
                "evidence_payload_sha256": evidence?.payloadSHA256 ?? "unavailable",
                "evidence_byte_length": String(evidence?.canonicalJSON.count ?? 0),
                "service_pid": String(evidence?.servicePID ?? 0),
                "runner_pid": String(evidence?.runnerPID ?? 0),
                "runner_thread_count": String(evidence?.threadCount ?? 0),
                "runner_open_descriptor_count": String(
                    evidence?.openDescriptorCount ?? 0
                ),
                "runner_inheritable_capabilities": String(
                    format: "%016llx", evidence?.inheritableCapabilities ?? 0
                ),
                "runner_permitted_capabilities": String(
                    format: "%016llx", evidence?.permittedCapabilities ?? 0
                ),
                "runner_effective_capabilities": String(
                    format: "%016llx", evidence?.effectiveCapabilities ?? 0
                ),
                "runner_bounding_capabilities": String(
                    format: "%016llx", evidence?.boundingCapabilities ?? 0
                ),
                "runner_ambient_capabilities": String(
                    format: "%016llx", evidence?.ambientCapabilities ?? 0
                ),
                "required_marker_count":
                    linuxVzPackageExecutionRuntimeQualificationRequiredMarkersV1.count
                        + (rootfsMode ? rootfsMarkers.count : 0),
                "missing_required_markers": missingMarkers,
                "failure_marker_present": failurePresent,
                "raw_frame_count": rawFrameCount,
                "raw_frame_retained_count": rawFrameCollection.retainedFrameCount,
                "raw_frame_dropped_count": rawFrameCollection.droppedFrameCount,
                "raw_frame_truncated_count": rawFrameCollection.truncatedFrameCount,
                "packet_sensor_healthy": rawFrameCollection.healthy,
                "packet_sensor_terminal": rawFrameCollection.terminal,
                "external_route": false,
                "root_disk_present": rootfsMode,
                "root_disk_read_only": rootfsMode,
                "rootfs_identity_stable": finalExecutionRuntimeRootfsSHA256
                    == executionRuntimeRootfsSHA256,
                "runtime_manifest_identity_stable": finalExecutionRuntimeManifestSHA256
                    == executionRuntimeManifestSHA256,
                "runtime_qualification_image_manifest_identity_stable":
                    finalExecutionRuntimeQualificationImageManifestSHA256
                        == executionRuntimeQualificationImageManifestSHA256,
                "storage_device_count": rootfsMode ? "1" : "0",
                "writable_storage_device_count": "0",
                "directory_share_count": "0",
                "execution_authority_issued": false,
                "execution_grant_consumed": false,
                "execution_request_consumed": false,
                "package_execution": false,
                "malware_execution": false,
                "sync_back": false,
                "exit_code": success ? 0 : 70,
            ])
            return success ? 0 : 70
        }
        if let expectedProbeSHA256 = options.expectedRootCoordinatorProbeSHA256,
           let expectedPublicKeySHA256 = options.expectedRootCoordinatorPublicKeySHA256 {
            let evidence = try? decodeLinuxVzPackageRootCoordinatorEvidenceV1(
                serialData,
                expectedProbeSHA256: expectedProbeSHA256,
                expectedPublicKeySHA256: expectedPublicKeySHA256
            )
            let missingMarkers = linuxVzPackageRootCoordinatorMissingMarkersV1(serialData)
            let failurePresent = linuxVzPackageRootCoordinatorFailurePresentV1(serialData)
            let success = stopped && evidence != nil && missingMarkers.isEmpty
                && !failurePresent && rawFrameCount == 0
                && rawFrameCollection.droppedFrameCount == 0
                && rawFrameCollection.truncatedFrameCount == 0
                && rawFrameCollection.healthy && imageIdentityStable
            emitJSON([
                "schema_version":
                    "whoathere.linux_vz_package_root_coordinator_boot_result.v1",
                "status": success ? "ok" : "error",
                "operation": "linux_vz_package_root_coordinator_qualification",
                "kernel_sha256": kernelSHA256,
                "initramfs_sha256": initramfsSHA256,
                "probe_sha256": expectedProbeSHA256,
                "guest_evidence_public_key_sha256": expectedPublicKeySHA256,
                "kernel_command_line": linuxVzInertKernelCommandLineV1,
                "network_topology": "host_raw_frame_sinkhole_no_external_route",
                "virtualization_supported": VZVirtualMachine.isSupported,
                "image_identity_stable": imageIdentityStable,
                "vm_stopped": stopped,
                "evidence_valid": evidence != nil,
                "evidence_payload_sha256": evidence?.payloadSHA256 ?? "unavailable",
                "evidence_byte_length": String(evidence?.canonicalJSON.count ?? 0),
                "service_pid": String(evidence?.servicePID ?? 0),
                "runner_pid": String(evidence?.runnerPID ?? 0),
                "runner_thread_count": String(evidence?.threadCount ?? 0),
                "runner_open_descriptor_count": String(evidence?.openDescriptorCount ?? 0),
                "runner_inheritable_capabilities": String(
                    format: "%016llx", evidence?.inheritableCapabilities ?? 0
                ),
                "runner_permitted_capabilities": String(
                    format: "%016llx", evidence?.permittedCapabilities ?? 0
                ),
                "runner_effective_capabilities": String(
                    format: "%016llx", evidence?.effectiveCapabilities ?? 0
                ),
                "runner_bounding_capabilities": String(
                    format: "%016llx", evidence?.boundingCapabilities ?? 0
                ),
                "runner_ambient_capabilities": String(
                    format: "%016llx", evidence?.ambientCapabilities ?? 0
                ),
                "required_marker_count": linuxVzPackageRootCoordinatorRequiredMarkersV1.count,
                "missing_required_markers": missingMarkers,
                "failure_marker_present": failurePresent,
                "raw_frame_count": rawFrameCount,
                "raw_frame_retained_count": rawFrameCollection.retainedFrameCount,
                "raw_frame_dropped_count": rawFrameCollection.droppedFrameCount,
                "raw_frame_truncated_count": rawFrameCollection.truncatedFrameCount,
                "packet_sensor_healthy": rawFrameCollection.healthy,
                "packet_sensor_terminal": rawFrameCollection.terminal,
                "external_route": false,
                "root_disk_present": false,
                "storage_device_count": "0",
                "directory_share_count": "0",
                "package_execution": false,
                "malware_execution": false,
                "sync_back": false,
                "exit_code": success ? 0 : 70,
            ])
            return success ? 0 : 70
        }
        if let expectedFixtureSHA256 = options.expectedPackageSensorFixtureSHA256,
           let expectedRuntimeBTFSHA256 = options.expectedRuntimeBTFSHA256,
           let expectedTaskExitCodeByteOffset = options.expectedTaskExitCodeByteOffset {
            let evidence = try? decodeLinuxVzPackageSensorBpfInertEvidenceV13(
                serialData,
                expectedFixtureSHA256: expectedFixtureSHA256,
                expectedRuntimeBTFSHA256: expectedRuntimeBTFSHA256,
                expectedTaskExitCodeByteOffset: expectedTaskExitCodeByteOffset
            )
            let missingMarkers = linuxVzPackageSensorBpfInertMissingMarkersV1(serialData)
            let failurePresent = linuxVzPackageSensorBpfInertFailurePresentV1(serialData)
            let hostUDPSendtoEvidence: LinuxVzPackageHostUDPSendtoEvidenceV1? = if let evidence {
                try? makeLinuxVzPackageHostUDPSendtoEvidenceV1(
                    expected: LinuxVzPackageExpectedHostUDPSendtoV1(
                        rootNetworkEvidenceSHA256: evidence.rootNetworkEvidenceSHA256,
                        processEvidenceSHA256: evidence.rootProcessEvidenceSHA256,
                        sensorSessionChallengeSHA256: evidence.sensorSessionChallengeSHA256,
                        destinationTokenSHA256: evidence.networkSendtoDestinationTokenSHA256,
                        egressPacketCorrelationSHA256:
                            evidence.egressPacketCorrelationSHA256,
                        destinationClass: .documentation,
                        destinationPort: 40_553,
                        enterSourceSequence: evidence.networkSendtoEnterSourceSequence,
                        syscallResult: evidence.networkSendtoResult
                    ),
                    collection: rawFrameCollection,
                    expectedSourceMAC: linuxVzInertGuestNetworkMACV1
                )
            } else {
                nil
            }
            let success = stopped && evidence != nil && hostUDPSendtoEvidence != nil
                && missingMarkers.isEmpty && !failurePresent && rawFrameCount == 1
                && rawFrameCollection.droppedFrameCount == 0
                && rawFrameCollection.truncatedFrameCount == 0
                && rawFrameCollection.healthy && imageIdentityStable
            emitJSON([
                "schema_version":
                    "whoathere.linux_vz_package_sensor_bpf_inert_boot_result.v3",
                "status": success ? "ok" : "error",
                "operation": "linux_vz_package_sensor_bpf_inert_qualification",
                "kernel_sha256": kernelSHA256,
                "initramfs_sha256": initramfsSHA256,
                "fixture_sha256": expectedFixtureSHA256,
                "runtime_btf_sha256": evidence?.runtimeBTFSHA256 ?? "unavailable",
                "task_exit_code_byte_offset": String(evidence?.taskExitCodeByteOffset ?? 0),
                "kernel_exit_wait_status": String(evidence?.kernelExitWaitStatus ?? 0),
                "waitpid_wait_status": String(evidence?.waitpidWaitStatus ?? 0),
                "kernel_command_line": linuxVzInertKernelCommandLineV1,
                "network_topology": "host_raw_frame_sinkhole_no_external_route",
                "virtualization_supported": VZVirtualMachine.isSupported,
                "image_identity_stable": imageIdentityStable,
                "vm_stopped": stopped,
                "evidence_valid": evidence != nil,
                "evidence_payload_sha256": evidence?.payloadSHA256 ?? "unavailable",
                "evidence_byte_length": String(evidence?.evidenceByteLength ?? 0),
                "root_process_evidence_sha256":
                    evidence?.rootProcessEvidenceSHA256 ?? "unavailable",
                "root_process_evidence_byte_length": String(
                    evidence?.rootProcessEvidenceByteLength ?? 0
                ),
                "root_process_evidence_source_event_count": String(
                    evidence?.rootProcessEvidenceSourceEventCount ?? 0
                ),
                "root_process_evidence_observation_count": String(
                    evidence?.rootProcessEvidenceObservationCount ?? 0
                ),
                "root_network_evidence_sha256":
                    evidence?.rootNetworkEvidenceSHA256 ?? "unavailable",
                "root_network_evidence_byte_length": String(
                    evidence?.rootNetworkEvidenceByteLength ?? 0
                ),
                "root_network_evidence_event_count": String(
                    evidence?.rootNetworkEvidenceEventCount ?? 0
                ),
                "root_network_evidence_unobserved_capabilities":
                    evidence?.rootNetworkEvidenceUnobservedCapabilities ?? [],
                "host_udp_sendto_evidence_valid": hostUDPSendtoEvidence != nil,
                "host_udp_sendto_evidence_sha256":
                    hostUDPSendtoEvidence?.payloadSHA256 ?? "unavailable",
                "host_udp_sendto_frame_sha256":
                    hostUDPSendtoEvidence?.frameSHA256 ?? "unavailable",
                "host_udp_sendto_source_port": String(
                    hostUDPSendtoEvidence?.sourcePort ?? 0
                ),
                "host_udp_sendto_destination_port": String(
                    hostUDPSendtoEvidence?.destinationPort ?? 0
                ),
                "host_udp_sendto_payload_byte_count": String(
                    hostUDPSendtoEvidence?.payloadByteCount ?? 0
                ),
                "host_udp_sendto_selected_correlation_complete":
                    hostUDPSendtoEvidence?.selectedCorrelationComplete ?? false,
                "host_udp_sendto_broad_frame_coverage_complete":
                    hostUDPSendtoEvidence?.broadHostFrameCoverageComplete ?? false,
                "root_file_evidence_sha256":
                    evidence?.rootFileEvidenceSHA256 ?? "unavailable",
                "root_file_evidence_byte_length": String(
                    evidence?.rootFileEvidenceByteLength ?? 0
                ),
                "root_file_evidence_source_event_count": String(
                    evidence?.rootFileEvidenceSourceEventCount ?? 0
                ),
                "root_file_evidence_change_count": String(
                    evidence?.rootFileEvidenceChangeCount ?? 0
                ),
                "root_file_fanotify_mark_scope": evidence?.fileFanotifyMarkScope ?? [],
                "root_file_fanotify_unobserved_mounts":
                    evidence?.fileFanotifyUnobservedMounts ?? [],
                "root_file_global_mount_coverage_complete":
                    evidence?.fileGlobalMountCoverageComplete ?? false,
                "network_intent_count": String(evidence?.networkIntentCount ?? 0),
                "cgroup_id": String(evidence?.cgroupID ?? 0),
                "fixture_pid": String(evidence?.fixturePID ?? 0),
                "tracepoint_format_sha256": evidence?.tracepointFormatSHA256 ?? [:],
                "required_marker_count": linuxVzPackageSensorBpfInertRequiredMarkersV1.count,
                "missing_required_markers": missingMarkers,
                "failure_marker_present": failurePresent,
                "raw_frame_count": rawFrameCount,
                "raw_frame_retained_count": rawFrameCollection.retainedFrameCount,
                "raw_frame_dropped_count": rawFrameCollection.droppedFrameCount,
                "raw_frame_truncated_count": rawFrameCollection.truncatedFrameCount,
                "packet_sensor_healthy": rawFrameCollection.healthy,
                "packet_sensor_terminal": rawFrameCollection.terminal,
                "external_route": false,
                "root_disk_present": false,
                "storage_device_count": "0",
                "directory_share_count": "0",
                "package_execution": false,
                "malware_execution": false,
                "sync_back": false,
                "exit_code": success ? 0 : 70,
            ])
            return success ? 0 : 70
        }
        let processSensorMarkerPresent = linuxVzInertSerialContainsExactMarker(
            serialData,
            marker: "WHOATHERE_SENSOR_PROCESS_PROBE_OK"
        )
        let processEvidence = try? decodeLinuxVzProcessEvidencePayloadV1(serialData)
        let success = stopped && markerPresent && processSensorMarkerPresent
            && processEvidence != nil && missingRequiredMarkers.isEmpty && rawFrameCount == 0
            && rawFrameCollection.droppedFrameCount == 0
            && rawFrameCollection.truncatedFrameCount == 0
            && rawFrameCollection.healthy && imageIdentityStable
        emitJSON([
            "schema_version": "whoathere.linux_vz_inert_boot_result.v4",
            "status": success ? "ok" : "error",
            "operation": "linux_vz_inert_boot",
            "kernel_sha256": kernelSHA256,
            "initramfs_sha256": initramfsSHA256,
            "kernel_command_line": linuxVzInertKernelCommandLineV1,
            "network_topology": "host_raw_frame_sinkhole_no_external_route",
            "virtualization_supported": VZVirtualMachine.isSupported,
            "image_identity_stable": imageIdentityStable,
            "vm_stopped": stopped,
            "inert_marker_present": markerPresent,
            "process_sensor_marker_present": processSensorMarkerPresent,
            "process_evidence_valid": processEvidence != nil,
            "process_evidence_payload_sha256": processEvidence?.payloadSHA256 ?? "unavailable",
            "process_evidence_byte_length": String(processEvidence?.evidenceByteLength ?? 0),
            "process_event_sequence_start": String(processEvidence?.eventSequenceStart ?? 0),
            "process_event_sequence_end": String(processEvidence?.eventSequenceEnd ?? 0),
            "process_event_count": String(processEvidence?.eventCount ?? 0),
            "process_heartbeat_count": String(processEvidence?.heartbeatCount ?? 0),
            "process_dropped_event_count": String(processEvidence?.droppedEventCount ?? 0),
            "process_descendant_teardown_complete":
                processEvidence?.descendantTeardownComplete ?? false,
            "required_platform_capability_count": linuxVzInertRequiredCapabilityMarkersV1.count,
            "required_process_sensor_marker_count": linuxVzInertProcessSensorMarkersV2.count,
            "missing_required_markers": missingRequiredMarkers,
            "raw_frame_count": rawFrameCount,
            "raw_frame_retained_count": rawFrameCollection.retainedFrameCount,
            "raw_frame_dropped_count": rawFrameCollection.droppedFrameCount,
            "raw_frame_truncated_count": rawFrameCollection.truncatedFrameCount,
            "packet_sensor_healthy": rawFrameCollection.healthy,
            "packet_sensor_terminal": rawFrameCollection.terminal,
            "external_route": false,
            "package_execution": false,
            "sync_back": false,
            "exit_code": success ? 0 : 70
        ])
        return success ? 0 : 70
    }

    private static func fileSHA256(_ url: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hasher = SHA256()
        while true {
            let chunk = try handle.read(upToCount: 1024 * 1024) ?? Data()
            if chunk.isEmpty { break }
            hasher.update(data: chunk)
        }
        return "sha256:" + hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    private static func emitJSON(_ fields: [String: Any]) {
        guard let data = try? JSONSerialization.data(
            withJSONObject: fields,
            options: [.sortedKeys, .withoutEscapingSlashes]
        ),
              let text = String(data: data, encoding: .utf8) else {
            return
        }
        print(text)
    }
}

private func validSHA256(_ value: String) -> Bool {
    guard value.utf8.count == 71, value.hasPrefix("sha256:") else { return false }
    return value.dropFirst(7).utf8.allSatisfy { byte in
        (byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102)
    }
}

private func regularNonSymlinkFile(_ url: URL) throws -> Bool {
    let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
    return values.isRegularFile == true && values.isSymbolicLink != true
}
