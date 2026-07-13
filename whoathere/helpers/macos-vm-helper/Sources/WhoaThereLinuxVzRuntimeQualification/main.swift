import CryptoKit
import Darwin
import Foundation
@preconcurrency import Virtualization
import WhoaThereMacosVmHelperCore

private let runtimeQualificationPort: UInt32 = 40_554

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

private struct ZeroFrameCollection: Sendable {
    let frameCount: UInt64
    let healthy: Bool
}

private final class ZeroFrameCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var stopRequested = false

    func requestStop() {
        lock.lock()
        stopRequested = true
        lock.unlock()
    }

    func run(fileDescriptor: Int32) -> ZeroFrameCollection {
        var frameCount: UInt64 = 0
        var healthy = true
        var buffer = [UInt8](repeating: 0, count: 65_535)
        while true {
            let received = recv(fileDescriptor, &buffer, buffer.count, MSG_DONTWAIT)
            if received >= 0 {
                frameCount += 1
                continue
            }
            if errno != EAGAIN && errno != EWOULDBLOCK {
                healthy = false
                break
            }
            lock.lock()
            let stop = stopRequested
            lock.unlock()
            if stop { break }
            usleep(1_000)
        }
        return ZeroFrameCollection(frameCount: frameCount, healthy: healthy)
    }
}

private enum QualificationHarnessError: Error, CustomStringConvertible {
    case usage
    case invalidInput(String)
    case requestBuilder(String)
    case socketPair
    case vmStart(String)
    case vmStop
    case timeout(String)
    case socketIO
    case verification(String)

    var description: String {
        switch self {
        case .usage: return "usage"
        case .invalidInput(let value): return "invalid_input_\(value)"
        case .requestBuilder(let value): return "request_builder_\(value)"
        case .socketPair: return "raw_frame_socket_pair_failed"
        case .vmStart(let value): return "vm_start_\(value)"
        case .vmStop: return "vm_stop_unproven"
        case .timeout(let value): return "timeout_\(value)"
        case .socketIO: return "vsock_io_failed"
        case .verification(let value): return "verification_\(value)"
        }
    }
}

private struct Options {
    let requestBuilder: URL
    let qualifiedBackend: URL
    let backendIdentity: URL
    let runtimeDirectory: URL
    let qualificationImage: URL
    let guestPublicKey: URL
    let hostSigningSeed: URL
    let outputDirectory: URL
    let timeoutSeconds: Int

    init(arguments: [String]) throws {
        var values: [String: String] = [:]
        var index = 1
        let accepted = Set([
            "--request-builder", "--qualified-backend", "--backend-identity",
            "--runtime-directory", "--qualification-image", "--guest-public-key",
            "--host-signing-seed", "--output-directory", "--timeout-seconds"
        ])
        while index < arguments.count {
            let key = arguments[index]
            guard accepted.contains(key), values[key] == nil, index + 1 < arguments.count else {
                throw QualificationHarnessError.usage
            }
            values[key] = arguments[index + 1]
            index += 2
        }
        let required = accepted.subtracting(["--timeout-seconds"])
        guard required.allSatisfy({ values[$0] != nil }),
              values.keys.allSatisfy(accepted.contains),
              let timeout = Int(values["--timeout-seconds"] ?? "60"),
              timeout >= 15, timeout <= 300 else {
            throw QualificationHarnessError.usage
        }
        for key in required {
            guard values[key]!.hasPrefix("/") else {
                throw QualificationHarnessError.usage
            }
        }
        requestBuilder = URL(fileURLWithPath: values["--request-builder"]!)
        qualifiedBackend = URL(fileURLWithPath: values["--qualified-backend"]!)
        backendIdentity = URL(fileURLWithPath: values["--backend-identity"]!)
        runtimeDirectory = URL(fileURLWithPath: values["--runtime-directory"]!, isDirectory: true)
        qualificationImage = URL(
            fileURLWithPath: values["--qualification-image"]!, isDirectory: true
        )
        guestPublicKey = URL(fileURLWithPath: values["--guest-public-key"]!)
        hostSigningSeed = URL(fileURLWithPath: values["--host-signing-seed"]!)
        outputDirectory = URL(
            fileURLWithPath: values["--output-directory"]!, isDirectory: true
        )
        timeoutSeconds = timeout
    }
}

private struct QualificationImage {
    let manifestData: Data
    let manifestSHA256: String
    let kernel: URL
    let initramfs: URL
    let agent: URL
    let guestInit: URL
    let moduleBundle: URL
    let kernelSHA256: String
    let initramfsSHA256: String
    let agentSHA256: String
    let guestInitSHA256: String
    let moduleBundleSHA256: String
    let baseInitramfsSHA256: String
    let guestSignerSHA256: String
    let protectedSensorSHA256: String
    let runtimeRootfsSHA256: String
    let runtimeRootfsByteLength: UInt64
    let runtimeManifestSHA256: String
    let packageRunnerSHA256: String
}

@main
private enum RuntimeQualificationMain {
    static func main() {
        do {
            let options = try Options(arguments: CommandLine.arguments)
            let result = try run(options)
            emitJSON(result)
            exit(0)
        } catch QualificationHarnessError.usage {
            fputs(
                "usage: whoathere-linux-vz-runtime-qualification --request-builder PATH --qualified-backend PATH --backend-identity PATH --runtime-directory PATH --qualification-image PATH --guest-public-key PATH --host-signing-seed PATH --output-directory PATH [--timeout-seconds 60]\n",
                stderr
            )
            emitFailure(reason: "usage", exitCode: 64)
            exit(64)
        } catch {
            emitFailure(reason: String(describing: error), exitCode: 70)
            exit(70)
        }
    }

    private static func run(_ options: Options) throws -> [String: Any] {
        try requireSecureOutputDirectory(options.outputDirectory)
        let image = try loadQualificationImage(options.qualificationImage)
        let qualifiedData = try readBoundedRegularFile(options.qualifiedBackend, maximum: 16 << 20)
        let qualified = try decodeLinuxVzTelemetryQualificationRecord(qualifiedData)
        let backendData = try readBoundedRegularFile(
            options.backendIdentity,
            maximum: maximumLinuxVzTelemetryBackendIdentityBytesV1
        )
        let backend = try decodeUnqualifiedLinuxVzTelemetryBackendIdentity(
            backendData,
            expectedTelemetryRequirementsSHA256: qualified.telemetryRequirementsSHA256
        )
        guard qualified.backendIdentitySHA256 == backend.identitySHA256 else {
            throw QualificationHarnessError.verification("qualified_backend_identity")
        }

        let runtimeLayout = LinuxVzPackageRuntimeBaseLayout(
            runtimeDirectory: options.runtimeDirectory
        )
        let runtimeManifestData = try readBoundedRegularFile(
            runtimeLayout.runtimeManifestURL,
            maximum: maximumLinuxVzPackageRuntimeManifestBytesV1
        )
        let runtimeManifest = try decodeLinuxVzPackageRuntimeManifest(runtimeManifestData)
        let base = try verifyAndLockLinuxVzPackageRuntimeBase(
            layout: runtimeLayout,
            expectedRootfsSHA256: runtimeManifest.rootfsSHA256,
            expectedRootfsByteLength: runtimeManifest.rootfsByteLength,
            expectedRuntimeManifestSHA256: runtimeManifest.manifestSHA256,
            expectedPackageRunnerSHA256: runtimeManifest.packageRunnerSHA256
        )
        let clone = try base.createDisposableClone()
        var virtualMachine: VZVirtualMachine?
        var vmQueue: DispatchQueue?
        var vmStopped = true
        var cloneDestroyed = false
        defer {
            if !vmStopped, let virtualMachine, let vmQueue {
                vmStopped = bestEffortStop(virtualMachine: virtualMachine, queue: vmQueue)
            }
            if vmStopped {
                if (try? clone.cleanup()) != nil { cloneDestroyed = true }
            } else {
                clone.preserveUntilVerifiedVMStop()
            }
        }

        let cloneBindingURL = options.outputDirectory.appendingPathComponent(
            "runtime-qualification-clone-binding.json"
        )
        try writeNewPrivateFile(cloneBindingURL, data: clone.cloneBindingCanonicalJSON)
        try invokeRequestBuilder(
            options: options,
            runtimeLayout: runtimeLayout,
            cloneBinding: cloneBindingURL
        )
        let requestURL = options.outputDirectory.appendingPathComponent(
            "runtime-qualification-request.json"
        )
        let requestFrameURL = options.outputDirectory.appendingPathComponent(
            "runtime-qualification-request.bin"
        )
        let requestData = try readBoundedRegularFile(
            requestURL,
            maximum: maximumLinuxVzPackageRuntimeQualificationRequestBytesV1
        )
        let requestFrame = try readBoundedRegularFile(
            requestFrameURL,
            maximum: maximumLinuxVzRuntimeQualificationRequestFrameBytesV1
        )
        guard try decodeLinuxVzPackageRuntimeQualificationRequestFrame(requestFrame)
                == requestData else {
            throw QualificationHarnessError.verification("request_frame")
        }
        let request = try decodeLinuxVzPackageRuntimeQualificationRequest(requestData)
        let guestPublicKey = try readBoundedRegularFile(options.guestPublicKey, maximum: 32)
        guard guestPublicKey.count == 32 else {
            throw QualificationHarnessError.invalidInput("guest_public_key")
        }
        try verifyRequestContext(
            request: request,
            qualified: qualified,
            backend: backend,
            runtimeManifest: runtimeManifest,
            base: base,
            clone: clone,
            image: image,
            guestPublicKey: guestPublicKey
        )

        let serialLog = options.outputDirectory.appendingPathComponent(
            "runtime-qualification-serial.log"
        )
        let serialOutput = try openNewPrivateFileHandle(serialLog)
        defer { try? serialOutput.close() }
        var sockets = [Int32](repeating: -1, count: 2)
        guard socketpair(AF_UNIX, SOCK_DGRAM, 0, &sockets) == 0 else {
            throw QualificationHarnessError.socketPair
        }
        defer {
            if sockets[0] >= 0 { close(sockets[0]) }
            if sockets[1] >= 0 { close(sockets[1]) }
        }
        let collector = ZeroFrameCollector()
        let collectionBox = LockedBox<ZeroFrameCollection>()
        let collectionDone = DispatchSemaphore(value: 0)
        var collectionFinished = false
        let hostFrameDescriptor = sockets[1]
        DispatchQueue.global(qos: .userInitiated).async {
            collectionBox.store(collector.run(fileDescriptor: hostFrameDescriptor))
            collectionDone.signal()
        }
        defer {
            if !collectionFinished {
                collector.requestStop()
                _ = collectionDone.wait(timeout: .now() + .seconds(2))
            }
        }

        let networkHandle = FileHandle(fileDescriptor: sockets[0], closeOnDealloc: false)
        let configuration = try buildLinuxVzPackageRuntimeVMConfiguration(
            kernelURL: image.kernel,
            initramfsURL: image.initramfs,
            clone: clone,
            serialInput: nil,
            serialOutput: serialOutput,
            rawFrameSocket: networkHandle
        )
        let queue = DispatchQueue(label: "whoathere.linux-vz.runtime-qualification")
        let machine = VZVirtualMachine(configuration: configuration, queue: queue)
        virtualMachine = machine
        vmQueue = queue
        vmStopped = false
        try startVirtualMachine(machine, queue: queue)
        let deadline = Date().addingTimeInterval(TimeInterval(options.timeoutSeconds))
        try waitForMarker(
            "WHOATHERE_RUNTIME_QUALIFICATION_READY port=40554",
            virtualMachine: machine,
            queue: queue,
            serialOutput: serialOutput,
            serialLog: serialLog,
            deadline: deadline
        )
        let connection = try connect(
            virtualMachine: machine,
            queue: queue,
            port: runtimeQualificationPort
        )
        try setSocketTimeouts(connection.fileDescriptor)
        try writeAll(connection.fileDescriptor, data: requestFrame)
        guard shutdown(connection.fileDescriptor, SHUT_WR) == 0 else {
            throw QualificationHarnessError.socketIO
        }
        let responseFrame = try readToEOF(
            connection.fileDescriptor,
            maximum: maximumLinuxVzRuntimeQualificationResponseFrameBytesV1
        )
        connection.close()
        let response = try decodeLinuxVzPackageRuntimeQualificationResponse(responseFrame)
        let verifiedGuest = try verifyLinuxVzPackageRuntimeQualificationReceipt(
            response: response,
            request: request,
            guestVerifyingKey: guestPublicKey
        )
        try waitForStop(machine, queue: queue, deadline: deadline)
        vmStopped = true
        collector.requestStop()
        guard collectionDone.wait(timeout: .now() + .seconds(2)) == .success,
              let frames = collectionBox.load() else {
            throw QualificationHarnessError.verification("packet_sensor_completion")
        }
        collectionFinished = true
        try serialOutput.synchronize()
        let serialData = try readBoundedRegularFile(serialLog, maximum: 4 << 20)
        try verifySerial(
            serialData,
            request: request,
            guestReceipt: response.guestReceipt
        )
        guard frames.healthy, frames.frameCount == 0 else {
            throw QualificationHarnessError.verification("unexpected_raw_frames")
        }
        try clone.verifyReadyForAttachment()
        let finalImage = try loadQualificationImage(options.qualificationImage)
        guard finalImage.manifestSHA256 == image.manifestSHA256,
              finalImage.kernelSHA256 == image.kernelSHA256,
              finalImage.initramfsSHA256 == image.initramfsSHA256,
              finalImage.agentSHA256 == image.agentSHA256,
              finalImage.guestInitSHA256 == image.guestInitSHA256,
              finalImage.moduleBundleSHA256 == image.moduleBundleSHA256 else {
            throw QualificationHarnessError.verification("image_identity_changed")
        }
        try clone.cleanup()
        cloneDestroyed = true

        let hostEvidence = try makeLinuxVzPackageRuntimeQualificationHostEvidence(
            request: request,
            requestFrame: requestFrame,
            responseFrame: responseFrame,
            response: response,
            serialLogSHA256: dataSHA256(serialData),
            rawFrameCount: frames.frameCount,
            droppedFrameCount: 0,
            packetSensorHealthy: frames.healthy,
            guestChannelTerminated: true,
            vmStarted: true,
            vmStopped: vmStopped,
            cloneDestroyed: cloneDestroyed,
            imageIdentityStable: true
        )
        var hostSigningSeed = try readProtectedSeed(options.hostSigningSeed)
        let hostPublicKey: Data
        do {
            hostPublicKey = try Curve25519.Signing.PrivateKey(
                rawRepresentation: hostSigningSeed
            ).publicKey.rawRepresentation
        } catch {
            hostSigningSeed.resetBytes(in: 0..<hostSigningSeed.count)
            throw QualificationHarnessError.invalidInput("host_signing_seed")
        }
        let hostReceipt = try signLinuxVzPackageRuntimeQualificationHostReceipt(
            request: request,
            evidence: hostEvidence,
            signingSeed: &hostSigningSeed
        )
        let verifiedHost = try verifyLinuxVzPackageRuntimeQualificationHostReceipt(
            hostReceipt,
            request: request,
            evidence: hostEvidence,
            hostVerifyingKey: hostPublicKey
        )
        guard !verifiedGuest.packageExecutionAuthorityPermitted,
              !verifiedGuest.syncBackPermitted,
              !verifiedHost.executionAuthorityPermitted,
              !verifiedHost.packageExecutionPermitted,
              !verifiedHost.syncBackPermitted else {
            throw QualificationHarnessError.verification("authority_elevation")
        }

        try writeNewPrivateFile(
            options.outputDirectory.appendingPathComponent(
                "runtime-qualification-response.bin"
            ),
            data: responseFrame
        )
        try writeNewPrivateFile(
            options.outputDirectory.appendingPathComponent(
                "runtime-qualification-process-evidence.json"
            ),
            data: response.processEvidence
        )
        try writeNewPrivateFile(
            options.outputDirectory.appendingPathComponent(
                "runtime-qualification-guest-receipt.json"
            ),
            data: response.guestReceipt
        )
        try writeNewPrivateFile(
            options.outputDirectory.appendingPathComponent(
                "runtime-qualification-host-evidence.json"
            ),
            data: hostEvidence.canonicalJSON
        )
        try writeNewPrivateFile(
            options.outputDirectory.appendingPathComponent(
                "runtime-qualification-host-receipt.json"
            ),
            data: hostReceipt
        )
        return [
            "schema_version": "whoathere.linux_vz_runtime_qualification_result.v1",
            "status": "qualified_inert_runtime",
            "qualification_request_sha256": request.requestSHA256,
            "qualified_telemetry_backend_sha256": request.qualifiedTelemetryBackendSHA256,
            "runtime_qualification_initramfs_sha256": image.initramfsSHA256,
            "candidate_runtime_rootfs_sha256": request.candidateRuntimeRootfsSHA256,
            "guest_receipt_sha256": dataSHA256(response.guestReceipt),
            "host_evidence_sha256": hostEvidence.evidenceSHA256,
            "host_receipt_sha256": dataSHA256(hostReceipt),
            "raw_frame_count": "0",
            "vm_stopped": true,
            "clone_destroyed": true,
            "execution_authority": false,
            "package_execution": false,
            "external_route": false,
            "sync_back": false
        ]
    }

    private static func verifyRequestContext(
        request: ParsedLinuxVzPackageRuntimeQualificationRequest,
        qualified: ParsedLinuxVzTelemetryQualificationRecord,
        backend: UnqualifiedLinuxVzTelemetryBackendIdentity,
        runtimeManifest: ParsedLinuxVzPackageRuntimeManifest,
        base: LockedLinuxVzPackageRuntimeBase,
        clone: DisposableLinuxVzPackageRuntimeClone,
        image: QualificationImage,
        guestPublicKey: Data
    ) throws {
        guard request.qualifiedTelemetryBackendSHA256 == qualified.recordSHA256,
              request.backendIdentitySHA256 == qualified.backendIdentitySHA256,
              request.backendIdentitySHA256 == backend.identitySHA256,
              request.telemetryRequirementsSHA256 == qualified.telemetryRequirementsSHA256,
              request.telemetryRequirementsSHA256 == backend.telemetryRequirementsSHA256,
              request.conformanceEvidenceSetSHA256 == qualified.conformanceEvidenceSetSHA256,
              request.kernelImageSHA256 == backend.kernelImageSHA256,
              request.kernelImageSHA256 == image.kernelSHA256,
              request.qualifiedInitramfsSHA256 == backend.initramfsSHA256,
              request.qualifiedInitramfsSHA256 == image.baseInitramfsSHA256,
              request.qualifiedGuestSignerSHA256 == backend.guestSensorSHA256,
              request.qualifiedGuestSignerSHA256 == image.guestSignerSHA256,
              request.qualifiedProtectedSensorSHA256 == backend.guestBPFBundleSHA256,
              request.qualifiedProtectedSensorSHA256 == image.protectedSensorSHA256,
              request.guestEvidencePublicKeySHA256 == backend.guestEvidencePublicKeySHA256,
              request.guestEvidencePublicKeySHA256 == dataSHA256(guestPublicKey),
              request.hostEvidencePublicKeySHA256 == backend.hostEvidencePublicKeySHA256,
              request.runtimeQualificationInitramfsSHA256 == image.initramfsSHA256,
              request.runtimeQualificationGuestAgentSHA256 == image.agentSHA256,
              request.runtimeQualificationGuestInitSHA256 == image.guestInitSHA256,
              request.runtimeQualificationModuleBundleSHA256 == image.moduleBundleSHA256,
              request.candidateRuntimeRootfsSHA256 == runtimeManifest.rootfsSHA256,
              request.candidateRuntimeRootfsSHA256 == base.measurement.rootfsSHA256,
              request.candidateRuntimeRootfsSHA256 == image.runtimeRootfsSHA256,
              request.candidateRuntimeRootfsByteLength == runtimeManifest.rootfsByteLength,
              request.candidateRuntimeRootfsByteLength == base.measurement.rootfsByteLength,
              request.candidateRuntimeRootfsByteLength == image.runtimeRootfsByteLength,
              request.candidateRuntimeManifestSHA256 == runtimeManifest.manifestSHA256,
              request.candidateRuntimeManifestSHA256 == base.measurement.runtimeManifestSHA256,
              request.candidateRuntimeManifestSHA256 == image.runtimeManifestSHA256,
              request.candidatePackageRunnerSHA256 == runtimeManifest.packageRunnerSHA256,
              request.candidatePackageRunnerSHA256 == base.measurement.packageRunnerSHA256,
              request.candidatePackageRunnerSHA256 == image.packageRunnerSHA256,
              request.cloneBindingSHA256 == clone.cloneBindingSHA256,
              request.packageUID == backend.packageUID,
              request.packageUID == runtimeManifest.packageUID,
              request.packageGID == backend.packageGID,
              request.packageGID == runtimeManifest.packageGID,
              !request.packageExecutionAuthorityPermitted,
              !request.syncBackPermitted else {
            throw QualificationHarnessError.verification("request_context")
        }
    }

    private static func verifySerial(
        _ data: Data,
        request: ParsedLinuxVzPackageRuntimeQualificationRequest,
        guestReceipt: Data
    ) throws {
        let markers = [
            "WHOATHERE_RUNTIME_QUALIFICATION_BEGIN",
            "WHOATHERE_CAPABILITY kernel_release=6.18.35-0-virt",
            "WHOATHERE_CAPABILITY architecture=aarch64",
            "WHOATHERE_CAPABILITY cgroup_v2=mounted",
            "WHOATHERE_CAPABILITY bpf_fs=mounted",
            "WHOATHERE_CAPABILITY runtime_modules=loaded",
            "WHOATHERE_CAPABILITY virtio_net=loaded_without_configuration",
            "WHOATHERE_CAPABILITY candidate_rootfs_block_device=present",
            "WHOATHERE_RUNTIME_QUALIFICATION_READY port=40554",
            "WHOATHERE_RUNTIME_QUALIFICATION_RECEIPT_OK request_sha256=\(request.requestSHA256) receipt_sha256=\(dataSHA256(guestReceipt)) execution_authority=false package_execution=false sync_back=false",
            "WHOATHERE_CAPABILITY runtime_qualification_receipt=passed",
            "WHOATHERE_CAPABILITY external_route_configured=false",
            "WHOATHERE_CAPABILITY package_execution=false",
            "WHOATHERE_CAPABILITY sync_back=false",
            "WHOATHERE_RUNTIME_QUALIFICATION_OK"
        ]
        guard markers.allSatisfy({
            linuxVzInertSerialContainsExactMarker(data, marker: $0)
        }),
        !linuxVzInertSerialContainsExactMarker(
            data,
            marker: "WHOATHERE_RUNTIME_QUALIFICATION_FAILED"
        ),
        !linuxVzInertSerialContainsExactMarker(
            data,
            marker: "WHOATHERE_RUNTIME_QUALIFICATION_POWER_OFF_FAILED"
        ) else {
            throw QualificationHarnessError.verification("serial_evidence")
        }
    }

    private static func invokeRequestBuilder(
        options: Options,
        runtimeLayout: LinuxVzPackageRuntimeBaseLayout,
        cloneBinding: URL
    ) throws {
        guard try regularNonSymlink(options.requestBuilder) else {
            throw QualificationHarnessError.invalidInput("request_builder")
        }
        let process = Process()
        process.executableURL = options.requestBuilder
        process.arguments = [
            options.qualifiedBackend.path,
            options.backendIdentity.path,
            runtimeLayout.rootfsURL.path,
            runtimeLayout.runtimeManifestURL.path,
            runtimeLayout.packageRunnerURL.path,
            options.qualificationImage.path,
            cloneBinding.path,
            options.outputDirectory.path
        ]
        process.environment = [
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "LANG": "C",
            "LC_ALL": "C"
        ]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do { try process.run() } catch {
            throw QualificationHarnessError.requestBuilder("launch")
        }
        process.waitUntilExit()
        guard process.terminationReason == .exit, process.terminationStatus == 0 else {
            throw QualificationHarnessError.requestBuilder("nonzero_exit")
        }
    }

    private static func loadQualificationImage(_ directory: URL) throws -> QualificationImage {
        let manifestURL = directory.appendingPathComponent("manifest.json")
        let manifestData = try readBoundedRegularFile(manifestURL, maximum: 4 << 20)
        guard let value = try? JSONSerialization.jsonObject(with: manifestData) as? [String: Any]
        else {
            throw QualificationHarnessError.invalidInput("qualification_manifest")
        }
        var canonical = try localCanonicalJSONData(value)
        canonical.append(0x0a)
        let expectedKeys = Set([
            "architecture", "base_signed_initramfs_sha256", "base_signed_manifest_sha256",
            "builder_source_sha256", "candidate_package_runner_sha256",
            "candidate_runtime_manifest_sha256", "candidate_runtime_rootfs_byte_length",
            "candidate_runtime_rootfs_sha256", "canonical_newc_source_sha256",
            "cargo_lock_sha256", "cargo_zigbuild_version", "external_network",
            "guest_signer_sha256", "image_state", "kernel_image_sha256", "kernel_release",
            "package_execution", "process_sensor_probe_sha256",
            "runtime_qualification_agent_sha256", "runtime_qualification_agent_source_sha256",
            "runtime_qualification_init_sha256", "runtime_qualification_init_source_sha256",
            "runtime_qualification_initramfs_sha256",
            "runtime_qualification_module_bundle_sha256",
            "runtime_qualification_operation", "runtime_qualification_overlay_cpio_gzip_sha256",
            "runtime_qualification_overlay_cpio_sha256", "rustc_version", "schema_version",
            "rust_source_tree_sha256", "sync_back_policy", "verifier_source_sha256",
            "zig_version"
        ])
        guard manifestData == canonical,
              Set(value.keys) == expectedKeys,
              value["schema_version"] as? String
                == "whoathere.linux_vz_package_runtime_qualification_image_manifest.v1",
              value["architecture"] as? String == "aarch64",
              value["kernel_release"] as? String == "6.18.35-0-virt",
              value["image_state"] as? String == "candidate_unqualified",
              value["runtime_qualification_operation"] as? String
                == "fixed_nonexecuting_probe",
              value["external_network"] as? String
                == "host_raw_frame_sinkhole_no_external_route",
              value["package_execution"] as? Bool == false,
              value["sync_back_policy"] as? String == "structurally_absent",
              let byteLengthText = value["candidate_runtime_rootfs_byte_length"] as? String,
              let byteLength = UInt64(byteLengthText), byteLength > 0 else {
            throw QualificationHarnessError.verification("qualification_manifest")
        }
        func digest(_ key: String) throws -> String {
            guard let result = value[key] as? String, validSHA256(result) else {
                throw QualificationHarnessError.verification("qualification_manifest_\(key)")
            }
            return result
        }
        _ = try digest("rust_source_tree_sha256")
        let kernel = directory.appendingPathComponent("Image-virt")
        let initramfs = directory.appendingPathComponent(
            "whoathere-runtime-qualification-initramfs-virt"
        )
        let agent = directory.appendingPathComponent(
            "overlay/whoathere/runtime-qualification-agent"
        )
        let guestInit = directory.appendingPathComponent("overlay/init")
        let moduleBundle = directory.appendingPathComponent(
            "overlay/whoathere/runtime-module-bundle.json"
        )
        let measured = try [kernel, initramfs, agent, guestInit, moduleBundle].map(fileSHA256)
        guard measured[0] == (try digest("kernel_image_sha256")),
              measured[1] == (try digest("runtime_qualification_initramfs_sha256")),
              measured[2] == (try digest("runtime_qualification_agent_sha256")),
              measured[3] == (try digest("runtime_qualification_init_sha256")),
              measured[4] == (try digest("runtime_qualification_module_bundle_sha256")) else {
            throw QualificationHarnessError.verification("qualification_image_components")
        }
        return QualificationImage(
            manifestData: manifestData,
            manifestSHA256: dataSHA256(manifestData),
            kernel: kernel,
            initramfs: initramfs,
            agent: agent,
            guestInit: guestInit,
            moduleBundle: moduleBundle,
            kernelSHA256: measured[0],
            initramfsSHA256: measured[1],
            agentSHA256: measured[2],
            guestInitSHA256: measured[3],
            moduleBundleSHA256: measured[4],
            baseInitramfsSHA256: try digest("base_signed_initramfs_sha256"),
            guestSignerSHA256: try digest("guest_signer_sha256"),
            protectedSensorSHA256: try digest("process_sensor_probe_sha256"),
            runtimeRootfsSHA256: try digest("candidate_runtime_rootfs_sha256"),
            runtimeRootfsByteLength: byteLength,
            runtimeManifestSHA256: try digest("candidate_runtime_manifest_sha256"),
            packageRunnerSHA256: try digest("candidate_package_runner_sha256")
        )
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
            throw QualificationHarnessError.vmStart("timeout")
        }
        do { try result.get() } catch {
            throw QualificationHarnessError.vmStart(String(describing: error))
        }
    }

    private static func waitForMarker(
        _ marker: String,
        virtualMachine: VZVirtualMachine,
        queue: DispatchQueue,
        serialOutput: FileHandle,
        serialLog: URL,
        deadline: Date
    ) throws {
        while Date() < deadline {
            try? serialOutput.synchronize()
            let data = (try? Data(contentsOf: serialLog)) ?? Data()
            if linuxVzInertSerialContainsExactMarker(data, marker: marker) { return }
            if queue.sync(execute: { virtualMachine.state == .stopped }) {
                throw QualificationHarnessError.timeout("guest_ready_vm_stopped")
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
        throw QualificationHarnessError.timeout("guest_ready")
    }

    private static func connect(
        virtualMachine: VZVirtualMachine,
        queue: DispatchQueue,
        port: UInt32
    ) throws -> VZVirtioSocketConnection {
        guard let device = queue.sync(execute: {
            virtualMachine.socketDevices.first as? VZVirtioSocketDevice
        }) else {
            throw QualificationHarnessError.verification("vsock_device")
        }
        let resultBox = LockedBox<Result<VZVirtioSocketConnection, Error>>()
        let completion = DispatchSemaphore(value: 0)
        let deviceBox = UncheckedSendableBox(value: device)
        queue.async {
            deviceBox.value.connect(toPort: port) { result in
                resultBox.store(result)
                completion.signal()
            }
        }
        guard completion.wait(timeout: .now() + .seconds(10)) == .success,
              let result = resultBox.load() else {
            throw QualificationHarnessError.timeout("vsock_connect")
        }
        do { return try result.get() } catch {
            throw QualificationHarnessError.verification("vsock_connect")
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
        throw QualificationHarnessError.vmStop
    }

    private static func bestEffortStop(
        virtualMachine: VZVirtualMachine,
        queue: DispatchQueue
    ) -> Bool {
        if queue.sync(execute: { virtualMachine.state == .stopped }) { return true }
        let completion = DispatchSemaphore(value: 0)
        let machineBox = UncheckedSendableBox(value: virtualMachine)
        queue.async {
            guard machineBox.value.canStop else {
                completion.signal()
                return
            }
            machineBox.value.stop { _ in completion.signal() }
        }
        guard completion.wait(timeout: .now() + .seconds(20)) == .success else { return false }
        return queue.sync(execute: { virtualMachine.state == .stopped })
    }

    private static func setSocketTimeouts(_ descriptor: Int32) throws {
        var timeout = timeval(tv_sec: 20, tv_usec: 0)
        for option in [SO_RCVTIMEO, SO_SNDTIMEO] {
            let result = withUnsafePointer(to: &timeout) { pointer in
                setsockopt(
                    descriptor,
                    SOL_SOCKET,
                    option,
                    pointer,
                    socklen_t(MemoryLayout<timeval>.size)
                )
            }
            guard result == 0 else { throw QualificationHarnessError.socketIO }
        }
    }

    private static func writeAll(_ descriptor: Int32, data: Data) throws {
        try data.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                let count = Darwin.write(
                    descriptor,
                    raw.baseAddress!.advanced(by: offset),
                    raw.count - offset
                )
                if count > 0 { offset += count; continue }
                if count < 0 && errno == EINTR { continue }
                throw QualificationHarnessError.socketIO
            }
        }
    }

    private static func readToEOF(_ descriptor: Int32, maximum: Int) throws -> Data {
        var result = Data()
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let count = Darwin.read(descriptor, &buffer, buffer.count)
            if count > 0 {
                guard result.count <= maximum - count else {
                    throw QualificationHarnessError.socketIO
                }
                result.append(contentsOf: buffer.prefix(count))
                continue
            }
            if count == 0 { break }
            if errno == EINTR { continue }
            throw QualificationHarnessError.socketIO
        }
        guard !result.isEmpty else { throw QualificationHarnessError.socketIO }
        return result
    }

    private static func readBoundedRegularFile(_ url: URL, maximum: Int) throws -> Data {
        let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else {
            throw QualificationHarnessError.invalidInput(url.lastPathComponent)
        }
        defer { close(descriptor) }
        var before = stat()
        guard fstat(descriptor, &before) == 0,
              before.st_mode & S_IFMT == S_IFREG,
              before.st_size > 0,
              UInt64(before.st_size) <= UInt64(maximum) else {
            throw QualificationHarnessError.invalidInput(url.lastPathComponent)
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
            throw QualificationHarnessError.invalidInput(url.lastPathComponent)
        }
        var extra: UInt8 = 0
        var extraCount: Int
        repeat {
            extraCount = Darwin.read(descriptor, &extra, 1)
        } while extraCount < 0 && errno == EINTR
        var after = stat()
        guard extraCount == 0,
              fstat(descriptor, &after) == 0,
              before.st_dev == after.st_dev,
              before.st_ino == after.st_ino,
              before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec else {
            throw QualificationHarnessError.invalidInput(url.lastPathComponent)
        }
        return data
    }

    private static func fileSHA256(_ url: URL) throws -> String {
        let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else {
            throw QualificationHarnessError.invalidInput(url.lastPathComponent)
        }
        defer { close(descriptor) }
        var before = stat()
        guard fstat(descriptor, &before) == 0,
              before.st_mode & S_IFMT == S_IFREG,
              before.st_size > 0 else {
            throw QualificationHarnessError.invalidInput(url.lastPathComponent)
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
            throw QualificationHarnessError.invalidInput(url.lastPathComponent)
        }
        var after = stat()
        guard fstat(descriptor, &after) == 0,
              total == before.st_size,
              before.st_dev == after.st_dev,
              before.st_ino == after.st_ino,
              before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec else {
            throw QualificationHarnessError.invalidInput(url.lastPathComponent)
        }
        return "sha256:" + hasher.finalize().map {
            String(format: "%02x", $0)
        }.joined()
    }

    private static func regularNonSymlink(_ url: URL) throws -> Bool {
        var status = stat()
        return lstat(url.path, &status) == 0 && status.st_mode & S_IFMT == S_IFREG
    }

    private static func requireSecureOutputDirectory(_ url: URL) throws {
        var status = stat()
        guard lstat(url.path, &status) == 0,
              status.st_mode & S_IFMT == S_IFDIR,
              status.st_uid == geteuid(),
              status.st_mode & 0o777 == 0o700 else {
            throw QualificationHarnessError.invalidInput("output_directory")
        }
        for name in [
            "runtime-qualification-clone-binding.json",
            "runtime-qualification-request.json",
            "runtime-qualification-request.bin",
            "runtime-qualification-response.bin",
            "runtime-qualification-process-evidence.json",
            "runtime-qualification-guest-receipt.json",
            "runtime-qualification-host-evidence.json",
            "runtime-qualification-host-receipt.json",
            "runtime-qualification-serial.log"
        ] where FileManager.default.fileExists(
            atPath: url.appendingPathComponent(name).path
        ) {
            throw QualificationHarnessError.invalidInput("output_exists_\(name)")
        }
    }

    private static func writeNewPrivateFile(_ url: URL, data: Data) throws {
        let descriptor = open(
            url.path,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            0o600
        )
        guard descriptor >= 0 else {
            throw QualificationHarnessError.invalidInput("output_file")
        }
        defer { close(descriptor) }
        try writeAll(descriptor, data: data)
        guard fsync(descriptor) == 0 else {
            throw QualificationHarnessError.invalidInput("output_file")
        }
    }

    private static func openNewPrivateFileHandle(_ url: URL) throws -> FileHandle {
        let descriptor = open(
            url.path,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            0o600
        )
        guard descriptor >= 0 else {
            throw QualificationHarnessError.invalidInput("serial_log")
        }
        return FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    }

    private static func readProtectedSeed(_ url: URL) throws -> Data {
        let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else {
            throw QualificationHarnessError.invalidInput("host_signing_seed")
        }
        defer { close(descriptor) }
        var status = stat()
        guard fstat(descriptor, &status) == 0,
              status.st_uid == geteuid(),
              status.st_nlink == 1,
              status.st_size == 32,
              status.st_mode & S_IFMT == S_IFREG,
              status.st_mode & 0o777 == 0o600 else {
            throw QualificationHarnessError.invalidInput("host_signing_seed")
        }
        var result = Data()
        var buffer = [UInt8](repeating: 0, count: 32)
        while result.count < 32 {
            let count = Darwin.read(descriptor, &buffer, 32 - result.count)
            if count > 0 {
                result.append(contentsOf: buffer.prefix(count))
                continue
            }
            if count < 0 && errno == EINTR { continue }
            throw QualificationHarnessError.invalidInput("host_signing_seed")
        }
        var extra: UInt8 = 0
        guard Darwin.read(descriptor, &extra, 1) == 0 else {
            throw QualificationHarnessError.invalidInput("host_signing_seed")
        }
        return result
    }

    private static func emitFailure(reason: String, exitCode: Int32) {
        emitJSON([
            "schema_version": "whoathere.linux_vz_runtime_qualification_result.v1",
            "status": "failed_closed",
            "reason": reason,
            "execution_authority": false,
            "package_execution": false,
            "external_route": false,
            "sync_back": false,
            "exit_code": Int(exitCode)
        ])
    }

    private static func emitJSON(_ fields: [String: Any]) {
        guard let data = try? JSONSerialization.data(
            withJSONObject: fields,
            options: [.sortedKeys, .withoutEscapingSlashes]
        ) else { return }
        print(String(decoding: data, as: UTF8.self))
    }
}

private func validSHA256(_ value: String) -> Bool {
    value.utf8.count == 71 && value.hasPrefix("sha256:")
        && value.dropFirst(7).utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
        }
}

private func dataSHA256(_ data: Data) -> String {
    "sha256:" + SHA256.hash(data: data).map {
        String(format: "%02x", $0)
    }.joined()
}

private func localCanonicalJSONData(_ value: Any) throws -> Data {
    try JSONSerialization.data(
        withJSONObject: value,
        options: [.sortedKeys, .withoutEscapingSlashes]
    )
}
