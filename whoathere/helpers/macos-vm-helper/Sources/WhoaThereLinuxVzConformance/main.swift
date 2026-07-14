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
        guard let kernel, let initramfs, let expectedKernelSHA256,
              let expectedInitramfsSHA256, let serialLog,
              kernel.path.hasPrefix("/"), initramfs.path.hasPrefix("/"),
              serialLog.path.hasPrefix("/"),
              validSHA256(expectedKernelSHA256), validSHA256(expectedInitramfsSHA256),
              expectedPackageSensorFixtureSHA256.map(validSHA256) ?? true,
              expectedRuntimeBTFSHA256.map(validSHA256) ?? true,
              (expectedPackageSensorFixtureSHA256 == nil
                  && expectedRuntimeBTFSHA256 == nil
                  && expectedTaskExitCodeByteOffset == nil)
                  || (expectedPackageSensorFixtureSHA256 != nil
                      && expectedRuntimeBTFSHA256 != nil
                      && expectedTaskExitCodeByteOffset != nil) else {
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
                "usage: whoathere-linux-vz-conformance --kernel PATH --initramfs PATH --expected-kernel-sha256 SHA256 --expected-initramfs-sha256 SHA256 --serial-log PATH [--expected-package-sensor-fixture-sha256 SHA256 --expected-runtime-btf-sha256 SHA256 --expected-task-exit-code-byte-offset DECIMAL] [--timeout-seconds 30]\n",
                stderr
            )
            exit(64)
        } catch {
            emitJSON([
                "schema_version": "whoathere.linux_vz_inert_boot_result.v3",
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
        let guestNetworkSocket = FileHandle(fileDescriptor: sockets[0], closeOnDealloc: false)
        let configuration = try buildLinuxVzInertVMConfiguration(
            kernelURL: options.kernel,
            initramfsURL: options.initramfs,
            serialInput: nil,
            serialOutput: serialOutput,
            rawFrameSocket: guestNetworkSocket
        )

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
        let rawFrameCount = drainRawFrames(fileDescriptor: sockets[1])
        let finalKernelSHA256 = try fileSHA256(options.kernel)
        let finalInitramfsSHA256 = try fileSHA256(options.initramfs)
        let imageIdentityStable = finalKernelSHA256 == kernelSHA256
            && finalInitramfsSHA256 == initramfsSHA256
        if let expectedFixtureSHA256 = options.expectedPackageSensorFixtureSHA256,
           let expectedRuntimeBTFSHA256 = options.expectedRuntimeBTFSHA256,
           let expectedTaskExitCodeByteOffset = options.expectedTaskExitCodeByteOffset {
            let evidence = try? decodeLinuxVzPackageSensorBpfInertEvidenceV11(
                serialData,
                expectedFixtureSHA256: expectedFixtureSHA256,
                expectedRuntimeBTFSHA256: expectedRuntimeBTFSHA256,
                expectedTaskExitCodeByteOffset: expectedTaskExitCodeByteOffset
            )
            let missingMarkers = linuxVzPackageSensorBpfInertMissingMarkersV1(serialData)
            let failurePresent = linuxVzPackageSensorBpfInertFailurePresentV1(serialData)
            let success = stopped && evidence != nil && missingMarkers.isEmpty
                && !failurePresent && rawFrameCount == 0 && imageIdentityStable
            emitJSON([
                "schema_version":
                    "whoathere.linux_vz_package_sensor_bpf_inert_boot_result.v1",
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
            && imageIdentityStable
        emitJSON([
            "schema_version": "whoathere.linux_vz_inert_boot_result.v3",
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

    private static func drainRawFrames(fileDescriptor: Int32) -> Int {
        var count = 0
        var buffer = [UInt8](repeating: 0, count: 65_535)
        while true {
            let received = recv(
                fileDescriptor,
                &buffer,
                buffer.count,
                MSG_DONTWAIT
            )
            if received > 0 {
                count += 1
                continue
            }
            break
        }
        return count
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
