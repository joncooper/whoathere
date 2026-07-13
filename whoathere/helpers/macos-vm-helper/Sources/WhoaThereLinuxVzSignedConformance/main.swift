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

private struct BoundedHostFrameCollection: Sendable {
    let retainedFrames: [Data]
    let ingressFrameCount: Int
    let droppedFrameCount: Int
    let healthy: Bool
    let terminal: String
}

private final class BoundedHostFrameCollector: @unchecked Sendable {
    private let lock = NSLock()
    private let capacity: Int
    private var retainedFrames = [Data]()
    private var ingressFrameCount = 0
    private var droppedFrameCount = 0
    private var healthy = true
    private var stopRequested = false

    init(capacity: Int) {
        self.capacity = capacity
    }

    func requestStop() {
        lock.lock()
        stopRequested = true
        lock.unlock()
    }

    func run(fileDescriptor: Int32) -> BoundedHostFrameCollection {
        var buffer = [UInt8](repeating: 0, count: 65_535)
        while true {
            let received = recv(fileDescriptor, &buffer, buffer.count, MSG_DONTWAIT)
            if received >= 0 {
                lock.lock()
                ingressFrameCount += 1
                if retainedFrames.count < capacity {
                    retainedFrames.append(Data(buffer.prefix(received)))
                } else {
                    droppedFrameCount += 1
                }
                lock.unlock()
                continue
            }
            if errno != EAGAIN && errno != EWOULDBLOCK {
                lock.lock()
                healthy = false
                lock.unlock()
                break
            }
            lock.lock()
            let shouldStop = stopRequested
            lock.unlock()
            if shouldStop { break }
            usleep(1_000)
        }
        lock.lock()
        defer { lock.unlock() }
        return BoundedHostFrameCollection(
            retainedFrames: retainedFrames,
            ingressFrameCount: ingressFrameCount,
            droppedFrameCount: droppedFrameCount,
            healthy: healthy,
            terminal: healthy ? "bounded_queue_overflow_accounted" : "socket_error"
        )
    }
}

private struct HostSensorDeathCollection: Sendable {
    let ingressFrameCount: Int
    let workerStarted: Bool
    let injected: Bool
    let workerTerminated: Bool
    let healthy: Bool
    let terminal: String
}

private final class HostSensorDeathCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var ingressFrameCount = 0
    private var running = false
    private var injectedDeathRequested = false
    private var cleanupStopRequested = false

    func requestInjectedDeath() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard running, !injectedDeathRequested, !cleanupStopRequested else { return false }
        injectedDeathRequested = true
        return true
    }

    func requestCleanupStop() {
        lock.lock()
        cleanupStopRequested = true
        lock.unlock()
    }

    func run(fileDescriptor: Int32) -> HostSensorDeathCollection {
        lock.lock()
        running = true
        lock.unlock()
        var buffer = [UInt8](repeating: 0, count: 65_535)
        var socketHealthy = true
        while true {
            let received = recv(fileDescriptor, &buffer, buffer.count, MSG_DONTWAIT)
            if received >= 0 {
                lock.lock()
                ingressFrameCount += 1
                lock.unlock()
                continue
            }
            if errno != EAGAIN && errno != EWOULDBLOCK {
                socketHealthy = false
                break
            }
            lock.lock()
            let injected = injectedDeathRequested
            let cleanup = cleanupStopRequested
            lock.unlock()
            if injected || cleanup { break }
            usleep(1_000)
        }
        lock.lock()
        let injected = injectedDeathRequested
        let cleanup = cleanupStopRequested
        let ingress = ingressFrameCount
        running = false
        lock.unlock()
        return HostSensorDeathCollection(
            ingressFrameCount: ingress,
            workerStarted: true,
            injected: injected,
            workerTerminated: injected,
            healthy: !injected && !cleanup && socketHealthy,
            terminal: injected ? "injected_sensor_death" :
                (socketHealthy ? "cleanup_stop" : "socket_error")
        )
    }
}

private struct Options {
    let kernel: URL
    let initramfs: URL
    let expectedKernelSHA256: String
    let expectedInitramfsSHA256: String
    let requestFrame: URL
    let backendIdentity: URL
    let guestPublicKey: URL
    let hostSigningSeed: URL
    let receiptOutput: URL
    let hostEvidenceOutput: URL
    let hostReceiptOutput: URL
    let serialLog: URL
    let timeoutSeconds: Int

    static func parse(_ arguments: [String]) throws -> Self {
        var values = [String: String]()
        var index = 1
        while index < arguments.count {
            guard index + 1 < arguments.count,
                  values.updateValue(arguments[index + 1], forKey: arguments[index]) == nil else {
                throw HarnessError.usage
            }
            index += 2
        }
        let required = [
            "--kernel", "--initramfs", "--expected-kernel-sha256",
            "--expected-initramfs-sha256", "--request-frame", "--backend-identity",
            "--guest-public-key", "--host-signing-seed", "--receipt-output",
            "--host-evidence-output", "--host-receipt-output", "--serial-log"
        ]
        guard required.allSatisfy({ values[$0] != nil }),
              Set(values.keys).isSubset(of: Set(required + ["--timeout-seconds"])),
              let kernel = values["--kernel"],
              let initramfs = values["--initramfs"],
              let expectedKernelSHA256 = values["--expected-kernel-sha256"],
              let expectedInitramfsSHA256 = values["--expected-initramfs-sha256"],
              let requestFrame = values["--request-frame"],
              let backendIdentity = values["--backend-identity"],
              let guestPublicKey = values["--guest-public-key"],
              let hostSigningSeed = values["--host-signing-seed"],
              let receiptOutput = values["--receipt-output"],
              let hostEvidenceOutput = values["--host-evidence-output"],
              let hostReceiptOutput = values["--host-receipt-output"],
              let serialLog = values["--serial-log"],
              [kernel, initramfs, requestFrame, backendIdentity, guestPublicKey,
               hostSigningSeed, receiptOutput, hostEvidenceOutput, hostReceiptOutput,
               serialLog].allSatisfy({ $0.hasPrefix("/") }),
              validSHA256(expectedKernelSHA256), validSHA256(expectedInitramfsSHA256) else {
            throw HarnessError.usage
        }
        let timeoutSeconds: Int
        if let text = values["--timeout-seconds"] {
            guard let parsed = Int(text), parsed >= 10, parsed <= 120 else {
                throw HarnessError.usage
            }
            timeoutSeconds = parsed
        } else {
            timeoutSeconds = 45
        }
        return Self(
            kernel: URL(fileURLWithPath: kernel),
            initramfs: URL(fileURLWithPath: initramfs),
            expectedKernelSHA256: expectedKernelSHA256,
            expectedInitramfsSHA256: expectedInitramfsSHA256,
            requestFrame: URL(fileURLWithPath: requestFrame),
            backendIdentity: URL(fileURLWithPath: backendIdentity),
            guestPublicKey: URL(fileURLWithPath: guestPublicKey),
            hostSigningSeed: URL(fileURLWithPath: hostSigningSeed),
            receiptOutput: URL(fileURLWithPath: receiptOutput),
            hostEvidenceOutput: URL(fileURLWithPath: hostEvidenceOutput),
            hostReceiptOutput: URL(fileURLWithPath: hostReceiptOutput),
            serialLog: URL(fileURLWithPath: serialLog),
            timeoutSeconds: timeoutSeconds
        )
    }
}

private enum HarnessError: Error {
    case usage
    case invalidInput(String)
    case imageDigestMismatch(String)
    case socketPair
    case serialLog
    case startTimeout
    case startFailed(String)
    case signerReadyTimeout
    case socketDeviceMissing
    case socketConnectTimeout
    case socketConnectFailed(String)
    case socketIO
    case vmDidNotStop
    case verificationFailed
}

@main
private struct LinuxVzSignedConformanceHarness {
    private static let signerPort: UInt32 = 40_551

    static func main() {
        do {
            let options = try Options.parse(CommandLine.arguments)
            exit(try run(options))
        } catch HarnessError.usage {
            fputs(
                "usage: whoathere-linux-vz-signed-conformance --kernel PATH --initramfs PATH --expected-kernel-sha256 SHA256 --expected-initramfs-sha256 SHA256 --request-frame PATH --backend-identity PATH --guest-public-key PATH --host-signing-seed PATH --receipt-output PATH --host-evidence-output PATH --host-receipt-output PATH --serial-log PATH [--timeout-seconds 45]\n",
                stderr
            )
            exit(64)
        } catch {
            emitJSON([
                "schema_version": "whoathere.linux_vz_signed_conformance_result.v1",
                "status": "error",
                "reason": String(describing: error),
                "execution_authority": false,
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
        let requestData = try readBoundedRegularFile(
            options.requestFrame,
            maximum: maximumLinuxVzGuestSignerRequestFrameBytesV1
        )
        let request = try decodeLinuxVzGuestSignerRequest(requestData)
        let runSpec = try decodeLinuxVzTelemetryConformanceRunSpec(request.runSpec)
        let backendData = try readBoundedRegularFile(
            options.backendIdentity,
            maximum: maximumLinuxVzTelemetryBackendIdentityBytesV1
        )
        let backend = try decodeUnqualifiedLinuxVzTelemetryBackendIdentity(
            backendData,
            expectedTelemetryRequirementsSHA256: runSpec.telemetryRequirementsSHA256
        )
        let challenge = try decodeLinuxVzTelemetryConformanceChallenge(
            request.challenge,
            expectedRunSpec: runSpec,
            expectedBackend: backend
        )
        let guestPublicKey = try readBoundedRegularFile(options.guestPublicKey, maximum: 32)
        guard guestPublicKey.count == 32,
              dataSHA256(guestPublicKey) == challenge.guestEvidencePublicKeySHA256,
              !FileManager.default.fileExists(atPath: options.receiptOutput.path),
              !FileManager.default.fileExists(atPath: options.hostEvidenceOutput.path),
              !FileManager.default.fileExists(atPath: options.hostReceiptOutput.path),
              !FileManager.default.fileExists(atPath: options.serialLog.path) else {
            throw HarnessError.invalidInput("guest_key_or_receipt_output")
        }

        let serialOutput = try openNewPrivateFileHandle(options.serialLog)
        defer { try? serialOutput.close() }

        var sockets = [Int32](repeating: -1, count: 2)
        guard socketpair(AF_UNIX, SOCK_DGRAM, 0, &sockets) == 0 else {
            throw HarnessError.socketPair
        }
        defer {
            if sockets[0] >= 0 { close(sockets[0]) }
            if sockets[1] >= 0 { close(sockets[1]) }
        }
        let overflowCollector = runSpec.fixtureCase == "host_frame_overflow"
            ? BoundedHostFrameCollector(capacity: 64) : nil
        let hostSensorDeathCollector = runSpec.fixtureCase == "host_sensor_death"
            ? HostSensorDeathCollector() : nil
        let overflowCollectionResult = LockedBox<BoundedHostFrameCollection>()
        let overflowCollectionDone = DispatchSemaphore(value: 0)
        var overflowCollectionFinished = false
        let hostSensorDeathCollectionResult = LockedBox<HostSensorDeathCollection>()
        let hostSensorDeathCollectionDone = DispatchSemaphore(value: 0)
        var hostSensorDeathCollectionFinished = false
        if let overflowCollector {
            let collectorBox = UncheckedSendableBox(value: overflowCollector)
            let descriptor = sockets[1]
            DispatchQueue.global(qos: .userInitiated).async {
                overflowCollectionResult.store(
                    collectorBox.value.run(fileDescriptor: descriptor)
                )
                overflowCollectionDone.signal()
            }
        }
        if let hostSensorDeathCollector {
            let collectorBox = UncheckedSendableBox(value: hostSensorDeathCollector)
            let descriptor = sockets[1]
            DispatchQueue.global(qos: .userInitiated).async {
                hostSensorDeathCollectionResult.store(
                    collectorBox.value.run(fileDescriptor: descriptor)
                )
                hostSensorDeathCollectionDone.signal()
            }
        }
        defer {
            if let overflowCollector, !overflowCollectionFinished {
                overflowCollector.requestStop()
                _ = overflowCollectionDone.wait(timeout: .now() + .seconds(2))
            }
            if let hostSensorDeathCollector, !hostSensorDeathCollectionFinished {
                hostSensorDeathCollector.requestCleanupStop()
                _ = hostSensorDeathCollectionDone.wait(timeout: .now() + .seconds(2))
            }
        }
        let guestNetworkSocket = FileHandle(fileDescriptor: sockets[0], closeOnDealloc: false)
        let configuration = try buildLinuxVzInertVMConfiguration(
            kernelURL: options.kernel,
            initramfsURL: options.initramfs,
            serialInput: nil,
            serialOutput: serialOutput,
            rawFrameSocket: guestNetworkSocket
        )

        let queue = DispatchQueue(label: "whoathere.linux-vz.signed-conformance")
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
        do { try result.get() } catch {
            throw HarnessError.startFailed(String(describing: error))
        }
        defer { bestEffortStop(virtualMachine: virtualMachine, queue: queue) }

        let deadline = Date().addingTimeInterval(TimeInterval(options.timeoutSeconds))
        try waitForSignerReady(
            virtualMachine: virtualMachine,
            queue: queue,
            serialOutput: serialOutput,
            serialLog: options.serialLog,
            deadline: deadline
        )
        guard let socketDevice = queue.sync(execute: {
            virtualMachine.socketDevices.first as? VZVirtioSocketDevice
        }) else {
            throw HarnessError.socketDeviceMissing
        }
        let connectionBox = LockedBox<Result<VZVirtioSocketConnection, Error>>()
        let connected = DispatchSemaphore(value: 0)
        let socketDeviceBox = UncheckedSendableBox(value: socketDevice)
        queue.async {
            socketDeviceBox.value.connect(toPort: signerPort) { result in
                connectionBox.store(result)
                connected.signal()
            }
        }
        guard connected.wait(timeout: .now() + .seconds(10)) == .success else {
            throw HarnessError.socketConnectTimeout
        }
        guard let connectionResult = connectionBox.load() else {
            throw HarnessError.socketConnectFailed("missing_connection_result")
        }
        let connection: VZVirtioSocketConnection
        do { connection = try connectionResult.get() } catch {
            throw HarnessError.socketConnectFailed(String(describing: error))
        }
        defer { connection.close() }
        try setSocketTimeouts(connection.fileDescriptor)
        if runSpec.fixtureCase == "channel_interruption" {
            return try runChannelInterruptionCase(
                options: options,
                requestData: requestData,
                runSpec: runSpec,
                challenge: challenge,
                backend: backend,
                configuration: configuration,
                virtualMachine: virtualMachine,
                queue: queue,
                connection: connection,
                serialOutput: serialOutput,
                rawFrameSocket: sockets[1],
                deadline: deadline,
                initialKernelSHA256: kernelSHA256,
                initialInitramfsSHA256: initramfsSHA256
            )
        }
        try writeAll(connection.fileDescriptor, data: requestData)
        guard shutdown(connection.fileDescriptor, SHUT_WR) == 0 else {
            throw HarnessError.socketIO
        }
        var hostSensorDeathCollection: HostSensorDeathCollection?
        if let hostSensorDeathCollector {
            guard hostSensorDeathCollector.requestInjectedDeath(),
                  hostSensorDeathCollectionDone.wait(timeout: .now() + .seconds(2)) == .success,
                  let collection = hostSensorDeathCollectionResult.load() else {
                throw HarnessError.verificationFailed
            }
            hostSensorDeathCollectionFinished = true
            hostSensorDeathCollection = collection
        }
        if runSpec.fixtureCase == "vm_stop" {
            return try runVmStopCase(
                options: options,
                requestData: requestData,
                runSpec: runSpec,
                challenge: challenge,
                backend: backend,
                configuration: configuration,
                virtualMachine: virtualMachine,
                queue: queue,
                connection: connection,
                serialOutput: serialOutput,
                rawFrameSocket: sockets[1],
                deadline: deadline,
                initialKernelSHA256: kernelSHA256,
                initialInitramfsSHA256: initramfsSHA256
            )
        }
        if runSpec.fixtureCase == "guest_sensor_death" {
            return try runGuestSensorDeathCase(
                options: options,
                requestData: requestData,
                runSpec: runSpec,
                challenge: challenge,
                backend: backend,
                configuration: configuration,
                virtualMachine: virtualMachine,
                queue: queue,
                connection: connection,
                serialOutput: serialOutput,
                rawFrameSocket: sockets[1],
                deadline: deadline,
                initialKernelSHA256: kernelSHA256,
                initialInitramfsSHA256: initramfsSHA256
            )
        }
        let responseData = try readToEOF(
            connection.fileDescriptor,
            maximum: maximumLinuxVzGuestSignerResponseFrameBytesV1
        )
        let receipt = try decodeLinuxVzGuestSignerResponse(responseData)

        try waitForStop(virtualMachine: virtualMachine, queue: queue, deadline: deadline)
        let boundedHostFrames: BoundedHostFrameCollection?
        if let overflowCollector {
            overflowCollector.requestStop()
            guard overflowCollectionDone.wait(timeout: .now() + .seconds(2)) == .success,
                  let collection = overflowCollectionResult.load() else {
                throw HarnessError.verificationFailed
            }
            overflowCollectionFinished = true
            boundedHostFrames = collection
        } else {
            boundedHostFrames = nil
        }
        try serialOutput.synchronize()
        let serialData = try Data(contentsOf: options.serialLog)
        if let serialText = String(data: serialData, encoding: .utf8) {
            fputs(serialText, stderr)
        }
        let claims: LinuxVzTelemetryGuestObservationClaims
        let guestEvidencePayloadSHA256: String
        let guestEventCount: UInt64
        let networkSourcePort: UInt16?
        let networkFixtureCase: String?
        let hostFrameTriggerCount: UInt64?
        switch runSpec.fixtureCase {
        case "kernel_config_and_btf":
            let evidence = try decodeLinuxVzPlatformEvidencePayloadV1(
                serialData,
                backend: backend
            )
            claims = evidence.claims
            guestEvidencePayloadSHA256 = evidence.payloadSHA256
            guestEventCount = evidence.claims.eventCount
            networkSourcePort = nil
            networkFixtureCase = nil
            hostFrameTriggerCount = nil
        case "cgroup_v2":
            let evidence = try decodeLinuxVzCgroupEvidencePayloadV1(
                serialData,
                backend: backend
            )
            claims = evidence.claims
            guestEvidencePayloadSHA256 = evidence.payloadSHA256
            guestEventCount = evidence.claims.eventCount
            networkSourcePort = nil
            networkFixtureCase = nil
            hostFrameTriggerCount = nil
        case "fork_exec_exit", "host_sensor_death", "all_protected_assets_denied", "reparenting",
             "double_fork_daemonization", "setsid_escape",
             "credential_change", "dynamic_library_load":
            let evidence = try decodeLinuxVzProcessEvidencePayloadV1(serialData)
            guard evidence.fixtureCase == runSpec.fixtureCase,
                  evidence.packageUID == UInt64(backend.packageUID),
                  evidence.packageGID == UInt64(backend.packageGID) else {
                throw HarnessError.verificationFailed
            }
            claims = LinuxVzTelemetryGuestObservationClaims(
                evidencePayloadSHA256: evidence.payloadSHA256,
                evidenceByteLength: evidence.evidenceByteLength,
                eventSequenceStart: evidence.eventSequenceStart,
                eventSequenceEnd: evidence.eventSequenceEnd,
                eventCount: evidence.eventCount,
                heartbeatCount: evidence.heartbeatCount,
                droppedEventCount: evidence.droppedEventCount,
                sensorHealthy: evidence.sensorHealthy,
                evidenceTruncated: evidence.evidenceTruncated,
                descendantTeardownComplete: evidence.descendantTeardownComplete,
                observedTerminal: runSpec.fixtureCase == "host_sensor_death"
                    ? "infrastructure_error_with_teardown"
                    : runSpec.fixtureCase == "all_protected_assets_denied"
                        ? "access_denied_with_complete_evidence" : "observation_complete"
            )
            guestEvidencePayloadSHA256 = evidence.payloadSHA256
            guestEventCount = evidence.eventCount
            networkSourcePort = nil
            networkFixtureCase = nil
            hostFrameTriggerCount = nil
        case "protected_open_read_write_rename_delete", "mmap_access":
            let evidence = try decodeLinuxVzFileEvidencePayload(serialData)
            guard evidence.fixtureCase == runSpec.fixtureCase,
                  evidence.packageUID == UInt64(backend.packageUID),
                  evidence.packageGID == UInt64(backend.packageGID) else {
                throw HarnessError.verificationFailed
            }
            claims = evidence.claims
            guestEvidencePayloadSHA256 = evidence.payloadSHA256
            guestEventCount = evidence.claims.eventCount
            networkSourcePort = nil
            networkFixtureCase = nil
            hostFrameTriggerCount = nil
        case "ipv4_connect", "ipv6_connect", "udp_send", "loopback_connect",
             "private_address_connect", "link_local_connect", "metadata_address_connect",
             "public_address_connect", "dns_plaintext", "dns_malformed",
             "encrypted_dns_connect":
            let evidence = try decodeLinuxVzNetworkEvidencePayloadV1(serialData)
            guard evidence.fixtureCase == runSpec.fixtureCase,
                  evidence.packageUID == UInt64(backend.packageUID),
                  evidence.packageGID == UInt64(backend.packageGID) else {
                throw HarnessError.verificationFailed
            }
            claims = evidence.claims
            guestEvidencePayloadSHA256 = evidence.payloadSHA256
            guestEventCount = evidence.claims.eventCount
            networkSourcePort = evidence.sourcePort
            networkFixtureCase = evidence.fixtureCase
            hostFrameTriggerCount = nil
        case "bpf_reservation_failure":
            let evidence = try decodeLinuxVzDropEvidencePayloadV1(serialData)
            guard evidence.fixtureCase == runSpec.fixtureCase,
                  evidence.packageUID == UInt64(backend.packageUID),
                  evidence.packageGID == UInt64(backend.packageGID) else {
                throw HarnessError.verificationFailed
            }
            claims = evidence.claims
            guestEvidencePayloadSHA256 = evidence.payloadSHA256
            guestEventCount = evidence.claims.eventCount
            networkSourcePort = nil
            networkFixtureCase = nil
            hostFrameTriggerCount = nil
        case "fanotify_queue_overflow":
            let evidence = try decodeLinuxVzFanotifyOverflowEvidencePayloadV1(serialData)
            guard evidence.fixtureCase == runSpec.fixtureCase,
                  evidence.packageUID == UInt64(backend.packageUID),
                  evidence.packageGID == UInt64(backend.packageGID) else {
                throw HarnessError.verificationFailed
            }
            claims = evidence.claims
            guestEvidencePayloadSHA256 = evidence.payloadSHA256
            guestEventCount = evidence.claims.eventCount
            networkSourcePort = nil
            networkFixtureCase = nil
            hostFrameTriggerCount = nil
        case "host_frame_overflow":
            let evidence = try decodeLinuxVzHostFrameOverflowGuestEvidencePayloadV1(serialData)
            guard evidence.fixtureCase == runSpec.fixtureCase,
                  evidence.packageUID == UInt64(backend.packageUID),
                  evidence.packageGID == UInt64(backend.packageGID) else {
                throw HarnessError.verificationFailed
            }
            claims = evidence.claims
            guestEvidencePayloadSHA256 = evidence.payloadSHA256
            guestEventCount = evidence.claims.eventCount
            networkSourcePort = evidence.sourcePort
            networkFixtureCase = evidence.fixtureCase
            hostFrameTriggerCount = evidence.triggerCount
        case "normal_exit", "timeout", "term_resistance", "escaped_session", "reparented_child", "background_listener":
            let evidence = try decodeLinuxVzTeardownEvidencePayloadV1(serialData)
            guard evidence.fixtureCase == runSpec.fixtureCase,
                  evidence.packageUID == UInt64(backend.packageUID),
                  evidence.packageGID == UInt64(backend.packageGID) else {
                throw HarnessError.verificationFailed
            }
            claims = evidence.claims
            guestEvidencePayloadSHA256 = evidence.payloadSHA256
            guestEventCount = evidence.claims.eventCount
            networkSourcePort = nil
            networkFixtureCase = nil
            hostFrameTriggerCount = nil
        default:
            throw HarnessError.verificationFailed
        }
        let verifiedGuest = try verifyLinuxVzTelemetryGuestReceipt(
            receipt,
            challenge: challenge,
            runSpec: runSpec,
            backend: backend,
            verifyingKey: guestPublicKey,
            expectedClaims: claims
        )

        let missingBaseMarkers: [String]
        if runSpec.fixtureCase == "fork_exec_exit" ||
            runSpec.fixtureCase == "host_sensor_death" ||
            runSpec.fixtureCase == "all_protected_assets_denied" ||
            runSpec.fixtureCase == "reparenting" ||
            runSpec.fixtureCase == "double_fork_daemonization" ||
            runSpec.fixtureCase == "setsid_escape" ||
            runSpec.fixtureCase == "credential_change" ||
            runSpec.fixtureCase == "dynamic_library_load" ||
            runSpec.fixtureCase == "ipv4_connect" ||
            runSpec.fixtureCase == "ipv6_connect" ||
            runSpec.fixtureCase == "udp_send" ||
            runSpec.fixtureCase == "loopback_connect" ||
            runSpec.fixtureCase == "private_address_connect" ||
            runSpec.fixtureCase == "link_local_connect" ||
            runSpec.fixtureCase == "metadata_address_connect" ||
            runSpec.fixtureCase == "public_address_connect" ||
            runSpec.fixtureCase == "dns_plaintext" ||
            runSpec.fixtureCase == "dns_malformed" ||
            runSpec.fixtureCase == "encrypted_dns_connect" ||
            runSpec.fixtureCase == "normal_exit" ||
            runSpec.fixtureCase == "timeout" ||
            runSpec.fixtureCase == "term_resistance" ||
            runSpec.fixtureCase == "escaped_session" ||
            runSpec.fixtureCase == "reparented_child" ||
            runSpec.fixtureCase == "background_listener" {
            let missingProcessMarkers = linuxVzInertMissingRequiredEvidenceMarkersV2(serialData)
            let missingDoubleForkMarkers = runSpec.fixtureCase == "double_fork_daemonization"
                ? linuxVzInertDoubleForkSensorMarkersV1.filter {
                    !linuxVzInertSerialContainsExactMarker(serialData, marker: $0)
                } : []
            let missingReparentingMarkers = runSpec.fixtureCase == "reparenting"
                ? linuxVzInertReparentingSensorMarkersV1.filter {
                    !linuxVzInertSerialContainsExactMarker(serialData, marker: $0)
                } : []
            let missingSetsidMarkers = runSpec.fixtureCase == "setsid_escape"
                ? linuxVzInertSetsidSensorMarkersV1.filter {
                    !linuxVzInertSerialContainsExactMarker(serialData, marker: $0)
                } : []
            let missingCredentialMarkers = runSpec.fixtureCase == "credential_change"
                ? linuxVzInertCredentialSensorMarkersV1.filter {
                    !linuxVzInertSerialContainsExactMarker(serialData, marker: $0)
                } : []
            let missingDynamicLibraryMarkers = runSpec.fixtureCase == "dynamic_library_load"
                ? linuxVzInertDynamicLibrarySensorMarkersV1.filter {
                    !linuxVzInertSerialContainsExactMarker(serialData, marker: $0)
                } : []
            let missingPackageIsolationMarkers = runSpec.fixtureCase == "all_protected_assets_denied"
                ? [
                    "WHOATHERE_SENSOR protected_assets_read_denied=7",
                    "WHOATHERE_SENSOR protected_assets_write_denied=7"
                ].filter {
                    !linuxVzInertSerialContainsExactMarker(serialData, marker: $0)
                } : []
            let missingIPv4Markers = runSpec.fixtureCase == "ipv4_connect"
                ? linuxVzInertIPv4ConnectSensorMarkersV1.filter {
                    !linuxVzInertSerialContainsExactMarker(serialData, marker: $0)
                } : []
            let missingIPv6Markers = runSpec.fixtureCase == "ipv6_connect"
                ? linuxVzInertIPv6ConnectSensorMarkersV1.filter {
                    !linuxVzInertSerialContainsExactMarker(serialData, marker: $0)
                } : []
            let missingUDPMarkers = runSpec.fixtureCase == "udp_send"
                ? linuxVzInertUDPSendSensorMarkersV1.filter {
                    !linuxVzInertSerialContainsExactMarker(serialData, marker: $0)
                } : []
            let missingLoopbackMarkers = runSpec.fixtureCase == "loopback_connect"
                ? linuxVzInertLoopbackConnectSensorMarkersV1.filter {
                    !linuxVzInertSerialContainsExactMarker(serialData, marker: $0)
                } : []
            let missingPrivateMarkers = runSpec.fixtureCase == "private_address_connect"
                ? linuxVzInertPrivateAddressConnectSensorMarkersV1.filter {
                    !linuxVzInertSerialContainsExactMarker(serialData, marker: $0)
                } : []
            let missingLinkLocalMarkers = runSpec.fixtureCase == "link_local_connect"
                ? linuxVzInertLinkLocalConnectSensorMarkersV1.filter {
                    !linuxVzInertSerialContainsExactMarker(serialData, marker: $0)
                } : []
            let missingMetadataMarkers = runSpec.fixtureCase == "metadata_address_connect"
                ? linuxVzInertMetadataAddressConnectSensorMarkersV1.filter {
                    !linuxVzInertSerialContainsExactMarker(serialData, marker: $0)
                } : []
            let missingPublicMarkers = runSpec.fixtureCase == "public_address_connect"
                ? linuxVzInertPublicAddressConnectSensorMarkersV1.filter {
                    !linuxVzInertSerialContainsExactMarker(serialData, marker: $0)
                } : []
            let missingDNSPlaintextMarkers = runSpec.fixtureCase == "dns_plaintext"
                ? linuxVzInertDNSPlaintextSensorMarkersV1.filter {
                    !linuxVzInertSerialContainsExactMarker(serialData, marker: $0)
                } : []
            let missingDNSMalformedMarkers = runSpec.fixtureCase == "dns_malformed"
                ? linuxVzInertDNSMalformedSensorMarkersV1.filter {
                    !linuxVzInertSerialContainsExactMarker(serialData, marker: $0)
                } : []
            let missingEncryptedDNSMarkers = runSpec.fixtureCase == "encrypted_dns_connect"
                ? linuxVzInertEncryptedDNSSensorMarkersV1.filter {
                    !linuxVzInertSerialContainsExactMarker(serialData, marker: $0)
                } : []
            let missingNormalExitMarkers = runSpec.fixtureCase == "normal_exit"
                ? linuxVzInertNormalExitSensorMarkersV1.filter {
                    !linuxVzInertSerialContainsExactMarker(serialData, marker: $0)
                } : []
            let missingTimeoutMarkers = runSpec.fixtureCase == "timeout"
                ? linuxVzInertTimeoutSensorMarkersV1.filter {
                    !linuxVzInertSerialContainsExactMarker(serialData, marker: $0)
                } : []
            let missingTermResistanceMarkers = runSpec.fixtureCase == "term_resistance"
                ? linuxVzInertTermResistanceSensorMarkersV1.filter {
                    !linuxVzInertSerialContainsExactMarker(serialData, marker: $0)
                } : []
            let missingEscapedSessionMarkers = runSpec.fixtureCase == "escaped_session"
                ? linuxVzInertEscapedSessionSensorMarkersV1.filter {
                    !linuxVzInertSerialContainsExactMarker(serialData, marker: $0)
                } : []
            let missingReparentedChildMarkers = runSpec.fixtureCase == "reparented_child"
                ? linuxVzInertReparentedChildSensorMarkersV1.filter {
                    !linuxVzInertSerialContainsExactMarker(serialData, marker: $0)
                } : []
            let missingBackgroundListenerMarkers = runSpec.fixtureCase == "background_listener"
                ? linuxVzInertBackgroundListenerSensorMarkersV1.filter {
                    !linuxVzInertSerialContainsExactMarker(serialData, marker: $0)
                } : []
            missingBaseMarkers = missingProcessMarkers + missingDoubleForkMarkers
                + missingReparentingMarkers + missingSetsidMarkers + missingCredentialMarkers
                + missingDynamicLibraryMarkers + missingIPv4Markers + missingIPv6Markers
                + missingPackageIsolationMarkers
                + missingUDPMarkers + missingLoopbackMarkers + missingPrivateMarkers
                + missingLinkLocalMarkers + missingMetadataMarkers + missingPublicMarkers
                + missingDNSPlaintextMarkers
                + missingDNSMalformedMarkers
                + missingEncryptedDNSMarkers
                + missingNormalExitMarkers
                + missingTimeoutMarkers
                + missingTermResistanceMarkers
                + missingEscapedSessionMarkers
                + missingReparentedChildMarkers
                + missingBackgroundListenerMarkers
        } else if ["kernel_config_and_btf", "cgroup_v2"].contains(runSpec.fixtureCase) {
            missingBaseMarkers = linuxVzInertMissingCapabilityMarkers(serialData)
        } else if runSpec.fixtureCase == "bpf_reservation_failure" {
            let missingCapabilities = linuxVzInertMissingCapabilityMarkers(serialData)
            let missingDropMarkers = linuxVzInertBPFReservationFailureSensorMarkersV1.filter {
                !linuxVzInertSerialContainsExactMarker(serialData, marker: $0)
            }
            missingBaseMarkers = missingCapabilities + missingDropMarkers
        } else if runSpec.fixtureCase == "fanotify_queue_overflow" {
            let missingCapabilities = linuxVzInertMissingCapabilityMarkers(serialData)
            let missingDropMarkers = linuxVzInertFanotifyQueueOverflowSensorMarkersV1.filter {
                !linuxVzInertSerialContainsExactMarker(serialData, marker: $0)
            }
            missingBaseMarkers = missingCapabilities + missingDropMarkers
        } else if runSpec.fixtureCase == "host_frame_overflow" {
            let missingCapabilities = linuxVzInertMissingCapabilityMarkers(serialData)
            let missingDropMarkers = linuxVzInertHostFrameOverflowSensorMarkersV1.filter {
                !linuxVzInertSerialContainsExactMarker(serialData, marker: $0)
            }
            missingBaseMarkers = missingCapabilities + missingDropMarkers
        } else {
            let missingCapabilities = linuxVzInertMissingCapabilityMarkers(serialData)
            let missingFileMarkers = linuxVzInertFileSensorMarkersV1.filter {
                !linuxVzInertSerialContainsExactMarker(serialData, marker: $0)
            }
            missingBaseMarkers = missingCapabilities + missingFileMarkers
        }
        let signedMarkers = [
            "WHOATHERE_LINUX_VZ_SIGNED_INERT_BEGIN",
            "WHOATHERE_CAPABILITY virtio_vsock=loaded",
            "WHOATHERE_CAPABILITY guest_receipt_signing=passed",
            "WHOATHERE_LINUX_VZ_SIGNED_INERT_OK"
        ]
        let missingSignedMarkers = signedMarkers.filter {
            !linuxVzInertSerialContainsExactMarker(serialData, marker: $0)
        }
        let serialText = String(decoding: serialData, as: UTF8.self)
        let signerMarkersPresent = linuxVzInertSerialContainsExactMarker(
            serialData,
            marker: "WHOATHERE_GUEST_SIGNER_READY port=40551"
        ) && serialText.contains("WHOATHERE_GUEST_SIGNER_RECEIPT_OK challenge_sha256=")
        let packetSensor: PacketSensorResult
        if let hostSensorDeathCollection {
            packetSensor = PacketSensorResult(
                frameCount: hostSensorDeathCollection.ingressFrameCount,
                ingressFrameCount: hostSensorDeathCollection.ingressFrameCount,
                droppedFrameCount: 0,
                matchedFrameCount: 0,
                bootstrapFrameCount: 0,
                uniqueSequenceCount: 0,
                duplicateFrameCount: 0,
                unexpectedFrameCount: hostSensorDeathCollection.ingressFrameCount,
                unexpectedFrameKinds: [],
                healthy: hostSensorDeathCollection.healthy,
                terminal: hostSensorDeathCollection.terminal
            )
        } else {
            packetSensor = drainRawFrames(
                fileDescriptor: sockets[1],
                networkFixtureCase: networkFixtureCase,
                networkSourcePort: networkSourcePort,
                hostFrameTriggerCount: hostFrameTriggerCount,
                boundedHostFrames: boundedHostFrames
            )
        }
        let finalKernelSHA256 = try fileSHA256(options.kernel)
        let finalInitramfsSHA256 = try fileSHA256(options.initramfs)
        let imageIdentityStable = finalKernelSHA256 == kernelSHA256
            && finalInitramfsSHA256 == initramfsSHA256
        guard missingBaseMarkers.isEmpty, missingSignedMarkers.isEmpty, signerMarkersPresent,
              imageIdentityStable else {
            throw HarnessError.verificationFailed
        }
        let hostEvidenceJSON: Data
        let hostEvidencePayloadSHA256: String
        let hostClaims: LinuxVzTelemetryHostObservationClaims
        let cloneDestroyed = configuration.storageDevices.isEmpty
        if runSpec.fixtureCase == "host_sensor_death" {
            guard let hostSensorDeathCollection,
                  hostSensorDeathCollection.workerStarted,
                  hostSensorDeathCollection.injected,
                  hostSensorDeathCollection.workerTerminated,
                  packetSensor.frameCount == 0,
                  packetSensor.ingressFrameCount == 0,
                  packetSensor.droppedFrameCount == 0,
                  packetSensor.unexpectedFrameCount == 0,
                  !packetSensor.healthy,
                  packetSensor.terminal == "injected_sensor_death",
                  cloneDestroyed else {
                throw HarnessError.verificationFailed
            }
            let hostEvidence = try makeLinuxVzHostSensorDeathHostEvidencePayload(
                requestFrameBytes: UInt64(requestData.count),
                responseBytes: UInt64(responseData.count),
                rawFrameCount: UInt64(packetSensor.frameCount),
                packetSensorHealthy: packetSensor.healthy,
                packetSensorTerminal: packetSensor.terminal,
                vmStarted: true,
                vmStopped: true,
                cloneDestroyed: cloneDestroyed,
                storageDeviceCount: UInt64(configuration.storageDevices.count)
            )
            hostEvidenceJSON = hostEvidence.canonicalJSON
            hostEvidencePayloadSHA256 = hostEvidence.payloadSHA256
            hostClaims = hostEvidence.claims
        } else if runSpec.fixtureCase == "host_frame_overflow" {
            guard let sourcePort = networkSourcePort,
                  let triggerCount = hostFrameTriggerCount,
                  triggerCount == 512,
                  packetSensor.ingressFrameCount == 512,
                  packetSensor.frameCount == 64,
                  packetSensor.droppedFrameCount == 448,
                  packetSensor.matchedFrameCount == packetSensor.frameCount,
                  packetSensor.uniqueSequenceCount == packetSensor.frameCount,
                  packetSensor.duplicateFrameCount == 0,
                  packetSensor.unexpectedFrameCount == 0,
                  packetSensor.healthy else {
                throw HarnessError.verificationFailed
            }
            let hostEvidence = try makeLinuxVzHostFrameOverflowHostEvidencePayloadV1(
                triggerFrameCount: triggerCount,
                ingressFrameCount: UInt64(packetSensor.ingressFrameCount),
                observedFrameCount: UInt64(packetSensor.frameCount),
                uniqueSequenceCount: UInt64(packetSensor.uniqueSequenceCount),
                duplicateFrameCount: UInt64(packetSensor.duplicateFrameCount),
                unexpectedFrameCount: UInt64(packetSensor.unexpectedFrameCount),
                sourcePort: sourcePort,
                hostFrameQueueCapacity: 64,
                packetSensorHealthy: packetSensor.healthy,
                packetSensorTerminal: packetSensor.terminal,
                storageDeviceCount: UInt64(configuration.storageDevices.count)
            )
            hostEvidenceJSON = hostEvidence.canonicalJSON
            hostEvidencePayloadSHA256 = hostEvidence.payloadSHA256
            hostClaims = hostEvidence.claims
        } else if let sourcePort = networkSourcePort, let networkFixtureCase {
            let expectedRawFrameCount = networkFixtureCase == "loopback_connect" ? 0 :
                (networkFixtureCase == "ipv6_connect" ? 2 : 1)
            let expectedBootstrapFrameCount = networkFixtureCase == "ipv6_connect" ? 1 : 0
            let expectedMatchedFrameCount = networkFixtureCase == "loopback_connect" ? 0 : 1
            if packetSensor.frameCount != expectedRawFrameCount ||
                packetSensor.matchedFrameCount != expectedMatchedFrameCount ||
                packetSensor.bootstrapFrameCount != expectedBootstrapFrameCount ||
                packetSensor.unexpectedFrameCount != 0 {
                fputs(
                    "WHOATHERE_HOST_PACKET_DIAGNOSTIC raw=\(packetSensor.frameCount) " +
                    "matched=\(packetSensor.matchedFrameCount) " +
                    "bootstrap=\(packetSensor.bootstrapFrameCount) " +
                    "unexpected=\(packetSensor.unexpectedFrameCount) " +
                    "kinds=\(packetSensor.unexpectedFrameKinds.joined(separator: ","))\n",
                    stderr
                )
                throw HarnessError.verificationFailed
            }
            if networkFixtureCase == "loopback_connect" {
                let hostEvidence = try makeLinuxVzInertHostEvidencePayload(
                    rawFrameCount: UInt64(packetSensor.frameCount),
                    packetSensorHealthy: packetSensor.healthy,
                    packetSensorTerminal: packetSensor.terminal,
                    guestChannelTerminated: true,
                    vmStarted: true,
                    vmStopped: true,
                    cloneDestroyed: cloneDestroyed,
                    storageDeviceCount: UInt64(configuration.storageDevices.count)
                )
                hostEvidenceJSON = hostEvidence.canonicalJSON
                hostEvidencePayloadSHA256 = hostEvidence.payloadSHA256
                hostClaims = hostEvidence.claims
            } else {
            let hostEvidence: LinuxVzNetworkHostEvidencePayload
            if networkFixtureCase == "ipv4_connect" {
                hostEvidence = try makeLinuxVzIPv4ConnectHostEvidencePayload(
                    sourcePort: sourcePort,
                    rawFrameCount: UInt64(packetSensor.frameCount),
                    matchedFrameCount: UInt64(packetSensor.matchedFrameCount),
                    unexpectedFrameCount: UInt64(packetSensor.unexpectedFrameCount),
                    packetSensorHealthy: packetSensor.healthy,
                    packetSensorTerminal: packetSensor.terminal,
                    storageDeviceCount: UInt64(configuration.storageDevices.count)
                )
            } else if networkFixtureCase == "ipv6_connect" {
                hostEvidence = try makeLinuxVzIPv6ConnectHostEvidencePayload(
                    sourcePort: sourcePort,
                    rawFrameCount: UInt64(packetSensor.frameCount),
                    matchedFrameCount: UInt64(packetSensor.matchedFrameCount),
                    unexpectedFrameCount: UInt64(packetSensor.unexpectedFrameCount),
                    packetSensorHealthy: packetSensor.healthy,
                    packetSensorTerminal: packetSensor.terminal,
                    storageDeviceCount: UInt64(configuration.storageDevices.count)
                )
            } else if networkFixtureCase == "udp_send" {
                hostEvidence = try makeLinuxVzUDPSendHostEvidencePayload(
                    sourcePort: sourcePort,
                    rawFrameCount: UInt64(packetSensor.frameCount),
                    matchedFrameCount: UInt64(packetSensor.matchedFrameCount),
                    unexpectedFrameCount: UInt64(packetSensor.unexpectedFrameCount),
                    packetSensorHealthy: packetSensor.healthy,
                    packetSensorTerminal: packetSensor.terminal,
                    storageDeviceCount: UInt64(configuration.storageDevices.count)
                )
            } else if networkFixtureCase == "private_address_connect" {
                hostEvidence = try makeLinuxVzPrivateAddressConnectHostEvidencePayload(
                    sourcePort: sourcePort,
                    rawFrameCount: UInt64(packetSensor.frameCount),
                    matchedFrameCount: UInt64(packetSensor.matchedFrameCount),
                    unexpectedFrameCount: UInt64(packetSensor.unexpectedFrameCount),
                    packetSensorHealthy: packetSensor.healthy,
                    packetSensorTerminal: packetSensor.terminal,
                    storageDeviceCount: UInt64(configuration.storageDevices.count)
                )
            } else if networkFixtureCase == "link_local_connect" {
                hostEvidence = try makeLinuxVzLinkLocalConnectHostEvidencePayload(
                    sourcePort: sourcePort,
                    rawFrameCount: UInt64(packetSensor.frameCount),
                    matchedFrameCount: UInt64(packetSensor.matchedFrameCount),
                    unexpectedFrameCount: UInt64(packetSensor.unexpectedFrameCount),
                    packetSensorHealthy: packetSensor.healthy,
                    packetSensorTerminal: packetSensor.terminal,
                    storageDeviceCount: UInt64(configuration.storageDevices.count)
                )
            } else if networkFixtureCase == "metadata_address_connect" {
                hostEvidence = try makeLinuxVzMetadataAddressConnectHostEvidencePayload(
                    sourcePort: sourcePort,
                    rawFrameCount: UInt64(packetSensor.frameCount),
                    matchedFrameCount: UInt64(packetSensor.matchedFrameCount),
                    unexpectedFrameCount: UInt64(packetSensor.unexpectedFrameCount),
                    packetSensorHealthy: packetSensor.healthy,
                    packetSensorTerminal: packetSensor.terminal,
                    storageDeviceCount: UInt64(configuration.storageDevices.count)
                )
            } else if networkFixtureCase == "public_address_connect" {
                hostEvidence = try makeLinuxVzPublicAddressConnectHostEvidencePayload(
                    sourcePort: sourcePort,
                    rawFrameCount: UInt64(packetSensor.frameCount),
                    matchedFrameCount: UInt64(packetSensor.matchedFrameCount),
                    unexpectedFrameCount: UInt64(packetSensor.unexpectedFrameCount),
                    packetSensorHealthy: packetSensor.healthy,
                    packetSensorTerminal: packetSensor.terminal,
                    storageDeviceCount: UInt64(configuration.storageDevices.count)
                )
            } else if networkFixtureCase == "dns_plaintext" {
                hostEvidence = try makeLinuxVzDNSPlaintextHostEvidencePayload(
                    sourcePort: sourcePort,
                    rawFrameCount: UInt64(packetSensor.frameCount),
                    matchedFrameCount: UInt64(packetSensor.matchedFrameCount),
                    unexpectedFrameCount: UInt64(packetSensor.unexpectedFrameCount),
                    packetSensorHealthy: packetSensor.healthy,
                    packetSensorTerminal: packetSensor.terminal,
                    storageDeviceCount: UInt64(configuration.storageDevices.count)
                )
            } else if networkFixtureCase == "dns_malformed" {
                hostEvidence = try makeLinuxVzDNSMalformedHostEvidencePayload(
                    sourcePort: sourcePort,
                    rawFrameCount: UInt64(packetSensor.frameCount),
                    matchedFrameCount: UInt64(packetSensor.matchedFrameCount),
                    unexpectedFrameCount: UInt64(packetSensor.unexpectedFrameCount),
                    packetSensorHealthy: packetSensor.healthy,
                    packetSensorTerminal: packetSensor.terminal,
                    storageDeviceCount: UInt64(configuration.storageDevices.count)
                )
            } else if networkFixtureCase == "encrypted_dns_connect" {
                hostEvidence = try makeLinuxVzEncryptedDNSConnectHostEvidencePayload(
                    sourcePort: sourcePort,
                    rawFrameCount: UInt64(packetSensor.frameCount),
                    matchedFrameCount: UInt64(packetSensor.matchedFrameCount),
                    unexpectedFrameCount: UInt64(packetSensor.unexpectedFrameCount),
                    packetSensorHealthy: packetSensor.healthy,
                    packetSensorTerminal: packetSensor.terminal,
                    storageDeviceCount: UInt64(configuration.storageDevices.count)
                )
            } else {
                throw HarnessError.verificationFailed
            }
            hostEvidenceJSON = hostEvidence.canonicalJSON
            hostEvidencePayloadSHA256 = hostEvidence.payloadSHA256
            hostClaims = hostEvidence.claims
            }
        } else {
            let hostEvidence = try makeLinuxVzInertHostEvidencePayload(
                rawFrameCount: UInt64(packetSensor.frameCount),
                packetSensorHealthy: packetSensor.healthy,
                packetSensorTerminal: packetSensor.terminal,
                guestChannelTerminated: true,
                vmStarted: true,
                vmStopped: true,
                cloneDestroyed: cloneDestroyed,
                storageDeviceCount: UInt64(configuration.storageDevices.count),
                observedTerminal: runSpec.expectedTerminal
            )
            hostEvidenceJSON = hostEvidence.canonicalJSON
            hostEvidencePayloadSHA256 = hostEvidence.payloadSHA256
            hostClaims = hostEvidence.claims
        }
        var hostSigningSeed = try readProtectedSeed(options.hostSigningSeed)
        let hostPublicKey: Data
        do {
            hostPublicKey = try Curve25519.Signing.PrivateKey(
                rawRepresentation: hostSigningSeed
            ).publicKey.rawRepresentation
        } catch {
            hostSigningSeed.resetBytes(in: 0..<hostSigningSeed.count)
            throw HarnessError.invalidInput("host_signing_seed")
        }
        let hostReceipt = try signLinuxVzTelemetryHostReceipt(
            challenge: challenge,
            runSpec: runSpec,
            backend: backend,
            claims: hostClaims,
            signingSeed: &hostSigningSeed
        )
        let verifiedHost = try verifyLinuxVzTelemetryHostReceipt(
            hostReceipt,
            challenge: challenge,
            runSpec: runSpec,
            backend: backend,
            verifyingKey: hostPublicKey,
            expectedClaims: hostClaims
        )
        let completeCase = try verifyLinuxVzObservationCompleteConformanceCase(
            challenge: challenge,
            runSpec: runSpec,
            backend: backend,
            guest: verifiedGuest,
            host: verifiedHost
        )
        try writeNewPrivateFile(options.receiptOutput, data: receipt)
        try writeNewPrivateFile(options.hostEvidenceOutput, data: hostEvidenceJSON)
        try writeNewPrivateFile(options.hostReceiptOutput, data: hostReceipt)
        emitJSON([
            "schema_version": "whoathere.linux_vz_signed_conformance_result.v1",
            "status": "ok",
            "challenge_sha256": challenge.challengeSHA256,
            "run_spec_sha256": runSpec.runSpecSHA256,
            "backend_identity_sha256": backend.identitySHA256,
            "receipt_sha256": dataSHA256(receipt),
            "host_evidence_payload_sha256": hostEvidencePayloadSHA256,
            "host_receipt_sha256": dataSHA256(hostReceipt),
            "complete_conformance_case_verified": completeCase.guestReceiptPresent
                && completeCase.hostReceiptPresent,
            "fixture_case": runSpec.fixtureCase,
            "guest_evidence_payload_sha256": guestEvidencePayloadSHA256,
            "guest_event_count": String(guestEventCount),
            "raw_frame_count": packetSensor.frameCount,
            "dropped_frame_count": String(hostClaims.droppedFrameCount),
            "packet_sensor_healthy": packetSensor.healthy,
            "clone_destroyed": hostClaims.cloneDestroyed,
            "vm_stopped": true,
            "image_identity_stable": imageIdentityStable,
            "execution_authority": false,
            "external_route": false,
            "package_execution": false,
            "sync_back": false,
            "exit_code": 0
        ])
        return 0
    }

    private static func runChannelInterruptionCase(
        options: Options,
        requestData: Data,
        runSpec: LinuxVzTelemetryConformanceRunSpec,
        challenge: LinuxVzTelemetryConformanceChallenge,
        backend: UnqualifiedLinuxVzTelemetryBackendIdentity,
        configuration: VZVirtualMachineConfiguration,
        virtualMachine: VZVirtualMachine,
        queue: DispatchQueue,
        connection: VZVirtioSocketConnection,
        serialOutput: FileHandle,
        rawFrameSocket: Int32,
        deadline: Date,
        initialKernelSHA256: String,
        initialInitramfsSHA256: String
    ) throws -> Int32 {
        guard requestData.count > 16 else { throw HarnessError.verificationFailed }
        let transmittedPrefix = Data(requestData.prefix(16))
        try writeAll(connection.fileDescriptor, data: transmittedPrefix)
        guard shutdown(connection.fileDescriptor, SHUT_WR) == 0 else {
            throw HarnessError.socketIO
        }
        let responseData = try readToEOFAllowingEmpty(
            connection.fileDescriptor,
            maximum: maximumLinuxVzGuestSignerResponseFrameBytesV1
        )
        guard responseData.isEmpty else { throw HarnessError.verificationFailed }
        try waitForStop(virtualMachine: virtualMachine, queue: queue, deadline: deadline)
        try serialOutput.synchronize()
        let serialData = try Data(contentsOf: options.serialLog)
        if let serialText = String(data: serialData, encoding: .utf8) {
            fputs(serialText, stderr)
        }
        let missingCapabilities = linuxVzInertMissingCapabilityMarkers(serialData)
        let missingInterruptionMarkers = linuxVzInertChannelInterruptionMarkersV1.filter {
            !linuxVzInertSerialContainsExactMarker(serialData, marker: $0)
        }
        let serialLines = String(decoding: serialData, as: UTF8.self)
            .split(whereSeparator: \.isNewline)
            .map(String.init)
        let requiredHostChannelMarkers = [
            "WHOATHERE_LINUX_VZ_SIGNED_INERT_BEGIN",
            "WHOATHERE_CAPABILITY virtio_vsock=loaded",
            "WHOATHERE_GUEST_SIGNER_READY port=40551"
        ]
        let missingHostChannelMarkers = requiredHostChannelMarkers.filter {
            !linuxVzInertSerialContainsExactMarker(serialData, marker: $0)
        }
        let forbiddenEvidence = serialLines.contains { line in
            line == "WHOATHERE_CAPABILITY guest_receipt_signing=passed"
                || line == "WHOATHERE_LINUX_VZ_SIGNED_INERT_OK"
                || line.hasPrefix("WHOATHERE_SENSOR")
                || line.hasPrefix("WHOATHERE_GUEST_PROCESS_EVIDENCE ")
                || line.hasPrefix("WHOATHERE_GUEST_FILE_EVIDENCE ")
                || line.hasPrefix("WHOATHERE_GUEST_NETWORK_EVIDENCE ")
                || line.hasPrefix("WHOATHERE_GUEST_TEARDOWN_EVIDENCE ")
                || line.hasPrefix("WHOATHERE_GUEST_SIGNER_RECEIPT_OK ")
        }
        let packetSensor = drainRawFrames(
            fileDescriptor: rawFrameSocket,
            networkFixtureCase: nil,
            networkSourcePort: nil,
            hostFrameTriggerCount: nil,
            boundedHostFrames: nil
        )
        let finalKernelSHA256 = try fileSHA256(options.kernel)
        let finalInitramfsSHA256 = try fileSHA256(options.initramfs)
        let imageIdentityStable = finalKernelSHA256 == initialKernelSHA256
            && finalInitramfsSHA256 == initialInitramfsSHA256
        let cloneDestroyed = configuration.storageDevices.isEmpty
        guard missingCapabilities.isEmpty,
              missingInterruptionMarkers.isEmpty,
              missingHostChannelMarkers.isEmpty,
              !forbiddenEvidence,
              packetSensor.frameCount == 0,
              packetSensor.droppedFrameCount == 0,
              packetSensor.unexpectedFrameCount == 0,
              packetSensor.healthy,
              packetSensor.terminal == "drained_would_block",
              imageIdentityStable,
              cloneDestroyed else {
            throw HarnessError.verificationFailed
        }
        let hostEvidence = try makeLinuxVzChannelInterruptionHostEvidencePayload(
            requestFrameBytes: UInt64(requestData.count),
            rawFrameCount: UInt64(packetSensor.frameCount),
            packetSensorHealthy: packetSensor.healthy,
            packetSensorTerminal: packetSensor.terminal,
            vmStarted: true,
            vmStopped: true,
            cloneDestroyed: cloneDestroyed,
            storageDeviceCount: UInt64(configuration.storageDevices.count)
        )
        var hostSigningSeed = try readProtectedSeed(options.hostSigningSeed)
        let hostPublicKey: Data
        do {
            hostPublicKey = try Curve25519.Signing.PrivateKey(
                rawRepresentation: hostSigningSeed
            ).publicKey.rawRepresentation
        } catch {
            hostSigningSeed.resetBytes(in: 0..<hostSigningSeed.count)
            throw HarnessError.invalidInput("host_signing_seed")
        }
        let hostReceipt = try signLinuxVzTelemetryHostReceipt(
            challenge: challenge,
            runSpec: runSpec,
            backend: backend,
            claims: hostEvidence.claims,
            signingSeed: &hostSigningSeed
        )
        let verifiedHost = try verifyLinuxVzTelemetryHostReceipt(
            hostReceipt,
            challenge: challenge,
            runSpec: runSpec,
            backend: backend,
            verifyingKey: hostPublicKey,
            expectedClaims: hostEvidence.claims
        )
        let completeCase = try verifyLinuxVzObservationCompleteConformanceCase(
            challenge: challenge,
            runSpec: runSpec,
            backend: backend,
            guest: nil,
            host: verifiedHost
        )
        guard !completeCase.guestReceiptPresent, completeCase.hostReceiptPresent else {
            throw HarnessError.verificationFailed
        }
        try writeNewPrivateFile(options.hostEvidenceOutput, data: hostEvidence.canonicalJSON)
        try writeNewPrivateFile(options.hostReceiptOutput, data: hostReceipt)
        emitJSON([
            "schema_version": "whoathere.linux_vz_signed_conformance_result.v1",
            "status": "ok",
            "challenge_sha256": challenge.challengeSHA256,
            "run_spec_sha256": runSpec.runSpecSHA256,
            "backend_identity_sha256": backend.identitySHA256,
            "host_evidence_payload_sha256": hostEvidence.payloadSHA256,
            "host_receipt_sha256": dataSHA256(hostReceipt),
            "complete_conformance_case_verified": true,
            "fixture_case": runSpec.fixtureCase,
            "guest_receipt_present": false,
            "guest_response_bytes": "0",
            "channel_transmitted_prefix_bytes": "16",
            "raw_frame_count": packetSensor.frameCount,
            "dropped_frame_count": String(hostEvidence.claims.droppedFrameCount),
            "packet_sensor_healthy": packetSensor.healthy,
            "clone_destroyed": hostEvidence.claims.cloneDestroyed,
            "vm_stopped": true,
            "image_identity_stable": imageIdentityStable,
            "execution_authority": false,
            "external_route": false,
            "package_execution": false,
            "sync_back": false,
            "exit_code": 0
        ])
        return 0
    }

    private static func runVmStopCase(
        options: Options,
        requestData: Data,
        runSpec: LinuxVzTelemetryConformanceRunSpec,
        challenge: LinuxVzTelemetryConformanceChallenge,
        backend: UnqualifiedLinuxVzTelemetryBackendIdentity,
        configuration: VZVirtualMachineConfiguration,
        virtualMachine: VZVirtualMachine,
        queue: DispatchQueue,
        connection: VZVirtioSocketConnection,
        serialOutput: FileHandle,
        rawFrameSocket: Int32,
        deadline: Date,
        initialKernelSHA256: String,
        initialInitramfsSHA256: String
    ) throws -> Int32 {
        let activeMarker = "WHOATHERE_SENSOR vm_stop_fixture=active"
        try waitForSerialMarker(
            activeMarker,
            virtualMachine: virtualMachine,
            queue: queue,
            serialOutput: serialOutput,
            serialLog: options.serialLog,
            deadline: deadline
        )
        try stopVirtualMachine(virtualMachine: virtualMachine, queue: queue)
        let responseData = try readToEOFAllowingEmpty(
            connection.fileDescriptor,
            maximum: maximumLinuxVzGuestSignerResponseFrameBytesV1
        )
        guard responseData.isEmpty else { throw HarnessError.verificationFailed }
        try serialOutput.synchronize()
        let serialData = try Data(contentsOf: options.serialLog)
        if let serialText = String(data: serialData, encoding: .utf8) {
            fputs(serialText, stderr)
        }
        let requiredMarkers = [
            "WHOATHERE_LINUX_VZ_SIGNED_INERT_BEGIN",
            "WHOATHERE_CAPABILITY kernel_release=6.18.35-0-virt",
            "WHOATHERE_CAPABILITY architecture=aarch64",
            "WHOATHERE_CAPABILITY kernel_btf=present",
            "WHOATHERE_CAPABILITY kernel_btf_sha256=sha256:d7f143446e11cfd67fa53392616afdbca6511a6af432e6bd56fb053aa4e7becb",
            "WHOATHERE_CAPABILITY cgroup_v2=mounted",
            "WHOATHERE_CAPABILITY bpf_fs=mounted",
            "WHOATHERE_CAPABILITY fanotify_init=available",
            "WHOATHERE_CAPABILITY bpf_program_load=available",
            "WHOATHERE_CAPABILITY syscall_probe=passed",
            "WHOATHERE_CAPABILITY virtio_vsock=loaded",
            "WHOATHERE_CAPABILITY virtio_net=loaded",
            "WHOATHERE_GUEST_SIGNER_READY port=40551",
            activeMarker
        ]
        let missingMarkers = requiredMarkers.filter {
            !linuxVzInertSerialContainsExactMarker(serialData, marker: $0)
        }
        let serialLines = String(decoding: serialData, as: UTF8.self)
            .split(whereSeparator: \.isNewline)
            .map(String.init)
        let forbiddenEvidence = serialLines.contains { line in
            line == "WHOATHERE_CAPABILITY guest_receipt_signing=passed"
                || line == "WHOATHERE_LINUX_VZ_SIGNED_INERT_OK"
                || line == "WHOATHERE_LINUX_VZ_SIGNED_INERT_FAILED"
                || line.hasPrefix("WHOATHERE_GUEST_PROCESS_EVIDENCE ")
                || line.hasPrefix("WHOATHERE_GUEST_FILE_EVIDENCE ")
                || line.hasPrefix("WHOATHERE_GUEST_NETWORK_EVIDENCE ")
                || line.hasPrefix("WHOATHERE_GUEST_TEARDOWN_EVIDENCE ")
                || line.hasPrefix("WHOATHERE_GUEST_SIGNER_RECEIPT_OK ")
                || line.hasPrefix("WHOATHERE_GUEST_SIGNER_FAILED ")
                || (line.hasPrefix("WHOATHERE_SENSOR ") && line != activeMarker)
                || line.hasPrefix("WHOATHERE_SENSOR_PROCESS_PROBE_")
        }
        let packetSensor = drainRawFrames(
            fileDescriptor: rawFrameSocket,
            networkFixtureCase: nil,
            networkSourcePort: nil,
            hostFrameTriggerCount: nil,
            boundedHostFrames: nil
        )
        let finalKernelSHA256 = try fileSHA256(options.kernel)
        let finalInitramfsSHA256 = try fileSHA256(options.initramfs)
        let imageIdentityStable = finalKernelSHA256 == initialKernelSHA256
            && finalInitramfsSHA256 == initialInitramfsSHA256
        let cloneDestroyed = configuration.storageDevices.isEmpty
        guard missingMarkers.isEmpty,
              !forbiddenEvidence,
              packetSensor.frameCount == 0,
              packetSensor.droppedFrameCount == 0,
              packetSensor.unexpectedFrameCount == 0,
              packetSensor.healthy,
              packetSensor.terminal == "drained_would_block",
              queue.sync(execute: { virtualMachine.state == .stopped }),
              imageIdentityStable,
              cloneDestroyed else {
            throw HarnessError.verificationFailed
        }
        let hostEvidence = try makeLinuxVzVmStopHostEvidencePayload(
            requestFrameBytes: UInt64(requestData.count),
            rawFrameCount: UInt64(packetSensor.frameCount),
            packetSensorHealthy: packetSensor.healthy,
            packetSensorTerminal: packetSensor.terminal,
            vmStarted: true,
            vmStopped: true,
            cloneDestroyed: cloneDestroyed,
            storageDeviceCount: UInt64(configuration.storageDevices.count)
        )
        var hostSigningSeed = try readProtectedSeed(options.hostSigningSeed)
        let hostPublicKey: Data
        do {
            hostPublicKey = try Curve25519.Signing.PrivateKey(
                rawRepresentation: hostSigningSeed
            ).publicKey.rawRepresentation
        } catch {
            hostSigningSeed.resetBytes(in: 0..<hostSigningSeed.count)
            throw HarnessError.invalidInput("host_signing_seed")
        }
        let hostReceipt = try signLinuxVzTelemetryHostReceipt(
            challenge: challenge,
            runSpec: runSpec,
            backend: backend,
            claims: hostEvidence.claims,
            signingSeed: &hostSigningSeed
        )
        let verifiedHost = try verifyLinuxVzTelemetryHostReceipt(
            hostReceipt,
            challenge: challenge,
            runSpec: runSpec,
            backend: backend,
            verifyingKey: hostPublicKey,
            expectedClaims: hostEvidence.claims
        )
        let completeCase = try verifyLinuxVzObservationCompleteConformanceCase(
            challenge: challenge,
            runSpec: runSpec,
            backend: backend,
            guest: nil,
            host: verifiedHost
        )
        guard !completeCase.guestReceiptPresent, completeCase.hostReceiptPresent else {
            throw HarnessError.verificationFailed
        }
        try writeNewPrivateFile(options.hostEvidenceOutput, data: hostEvidence.canonicalJSON)
        try writeNewPrivateFile(options.hostReceiptOutput, data: hostReceipt)
        emitJSON([
            "schema_version": "whoathere.linux_vz_signed_conformance_result.v1",
            "status": "ok",
            "challenge_sha256": challenge.challengeSHA256,
            "run_spec_sha256": runSpec.runSpecSHA256,
            "backend_identity_sha256": backend.identitySHA256,
            "host_evidence_payload_sha256": hostEvidence.payloadSHA256,
            "host_receipt_sha256": dataSHA256(hostReceipt),
            "complete_conformance_case_verified": true,
            "fixture_case": runSpec.fixtureCase,
            "guest_receipt_present": false,
            "guest_response_bytes": "0",
            "vm_stop_fixture_active_marker_observed": true,
            "vm_stop_transmitted_request_bytes": String(requestData.count),
            "raw_frame_count": packetSensor.frameCount,
            "dropped_frame_count": String(hostEvidence.claims.droppedFrameCount),
            "packet_sensor_healthy": packetSensor.healthy,
            "clone_destroyed": hostEvidence.claims.cloneDestroyed,
            "vm_stopped": true,
            "image_identity_stable": imageIdentityStable,
            "execution_authority": false,
            "external_route": false,
            "package_execution": false,
            "sync_back": false,
            "exit_code": 0
        ])
        return 0
    }

    private static func runGuestSensorDeathCase(
        options: Options,
        requestData: Data,
        runSpec: LinuxVzTelemetryConformanceRunSpec,
        challenge: LinuxVzTelemetryConformanceChallenge,
        backend: UnqualifiedLinuxVzTelemetryBackendIdentity,
        configuration: VZVirtualMachineConfiguration,
        virtualMachine: VZVirtualMachine,
        queue: DispatchQueue,
        connection: VZVirtioSocketConnection,
        serialOutput: FileHandle,
        rawFrameSocket: Int32,
        deadline: Date,
        initialKernelSHA256: String,
        initialInitramfsSHA256: String
    ) throws -> Int32 {
        let responseData = try readToEOFAllowingEmpty(
            connection.fileDescriptor,
            maximum: maximumLinuxVzGuestSignerResponseFrameBytesV1
        )
        guard responseData.isEmpty else { throw HarnessError.verificationFailed }
        try waitForStop(virtualMachine: virtualMachine, queue: queue, deadline: deadline)
        try serialOutput.synchronize()
        let serialData = try Data(contentsOf: options.serialLog)
        if let serialText = String(data: serialData, encoding: .utf8) {
            fputs(serialText, stderr)
        }
        let activeMarker = "WHOATHERE_SENSOR guest_sensor_death_fixture=active"
        let requiredMarkers = [
            "WHOATHERE_LINUX_VZ_SIGNED_INERT_BEGIN",
            "WHOATHERE_CAPABILITY kernel_release=6.18.35-0-virt",
            "WHOATHERE_CAPABILITY architecture=aarch64",
            "WHOATHERE_CAPABILITY kernel_btf=present",
            "WHOATHERE_CAPABILITY kernel_btf_sha256=sha256:d7f143446e11cfd67fa53392616afdbca6511a6af432e6bd56fb053aa4e7becb",
            "WHOATHERE_CAPABILITY cgroup_v2=mounted",
            "WHOATHERE_CAPABILITY bpf_fs=mounted",
            "WHOATHERE_CAPABILITY fanotify_init=available",
            "WHOATHERE_CAPABILITY bpf_program_load=available",
            "WHOATHERE_CAPABILITY syscall_probe=passed",
            "WHOATHERE_CAPABILITY virtio_vsock=loaded",
            "WHOATHERE_CAPABILITY virtio_net=loaded",
            "WHOATHERE_GUEST_SIGNER_READY port=40551",
            activeMarker,
            "WHOATHERE_GUEST_SENSOR_DEATH observed_signal=9",
            "WHOATHERE_GUEST_SIGNER_FAILED reason=guest_sensor_death_injected",
            "WHOATHERE_CAPABILITY guest_receipt_signing=failed",
            "WHOATHERE_CAPABILITY external_route_configured=false",
            "WHOATHERE_CAPABILITY package_execution=false",
            "WHOATHERE_CAPABILITY sync_back=false",
            "WHOATHERE_LINUX_VZ_SIGNED_INERT_FAILED"
        ]
        let missingMarkers = requiredMarkers.filter {
            !linuxVzInertSerialContainsExactMarker(serialData, marker: $0)
        }
        let serialLines = String(decoding: serialData, as: UTF8.self)
            .split(whereSeparator: \.isNewline)
            .map(String.init)
        let forbiddenEvidence = serialLines.contains { line in
            line == "WHOATHERE_CAPABILITY guest_receipt_signing=passed"
                || line == "WHOATHERE_LINUX_VZ_SIGNED_INERT_OK"
                || line.hasPrefix("WHOATHERE_GUEST_PROCESS_EVIDENCE ")
                || line.hasPrefix("WHOATHERE_GUEST_FILE_EVIDENCE ")
                || line.hasPrefix("WHOATHERE_GUEST_NETWORK_EVIDENCE ")
                || line.hasPrefix("WHOATHERE_GUEST_TEARDOWN_EVIDENCE ")
                || line.hasPrefix("WHOATHERE_GUEST_SIGNER_RECEIPT_OK ")
                || (line.hasPrefix("WHOATHERE_SENSOR ") && line != activeMarker)
                || line.hasPrefix("WHOATHERE_SENSOR_PROCESS_PROBE_")
        }
        let packetSensor = drainRawFrames(
            fileDescriptor: rawFrameSocket,
            networkFixtureCase: nil,
            networkSourcePort: nil,
            hostFrameTriggerCount: nil,
            boundedHostFrames: nil
        )
        let finalKernelSHA256 = try fileSHA256(options.kernel)
        let finalInitramfsSHA256 = try fileSHA256(options.initramfs)
        let imageIdentityStable = finalKernelSHA256 == initialKernelSHA256
            && finalInitramfsSHA256 == initialInitramfsSHA256
        let cloneDestroyed = configuration.storageDevices.isEmpty
        guard missingMarkers.isEmpty,
              !forbiddenEvidence,
              packetSensor.frameCount == 0,
              packetSensor.droppedFrameCount == 0,
              packetSensor.unexpectedFrameCount == 0,
              packetSensor.healthy,
              packetSensor.terminal == "drained_would_block",
              imageIdentityStable,
              cloneDestroyed else {
            throw HarnessError.verificationFailed
        }
        let hostEvidence = try makeLinuxVzGuestSensorDeathHostEvidencePayload(
            requestFrameBytes: UInt64(requestData.count),
            rawFrameCount: UInt64(packetSensor.frameCount),
            packetSensorHealthy: packetSensor.healthy,
            packetSensorTerminal: packetSensor.terminal,
            vmStarted: true,
            vmStopped: true,
            cloneDestroyed: cloneDestroyed,
            storageDeviceCount: UInt64(configuration.storageDevices.count)
        )
        var hostSigningSeed = try readProtectedSeed(options.hostSigningSeed)
        let hostPublicKey: Data
        do {
            hostPublicKey = try Curve25519.Signing.PrivateKey(
                rawRepresentation: hostSigningSeed
            ).publicKey.rawRepresentation
        } catch {
            hostSigningSeed.resetBytes(in: 0..<hostSigningSeed.count)
            throw HarnessError.invalidInput("host_signing_seed")
        }
        let hostReceipt = try signLinuxVzTelemetryHostReceipt(
            challenge: challenge,
            runSpec: runSpec,
            backend: backend,
            claims: hostEvidence.claims,
            signingSeed: &hostSigningSeed
        )
        let verifiedHost = try verifyLinuxVzTelemetryHostReceipt(
            hostReceipt,
            challenge: challenge,
            runSpec: runSpec,
            backend: backend,
            verifyingKey: hostPublicKey,
            expectedClaims: hostEvidence.claims
        )
        let completeCase = try verifyLinuxVzObservationCompleteConformanceCase(
            challenge: challenge,
            runSpec: runSpec,
            backend: backend,
            guest: nil,
            host: verifiedHost
        )
        guard !completeCase.guestReceiptPresent, completeCase.hostReceiptPresent else {
            throw HarnessError.verificationFailed
        }
        try writeNewPrivateFile(options.hostEvidenceOutput, data: hostEvidence.canonicalJSON)
        try writeNewPrivateFile(options.hostReceiptOutput, data: hostReceipt)
        emitJSON([
            "schema_version": "whoathere.linux_vz_signed_conformance_result.v1",
            "status": "ok",
            "challenge_sha256": challenge.challengeSHA256,
            "run_spec_sha256": runSpec.runSpecSHA256,
            "backend_identity_sha256": backend.identitySHA256,
            "host_evidence_payload_sha256": hostEvidence.payloadSHA256,
            "host_receipt_sha256": dataSHA256(hostReceipt),
            "complete_conformance_case_verified": true,
            "fixture_case": runSpec.fixtureCase,
            "guest_receipt_present": false,
            "guest_response_bytes": "0",
            "guest_sensor_death_fixture_active_marker_observed": true,
            "guest_sensor_death_signal": "9",
            "guest_sensor_death_transmitted_request_bytes": String(requestData.count),
            "raw_frame_count": packetSensor.frameCount,
            "dropped_frame_count": String(hostEvidence.claims.droppedFrameCount),
            "packet_sensor_healthy": packetSensor.healthy,
            "clone_destroyed": hostEvidence.claims.cloneDestroyed,
            "vm_stopped": true,
            "image_identity_stable": imageIdentityStable,
            "execution_authority": false,
            "external_route": false,
            "package_execution": false,
            "sync_back": false,
            "exit_code": 0
        ])
        return 0
    }

    private static func waitForSignerReady(
        virtualMachine: VZVirtualMachine,
        queue: DispatchQueue,
        serialOutput: FileHandle,
        serialLog: URL,
        deadline: Date
    ) throws {
        while Date() < deadline {
            try? serialOutput.synchronize()
            let data = (try? Data(contentsOf: serialLog)) ?? Data()
            if linuxVzInertSerialContainsExactMarker(
                data,
                marker: "WHOATHERE_GUEST_SIGNER_READY port=40551"
            ) {
                return
            }
            if queue.sync(execute: { virtualMachine.state == .stopped }) {
                throw HarnessError.signerReadyTimeout
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
        throw HarnessError.signerReadyTimeout
    }

    private static func waitForSerialMarker(
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
                throw HarnessError.verificationFailed
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
        throw HarnessError.verificationFailed
    }

    private static func stopVirtualMachine(
        virtualMachine: VZVirtualMachine,
        queue: DispatchQueue
    ) throws {
        let successBox = LockedBox<Bool>()
        let completion = DispatchSemaphore(value: 0)
        let virtualMachineBox = UncheckedSendableBox(value: virtualMachine)
        queue.async {
            guard virtualMachineBox.value.state == .running,
                  virtualMachineBox.value.canStop else {
                completion.signal()
                return
            }
            virtualMachineBox.value.stop { error in
                successBox.store(error == nil)
                completion.signal()
            }
        }
        guard completion.wait(timeout: .now() + .seconds(20)) == .success,
              successBox.load() == true else {
            throw HarnessError.vmDidNotStop
        }
        guard queue.sync(execute: { virtualMachine.state == .stopped }) else {
            throw HarnessError.vmDidNotStop
        }
    }

    private static func waitForStop(
        virtualMachine: VZVirtualMachine,
        queue: DispatchQueue,
        deadline: Date
    ) throws {
        while Date() < deadline {
            if queue.sync(execute: { virtualMachine.state == .stopped }) { return }
            Thread.sleep(forTimeInterval: 0.05)
        }
        throw HarnessError.vmDidNotStop
    }

    private static func bestEffortStop(
        virtualMachine: VZVirtualMachine,
        queue: DispatchQueue
    ) {
        let completion = DispatchSemaphore(value: 0)
        let virtualMachineBox = UncheckedSendableBox(value: virtualMachine)
        queue.async {
            guard virtualMachineBox.value.state != .stopped,
                  virtualMachineBox.value.canStop else {
                completion.signal()
                return
            }
            virtualMachineBox.value.stop { _ in completion.signal() }
        }
        _ = completion.wait(timeout: .now() + .seconds(10))
    }

    private static func readBoundedRegularFile(_ url: URL, maximum: Int) throws -> Data {
        let values = try url.resourceValues(forKeys: [
            .isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey
        ])
        guard values.isRegularFile == true, values.isSymbolicLink != true,
              let size = values.fileSize, size > 0, size <= maximum else {
            throw HarnessError.invalidInput(url.lastPathComponent)
        }
        return try Data(contentsOf: url, options: [.mappedIfSafe])
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
                throw HarnessError.socketIO
            }
        }
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
            guard result == 0 else { throw HarnessError.socketIO }
        }
    }

    private static func readToEOF(_ descriptor: Int32, maximum: Int) throws -> Data {
        let result = try readToEOFAllowingEmpty(descriptor, maximum: maximum)
        guard !result.isEmpty else { throw HarnessError.socketIO }
        return result
    }

    private static func readToEOFAllowingEmpty(
        _ descriptor: Int32,
        maximum: Int
    ) throws -> Data {
        var result = Data()
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let count = Darwin.read(descriptor, &buffer, buffer.count)
            if count > 0 {
                guard result.count <= maximum - count else { throw HarnessError.socketIO }
                result.append(contentsOf: buffer.prefix(count))
                continue
            }
            if count == 0 { break }
            if errno == EINTR { continue }
            throw HarnessError.socketIO
        }
        return result
    }

    private static func writeNewPrivateFile(_ url: URL, data: Data) throws {
        let descriptor = open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw HarnessError.invalidInput("receipt_output") }
        defer { close(descriptor) }
        try writeAll(descriptor, data: data)
        guard fsync(descriptor) == 0 else { throw HarnessError.invalidInput("receipt_output") }
    }

    private static func openNewPrivateFileHandle(_ url: URL) throws -> FileHandle {
        let descriptor = open(
            url.path,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            0o600
        )
        guard descriptor >= 0 else { throw HarnessError.serialLog }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              metadata.st_uid == geteuid(),
              metadata.st_nlink == 1,
              metadata.st_size == 0,
              metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_mode & 0o777 == 0o600 else {
            close(descriptor)
            throw HarnessError.serialLog
        }
        return FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
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

    private static func dataSHA256(_ data: Data) -> String {
        "sha256:" + SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private struct PacketSensorResult {
        let frameCount: Int
        let ingressFrameCount: Int
        let droppedFrameCount: Int
        let matchedFrameCount: Int
        let bootstrapFrameCount: Int
        let uniqueSequenceCount: Int
        let duplicateFrameCount: Int
        let unexpectedFrameCount: Int
        let unexpectedFrameKinds: [String]
        let healthy: Bool
        let terminal: String
    }

    private static func drainRawFrames(
        fileDescriptor: Int32,
        networkFixtureCase: String?,
        networkSourcePort: UInt16?,
        hostFrameTriggerCount: UInt64?,
        boundedHostFrames: BoundedHostFrameCollection?
    ) -> PacketSensorResult {
        var count = 0
        var matched = 0
        var bootstrap = 0
        var sequences = Set<UInt32>()
        var duplicates = 0
        var unexpected = 0
        var unexpectedKinds = [String]()
        func recordFrame(_ frame: Data) {
            if networkFixtureCase == "host_frame_overflow",
               let sourcePort = networkSourcePort,
               hostFrameTriggerCount == 512 {
                if let sequence = linuxVzHostFrameOverflowSequence(
                    frame,
                    sourcePort: sourcePort
                ) {
                    if sequences.insert(sequence).inserted {
                        matched += 1
                    } else {
                        duplicates += 1
                    }
                } else {
                    unexpected += 1
                    if unexpectedKinds.count < 4 {
                        unexpectedKinds.append(sanitizedFrameKind(frame))
                    }
                }
                return
            }
            let exactMatch: Bool
            if networkFixtureCase == "ipv4_connect", let sourcePort = networkSourcePort {
                exactMatch = linuxVzIsExactIPv4SinkholeSYNFrame(frame, sourcePort: sourcePort)
            } else if networkFixtureCase == "ipv6_connect", let sourcePort = networkSourcePort {
                exactMatch = linuxVzIsExactIPv6SinkholeSYNFrame(frame, sourcePort: sourcePort)
            } else if networkFixtureCase == "udp_send", let sourcePort = networkSourcePort {
                exactMatch = linuxVzIsExactIPv4SinkholeUDPFrame(frame, sourcePort: sourcePort)
            } else if networkFixtureCase == "private_address_connect",
                      let sourcePort = networkSourcePort {
                exactMatch = linuxVzIsExactIPv4PrivateSinkholeSYNFrame(
                    frame, sourcePort: sourcePort
                )
            } else if networkFixtureCase == "link_local_connect",
                      let sourcePort = networkSourcePort {
                exactMatch = linuxVzIsExactIPv4LinkLocalSinkholeSYNFrame(
                    frame, sourcePort: sourcePort
                )
            } else if networkFixtureCase == "metadata_address_connect",
                      let sourcePort = networkSourcePort {
                exactMatch = linuxVzIsExactIPv4MetadataSinkholeSYNFrame(
                    frame, sourcePort: sourcePort
                )
            } else if networkFixtureCase == "public_address_connect",
                      let sourcePort = networkSourcePort {
                exactMatch = linuxVzIsExactIPv4PublicSinkholeSYNFrame(
                    frame, sourcePort: sourcePort
                )
            } else if networkFixtureCase == "dns_plaintext",
                      let sourcePort = networkSourcePort {
                exactMatch = linuxVzIsExactIPv4PlaintextDNSQueryFrame(
                    frame, sourcePort: sourcePort
                )
            } else if networkFixtureCase == "dns_malformed",
                      let sourcePort = networkSourcePort {
                exactMatch = linuxVzIsExactIPv4MalformedDNSQueryFrame(
                    frame, sourcePort: sourcePort
                )
            } else if networkFixtureCase == "encrypted_dns_connect",
                      let sourcePort = networkSourcePort {
                exactMatch = linuxVzIsExactIPv4EncryptedDNSSinkholeSYNFrame(
                    frame, sourcePort: sourcePort
                )
            } else {
                exactMatch = false
            }
            if exactMatch {
                matched += 1
            } else if networkFixtureCase == "ipv6_connect" &&
                        linuxVzIsExactIPv6MLDv2BootstrapFrame(frame) {
                bootstrap += 1
            } else {
                unexpected += 1
                if unexpectedKinds.count < 4 {
                    unexpectedKinds.append(sanitizedFrameKind(frame))
                }
            }
        }
        if let boundedHostFrames {
            for frame in boundedHostFrames.retainedFrames {
                count += 1
                recordFrame(frame)
            }
            return PacketSensorResult(
                frameCount: count,
                ingressFrameCount: boundedHostFrames.ingressFrameCount,
                droppedFrameCount: boundedHostFrames.droppedFrameCount,
                matchedFrameCount: matched,
                bootstrapFrameCount: bootstrap,
                uniqueSequenceCount: sequences.count,
                duplicateFrameCount: duplicates,
                unexpectedFrameCount: unexpected,
                unexpectedFrameKinds: unexpectedKinds,
                healthy: boundedHostFrames.healthy,
                terminal: boundedHostFrames.terminal
            )
        }
        var buffer = [UInt8](repeating: 0, count: 65_535)
        while true {
            let received = recv(fileDescriptor, &buffer, buffer.count, MSG_DONTWAIT)
            if received >= 0 {
                count += 1
                let frame = Data(buffer.prefix(received))
                recordFrame(frame)
                continue
            }
            if errno == EAGAIN || errno == EWOULDBLOCK {
                return PacketSensorResult(
                    frameCount: count,
                    ingressFrameCount: count,
                    droppedFrameCount: 0,
                    matchedFrameCount: matched,
                    bootstrapFrameCount: bootstrap,
                    uniqueSequenceCount: sequences.count,
                    duplicateFrameCount: duplicates,
                    unexpectedFrameCount: unexpected,
                    unexpectedFrameKinds: unexpectedKinds,
                    healthy: true,
                    terminal: "drained_would_block"
                )
            }
            return PacketSensorResult(
                frameCount: count,
                ingressFrameCount: count,
                droppedFrameCount: 0,
                matchedFrameCount: matched,
                bootstrapFrameCount: bootstrap,
                uniqueSequenceCount: sequences.count,
                duplicateFrameCount: duplicates,
                unexpectedFrameCount: unexpected,
                unexpectedFrameKinds: unexpectedKinds,
                healthy: false,
                terminal: "socket_error"
            )
        }
    }

    private static func sanitizedFrameKind(_ frame: Data) -> String {
        let bytes = [UInt8](frame)
        guard bytes.count >= 14 else { return "short_len_\(bytes.count)" }
        let etherType = UInt16(bytes[12]) << 8 | UInt16(bytes[13])
        guard etherType == 0x86dd, bytes.count >= 54 else {
            return String(format: "eth_%04x_len_%d", etherType, bytes.count)
        }
        let nextHeader = bytes[20]
        if nextHeader == 58, bytes.count >= 55 {
            return "ipv6_next_58_icmp_\(bytes[54])_len_\(bytes.count)"
        }
        if nextHeader == 0, bytes.count >= 62 {
            let extensionNext = bytes[54]
            let extensionLength = (Int(bytes[55]) + 1) * 8
            let payloadOffset = 54 + extensionLength
            if extensionNext == 58, payloadOffset < bytes.count {
                return "ipv6_hop_icmp_\(bytes[payloadOffset])_len_\(bytes.count)"
            }
        }
        return "ipv6_next_\(nextHeader)_len_\(bytes.count)"
    }

    private static func readProtectedSeed(_ url: URL) throws -> Data {
        let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw HarnessError.invalidInput("host_signing_seed") }
        defer { close(descriptor) }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              metadata.st_uid == geteuid(),
              metadata.st_nlink == 1,
              metadata.st_size == 32,
              metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_mode & 0o777 == 0o600 else {
            throw HarnessError.invalidInput("host_signing_seed")
        }
        let seed = try readToEOF(descriptor, maximum: 32)
        guard seed.count == 32 else { throw HarnessError.invalidInput("host_signing_seed") }
        return seed
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
