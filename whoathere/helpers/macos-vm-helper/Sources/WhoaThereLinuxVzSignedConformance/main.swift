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
        try writeAll(connection.fileDescriptor, data: requestData)
        guard shutdown(connection.fileDescriptor, SHUT_WR) == 0 else {
            throw HarnessError.socketIO
        }
        let responseData = try readToEOF(
            connection.fileDescriptor,
            maximum: maximumLinuxVzGuestSignerResponseFrameBytesV1
        )
        let receipt = try decodeLinuxVzGuestSignerResponse(responseData)

        try waitForStop(virtualMachine: virtualMachine, queue: queue, deadline: deadline)
        try serialOutput.synchronize()
        let serialData = try Data(contentsOf: options.serialLog)
        if let serialText = String(data: serialData, encoding: .utf8) {
            fputs(serialText, stderr)
        }
        let evidence = try decodeLinuxVzProcessEvidencePayloadV1(serialData)
        let claims = LinuxVzTelemetryGuestObservationClaims(
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
            observedTerminal: "observation_complete"
        )
        let verifiedGuest = try verifyLinuxVzTelemetryGuestReceipt(
            receipt,
            challenge: challenge,
            runSpec: runSpec,
            backend: backend,
            verifyingKey: guestPublicKey,
            expectedClaims: claims
        )

        let missingBaseMarkers = linuxVzInertMissingRequiredEvidenceMarkersV2(serialData)
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
        let packetSensor = drainRawFrames(fileDescriptor: sockets[1])
        let finalKernelSHA256 = try fileSHA256(options.kernel)
        let finalInitramfsSHA256 = try fileSHA256(options.initramfs)
        let imageIdentityStable = finalKernelSHA256 == kernelSHA256
            && finalInitramfsSHA256 == initramfsSHA256
        guard missingBaseMarkers.isEmpty, missingSignedMarkers.isEmpty, signerMarkersPresent,
              imageIdentityStable else {
            throw HarnessError.verificationFailed
        }
        let hostEvidence = try makeLinuxVzInertHostEvidencePayload(
            rawFrameCount: UInt64(packetSensor.frameCount),
            packetSensorHealthy: packetSensor.healthy,
            packetSensorTerminal: packetSensor.terminal,
            guestChannelTerminated: true,
            vmStarted: true,
            vmStopped: true,
            cloneDestroyed: configuration.storageDevices.isEmpty,
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
            guest: verifiedGuest,
            host: verifiedHost
        )
        try writeNewPrivateFile(options.receiptOutput, data: receipt)
        try writeNewPrivateFile(options.hostEvidenceOutput, data: hostEvidence.canonicalJSON)
        try writeNewPrivateFile(options.hostReceiptOutput, data: hostReceipt)
        emitJSON([
            "schema_version": "whoathere.linux_vz_signed_conformance_result.v1",
            "status": "ok",
            "challenge_sha256": challenge.challengeSHA256,
            "run_spec_sha256": runSpec.runSpecSHA256,
            "backend_identity_sha256": backend.identitySHA256,
            "receipt_sha256": dataSHA256(receipt),
            "host_evidence_payload_sha256": hostEvidence.payloadSHA256,
            "host_receipt_sha256": dataSHA256(hostReceipt),
            "complete_conformance_case_verified": completeCase.guestReceiptPresent
                && completeCase.hostReceiptPresent,
            "process_evidence_payload_sha256": evidence.payloadSHA256,
            "process_event_count": String(evidence.eventCount),
            "raw_frame_count": packetSensor.frameCount,
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
        guard !result.isEmpty else { throw HarnessError.socketIO }
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
        let healthy: Bool
        let terminal: String
    }

    private static func drainRawFrames(fileDescriptor: Int32) -> PacketSensorResult {
        var count = 0
        var buffer = [UInt8](repeating: 0, count: 65_535)
        while true {
            let received = recv(fileDescriptor, &buffer, buffer.count, MSG_DONTWAIT)
            if received >= 0 {
                count += 1
                continue
            }
            if errno == EAGAIN || errno == EWOULDBLOCK {
                return PacketSensorResult(
                    frameCount: count,
                    healthy: true,
                    terminal: "drained_would_block"
                )
            }
            return PacketSensorResult(
                frameCount: count,
                healthy: false,
                terminal: "socket_error"
            )
        }
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
