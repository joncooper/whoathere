import Darwin
import CryptoKit
import Foundation
import Security
@preconcurrency import Virtualization
import WhoaThereMacosVmHelperCore

private let guestReadinessPort: UInt32 = 47078
private let artifactGuestPort: UInt32 = 47079
private let guestReadinessProtocol = "whoathere.guest_ready.v1"
private let guestDetonationProtocol = "whoathere.guest_detonation.v1"
private let maxProjectPayloadHexBytes = 2 * 1024 * 1024
private let maxSyncBackArchiveHexBytes = 8 * 1024 * 1024

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
            "guest_toolchain_npm_available": response["npm_available"] as? Bool ?? false,
            "guest_toolchain_python3_available": response["python3_available"] as? Bool ?? false,
            "guest_toolchain_pip_available": response["pip_available"] as? Bool ?? false,
            "guest_toolchain_uv_available": response["uv_available"] as? Bool ?? false,
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
        serveDetonationJobs(connection)
    }

    private func serveDetonationJobs(_ connection: VZVirtioSocketConnection) {
        let jobsDir = detonationJobsDir(layout)
        try? FileManager.default.createDirectory(
            at: jobsDir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        while true {
            guard let request = nextDetonationRequest(in: jobsDir) else {
                Thread.sleep(forTimeInterval: 0.25)
                continue
            }
            let jobID = request.jobID
            let activeURL = jobsDir.appendingPathComponent("\(jobID).active.json")
            let resultURL = jobsDir.appendingPathComponent("\(jobID).result.json")
            do {
                try? FileManager.default.removeItem(at: activeURL)
                try FileManager.default.moveItem(at: request.url, to: activeURL)
                guard var requestFields = readJSONObject(activeURL) else {
                    writeDetonationResult(
                        to: resultURL,
                        fields: detonationFailureResult(
                            jobID: jobID,
                            reasons: ["detonation_request_unreadable"],
                            exitCode: 70
                        )
                    )
                    try? FileManager.default.removeItem(at: activeURL)
                    continue
                }
                requestFields["protocol"] = guestDetonationProtocol
                requestFields["vm_session_id"] = sessionID
                requestFields["helper_version"] = helperVersion
                let syncBackRequested = requestFields["sync_back_enabled"] as? Bool ?? false
                requestFields["sync_back_enabled"] = syncBackRequested
                requestFields["host_package_execution_enabled"] = false
                requestFields["high_risk_package_execution_enabled"] = false
                guard writeJSONLine(requestFields, to: connection.fileDescriptor) else {
                    writeDetonationResult(
                        to: resultURL,
                        fields: detonationFailureResult(
                            jobID: jobID,
                            reasons: ["guest_detonation_request_send_failed"],
                            exitCode: 70
                        )
                    )
                    try? FileManager.default.removeItem(at: activeURL)
                    return
                }
                let timeout = min(900, max(5, intField(requestFields, "timeout_seconds") ?? 120) + 15)
                guard let responseData = readFileDescriptor(
                    connection.fileDescriptor,
                    timeoutSeconds: Int32(timeout),
                    maxBytes: maxSyncBackArchiveHexBytes + 128 * 1024
                ),
                      var response = try? JSONSerialization.jsonObject(with: responseData) as? [String: Any],
                      response["protocol"] as? String == guestDetonationProtocol else {
                    writeDetonationResult(
                        to: resultURL,
                        fields: detonationFailureResult(
                            jobID: jobID,
                            reasons: ["guest_detonation_result_missing_or_invalid"],
                            exitCode: 20
                        )
                    )
                    try? FileManager.default.removeItem(at: activeURL)
                    continue
                }
                let mismatchReasons = detonationResultMismatchReasons(response, request: requestFields)
                if !mismatchReasons.isEmpty {
                    writeDetonationResult(
                        to: resultURL,
                        fields: detonationFailureResult(
                            jobID: jobID,
                            reasons: ["guest_detonation_result_context_mismatch"] + mismatchReasons,
                            exitCode: 20
                        )
                    )
                    try? FileManager.default.removeItem(at: activeURL)
                    continue
                }
                response["vm_session_id"] = sessionID
                let guestSyncBackEnabled = response["sync_back_enabled"] as? Bool ?? false
                response["sync_back_enabled"] = syncBackRequested && guestSyncBackEnabled
                if syncBackRequested,
                   guestSyncBackEnabled,
                   let archiveHex = response["sync_output_archive_hex"] as? String {
                    guard let archiveData = dataFromHex(
                        archiveHex,
                        maxBytes: maxSyncBackArchiveHexBytes / 2
                    ) else {
                        writeDetonationResult(
                            to: resultURL,
                            fields: detonationFailureResult(
                                jobID: jobID,
                                reasons: ["guest_sync_output_archive_invalid"],
                                exitCode: 20
                            )
                        )
                        try? FileManager.default.removeItem(at: activeURL)
                        continue
                    }
                    response["sync_output_archive_sha256"] = sha256Digest(data: archiveData)
                }
                response["host_package_execution_enabled"] = false
                response["high_risk_package_execution_enabled"] = false
                writeDetonationResult(to: resultURL, fields: response)
                try? FileManager.default.removeItem(at: activeURL)
            } catch {
                writeDetonationResult(
                    to: resultURL,
                        fields: detonationFailureResult(
                            jobID: jobID,
                            reasons: ["guest_detonation_runtime_loop_failed", sanitizedTopLevelReason(error)],
                            exitCode: 70
                        )
                    )
                try? FileManager.default.removeItem(at: activeURL)
            }
        }
    }
}

private final class ArtifactGuestRunListener: NSObject, VZVirtioSocketListenerDelegate {
    private let lock = NSLock()
    private var accepted = false
    private let reader: ArtifactRunSubmissionReader
    private let base: LockedArtifactRunBase
    private let clone: DisposableArtifactRunClone
    private let resultBox: LockedResultBox<ArtifactGuestNonExecutingSessionObservation>
    private let completion: DispatchSemaphore

    init(
        reader: ArtifactRunSubmissionReader,
        base: LockedArtifactRunBase,
        clone: DisposableArtifactRunClone,
        resultBox: LockedResultBox<ArtifactGuestNonExecutingSessionObservation>,
        completion: DispatchSemaphore
    ) {
        self.reader = reader
        self.base = base
        self.clone = clone
        self.resultBox = resultBox
        self.completion = completion
    }

    func listener(
        _ listener: VZVirtioSocketListener,
        shouldAcceptNewConnection connection: VZVirtioSocketConnection,
        from socketDevice: VZVirtioSocketDevice
    ) -> Bool {
        guard connection.destinationPort == artifactGuestPort else { return false }
        lock.lock()
        let shouldAccept = !accepted
        if shouldAccept { accepted = true }
        lock.unlock()
        guard shouldAccept else { return false }

        let listenerBox = UncheckedSendableBox(value: self)
        let connectionBox = UncheckedSendableBox(value: connection)
        DispatchQueue.global(qos: .userInitiated).async {
            listenerBox.value.handle(connectionBox.value)
        }
        return true
    }

    private func handle(_ connection: VZVirtioSocketConnection) {
        defer {
            connection.close()
            completion.signal()
        }
        do {
            let observation = try runNonExecutingArtifactGuestSession(
                descriptor: connection.fileDescriptor,
                reader: reader,
                base: base,
                clone: clone,
                timeoutMillis: 90_000
            )
            resultBox.store(.success(observation))
        } catch {
            resultBox.store(.failure(error))
        }
    }
}

private final class WheelGuestRunListener: NSObject, VZVirtioSocketListenerDelegate {
    private let lock = NSLock()
    private var accepted = false
    private let reader: WheelRunSubmissionReader
    private let authority: ConsumedWheelRunAuthority
    private let base: LockedWheelRunBase
    private let clone: DisposableWheelRunClone
    private let resultBox: LockedResultBox<WheelGuestNonExecutingSessionObservation>
    private let completion: DispatchSemaphore

    init(
        reader: WheelRunSubmissionReader,
        authority: ConsumedWheelRunAuthority,
        base: LockedWheelRunBase,
        clone: DisposableWheelRunClone,
        resultBox: LockedResultBox<WheelGuestNonExecutingSessionObservation>,
        completion: DispatchSemaphore
    ) {
        self.reader = reader
        self.authority = authority
        self.base = base
        self.clone = clone
        self.resultBox = resultBox
        self.completion = completion
    }

    func listener(
        _ listener: VZVirtioSocketListener,
        shouldAcceptNewConnection connection: VZVirtioSocketConnection,
        from socketDevice: VZVirtioSocketDevice
    ) -> Bool {
        guard connection.destinationPort == wheelGuestVSOCKPortV1 else { return false }
        lock.lock()
        let shouldAccept = !accepted
        if shouldAccept { accepted = true }
        lock.unlock()
        guard shouldAccept else { return false }

        let listenerBox = UncheckedSendableBox(value: self)
        let connectionBox = UncheckedSendableBox(value: connection)
        DispatchQueue.global(qos: .userInitiated).async {
            listenerBox.value.handle(connectionBox.value)
        }
        return true
    }

    private func handle(_ connection: VZVirtioSocketConnection) {
        defer {
            connection.close()
            completion.signal()
        }
        do {
            let observation = try runNonExecutingWheelGuestSession(
                descriptor: connection.fileDescriptor,
                reader: reader,
                authority: authority,
                base: base,
                clone: clone,
                timeoutMillis: 90_000
            )
            resultBox.store(.success(observation))
        } catch {
            resultBox.store(.failure(error))
        }
    }
}

private final class SdistGuestRunListener: NSObject, VZVirtioSocketListenerDelegate {
    private let lock = NSLock()
    private var accepted = false
    private let authorized: AuthorizedSdistRunSubmission
    private let closure: AuthorizedSdistBuildClosureSubmission
    private let base: LockedSdistRunBase
    private let clone: DisposableSdistRunClone
    private let resultBox: LockedResultBox<SdistGuestNonExecutingSessionObservation>
    private let completion: DispatchSemaphore

    init(
        authorized: AuthorizedSdistRunSubmission,
        closure: AuthorizedSdistBuildClosureSubmission,
        base: LockedSdistRunBase,
        clone: DisposableSdistRunClone,
        resultBox: LockedResultBox<SdistGuestNonExecutingSessionObservation>,
        completion: DispatchSemaphore
    ) {
        self.authorized = authorized
        self.closure = closure
        self.base = base
        self.clone = clone
        self.resultBox = resultBox
        self.completion = completion
    }

    func listener(
        _ listener: VZVirtioSocketListener,
        shouldAcceptNewConnection connection: VZVirtioSocketConnection,
        from socketDevice: VZVirtioSocketDevice
    ) -> Bool {
        guard connection.destinationPort == sdistGuestVSOCKPortV1 else { return false }
        lock.lock()
        let shouldAccept = !accepted
        if shouldAccept { accepted = true }
        lock.unlock()
        guard shouldAccept else { return false }

        let listenerBox = UncheckedSendableBox(value: self)
        let connectionBox = UncheckedSendableBox(value: connection)
        DispatchQueue.global(qos: .userInitiated).async {
            listenerBox.value.handle(connectionBox.value)
        }
        return true
    }

    private func handle(_ connection: VZVirtioSocketConnection) {
        defer {
            connection.close()
            completion.signal()
        }
        do {
            let cloneBinding = sdistCloneBindingSHA256(
                baseGenerationID: base.identity.baseGenerationID,
                runID: clone.runID,
                diskSHA256: clone.diskSHA256,
                auxiliaryStorageSHA256: clone.auxiliaryStorageSHA256
            )
            let observation = try runNonExecutingSdistGuestSession(
                descriptor: connection.fileDescriptor,
                authorized: authorized,
                closure: closure,
                cloneBindingSHA256: cloneBinding,
                guestAuthPublicKey: base.guestAuthPublicKeyData,
                timeoutMillis: 90_000
            )
            resultBox.store(.success(observation))
        } catch {
            resultBox.store(.failure(error))
        }
    }

    var hasAcceptedConnection: Bool {
        lock.lock()
        defer { lock.unlock() }
        return accepted
    }
}

private struct DetonationRequestFile {
    var jobID: String
    var url: URL
}

private func detonationJobsDir(_ layout: BundleLayout) -> URL {
    layout.runsDir.appendingPathComponent("detonation-jobs", isDirectory: true)
}

private func nextDetonationRequest(in directory: URL) -> DetonationRequestFile? {
    guard let entries = try? FileManager.default.contentsOfDirectory(
        at: directory,
        includingPropertiesForKeys: nil
    ) else {
        return nil
    }
    return entries
        .filter { $0.lastPathComponent.hasSuffix(".request.json") }
        .sorted { $0.lastPathComponent < $1.lastPathComponent }
        .first
        .map { url in
            let name = url.lastPathComponent
            let suffix = ".request.json"
            let jobID = String(name.dropLast(suffix.count))
            return DetonationRequestFile(jobID: jobID, url: url)
        }
}

private func detonationFailureResult(jobID: String, reasons: [String], exitCode: Int) -> [String: Any] {
    [
        "schema_version": bundleSchemaVersion,
        "protocol": guestDetonationProtocol,
        "job_id": jobID,
        "status": "fail_closed",
        "verdict": exitCode == 70 ? "fail_closed_runner_error" : "infrastructure_error_fail_closed",
        "reason_codes": reasonArray(reasons),
        "sync_back_enabled": false,
        "host_package_execution_enabled": false,
        "high_risk_package_execution_enabled": false,
        "exit_code": exitCode
    ]
}

private func detonationResultMismatchReasons(_ result: [String: Any], request: [String: Any]) -> [String] {
    var reasons: [String] = []
    for key in ["job_id", "request_nonce", "tool", "command_class", "fixture"] {
        let expected = request[key] as? String ?? ""
        let actual = result[key] as? String ?? ""
        if actual != expected {
            reasons.append("guest_detonation_result_\(key)_mismatch")
        }
    }
    if request["project_mode"] as? Bool == true {
        let expectedWorkflow = request["project_workflow"] as? String ?? ""
        let actualWorkflow = result["project_workflow"] as? String ?? ""
        if actualWorkflow != expectedWorkflow {
            reasons.append("guest_detonation_result_project_workflow_mismatch")
        }
        let expectedApiProbe = request["project_api_probe_enabled"] as? Bool ?? false
        let actualApiProbe = result["project_api_probe_enabled"] as? Bool ?? false
        if actualApiProbe != expectedApiProbe {
            reasons.append("guest_detonation_result_project_api_probe_mismatch")
        }
    }
    return reasons.sorted()
}

private func writeDetonationResult(to url: URL, fields: [String: Any]) {
    guard JSONSerialization.isValidJSONObject(fields),
          let data = try? JSONSerialization.data(withJSONObject: fields, options: [.prettyPrinted, .sortedKeys]) else {
        return
    }
    try? data.write(to: url, options: [.atomic])
}

private func sanitizedTopLevelReason(_ error: Error) -> String {
    String(describing: error)
        .replacingOccurrences(of: "\n", with: "_")
        .replacingOccurrences(of: "\r", with: "_")
        .replacingOccurrences(of: " ", with: "_")
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

private func sha256Digest(data: Data) -> String {
    "sha256:" + SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

private func dataFromHex(_ hex: String, maxBytes: Int) -> Data? {
    guard !hex.isEmpty, hex.count % 2 == 0, hex.count <= maxBytes * 2 else {
        return nil
    }
    var data = Data(capacity: hex.count / 2)
    var index = hex.startIndex
    while index < hex.endIndex {
        let next = hex.index(index, offsetBy: 2)
        guard let byte = UInt8(hex[index..<next], radix: 16) else {
            return nil
        }
        data.append(byte)
        index = next
    }
    return data
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
    nonisolated(unsafe) private static var activeSdistCancellationSignalSources:
        [DispatchSourceSignal] = []

    static func main() {
        do {
            let invocation = try parseHelperInvocation(Array(CommandLine.arguments.dropFirst()))
            switch invocation {
            case .legacy(let options):
                run(options)
            case .artifactRun(let options):
                artifactRun(options)
            case .wheelRun(let options):
                wheelRun(options)
            case .sdistRun(let options):
                sdistRun(options)
            }
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

    private static func artifactRun(_ options: ArtifactRunOptions) {
        guard options.execute else {
            emit(
                fields: [
                    "schema_version": "whoathere.macos_artifact_run_nonexecuting.v1",
                    "helper_version": helperVersion,
                    "status": "blocked",
                    "execution_requested": false,
                    "vm_execution_enabled": false,
                    "package_execution_enabled": false,
                    "reason_codes": ["execute_required_for_artifact_vm_run"],
                    "exit_code": 78
                ],
                exitCode: 78
            )
        }
        var pendingClone: DisposableArtifactRunClone?
        do {
            let reader = try beginArtifactSubmission(from: FileHandle.standardInput)
            let prelude = reader.prelude
            let stateDirectory = options.stateDir.map {
                URL(fileURLWithPath: $0, isDirectory: true)
            } ?? defaultStateDir()
            let layout = ArtifactRunBaseLayout(stateDirectory: stateDirectory)
            let helperURL = URL(
                fileURLWithPath: absoluteExecutablePath(CommandLine.arguments[0])
            )
            let base = try verifyAndLockArtifactRunBase(
                layout: layout,
                identity: prelude.backendIdentity,
                helperURL: helperURL
            )
            let clone = try base.createDisposableClone()
            pendingClone = clone
            let configuration = try buildArtifactScenarioConfiguration(base: base, clone: clone)
            let queue = DispatchQueue(label: "whoathere.macos.artifact-run")
            let virtualMachine = VZVirtualMachine(configuration: configuration, queue: queue)
            guard let socketDevice = virtualMachine.socketDevices.first as? VZVirtioSocketDevice else {
                throw helperError("artifact_run_socket_device_missing")
            }
            let sessionResult = LockedResultBox<ArtifactGuestNonExecutingSessionObservation>()
            let sessionCompletion = DispatchSemaphore(value: 0)
            let listenerDelegate = ArtifactGuestRunListener(
                reader: reader,
                base: base,
                clone: clone,
                resultBox: sessionResult,
                completion: sessionCompletion
            )
            let socketListener = VZVirtioSocketListener()
            socketListener.delegate = listenerDelegate
            queue.sync {
                socketDevice.setSocketListener(socketListener, forPort: artifactGuestPort)
            }

            var primaryError: Error?
            var sessionObservation: ArtifactGuestNonExecutingSessionObservation?
            var vmStartSucceeded = false
            var sessionCompleted = false
            do {
                try startArtifactVirtualMachine(virtualMachine, queue: queue)
                vmStartSucceeded = true
                guard sessionCompletion.wait(timeout: .now() + .seconds(120)) == .success else {
                    throw helperError("artifact_run_guest_session_timeout")
                }
                sessionCompleted = true
                guard let result = sessionResult.load() else {
                    throw helperError("artifact_run_guest_session_result_missing")
                }
                sessionObservation = try result.get()
            } catch {
                primaryError = error
            }

            queue.sync {
                socketDevice.removeSocketListener(forPort: artifactGuestPort)
            }
            let stopResult = stopArtifactVirtualMachine(virtualMachine, queue: queue)
            if !sessionCompleted {
                sessionCompleted = sessionCompletion.wait(
                    timeout: .now() + .seconds(10)
                ) == .success
            }
            var cloneCleanupSucceeded = false
            var cleanupError: Error?
            let vmStopSucceeded: Bool
            switch stopResult {
            case .success: vmStopSucceeded = true
            case .failure: vmStopSucceeded = false
            }
            let cleanupDisposition = artifactRunCloneCleanupDisposition(
                vmStopSucceeded: vmStopSucceeded,
                guestSessionTerminated: sessionCompleted
            )
            switch cleanupDisposition {
            case .cleanupAuthorized:
                do {
                    try clone.cleanup()
                    cloneCleanupSucceeded = true
                    pendingClone = nil
                } catch {
                    cleanupError = error
                }
            case .retainBecauseVMStopUnproven:
                if case .failure(let error) = stopResult {
                    cleanupError = error
                } else {
                    cleanupError = helperError(
                        cleanupDisposition.reasonCode
                            ?? "artifact_run_clone_cleanup_disposition_invalid"
                    )
                }
            case .retainBecauseGuestSessionUnterminated:
                cleanupError = helperError(
                    cleanupDisposition.reasonCode
                        ?? "artifact_run_clone_cleanup_disposition_invalid"
                )
            }

            if primaryError != nil || cleanupError != nil {
                var reasons: [String] = []
                if let primaryError { reasons.append(String(describing: primaryError)) }
                if let cleanupError { reasons.append(String(describing: cleanupError)) }
                if !sessionCompleted {
                    reasons.append("artifact_run_guest_session_not_terminated")
                }
                if !cloneCleanupSucceeded {
                    reasons.append("artifact_run_clone_cleanup_unproven")
                }
                emit(
                    fields: [
                        "schema_version": "whoathere.macos_artifact_run_nonexecuting.v1",
                        "helper_version": helperVersion,
                        "status": "error",
                        "execution_requested": true,
                        "submission_prelude_verified": true,
                        "run_spec_sha256": prelude.runSpecSHA256,
                        "artifact_sha256": prelude.artifactSHA256,
                        "vm_start_succeeded": vmStartSucceeded,
                        "vm_stop_succeeded": vmStopSucceeded,
                        "guest_session_completed": sessionCompleted,
                        "clone_cleanup_succeeded": cloneCleanupSucceeded,
                        "package_execution_enabled": false,
                        "sync_back_enabled": false,
                        "reason_codes": reasonArray(reasons),
                        "exit_code": 70
                    ],
                    exitCode: 70
                )
            }
            guard let observation = sessionObservation else {
                throw helperError("artifact_run_guest_session_observation_missing")
            }
            emit(
                fields: [
                    "schema_version": "whoathere.macos_artifact_run_nonexecuting.v1",
                    "helper_version": helperVersion,
                    "status": "staged_no_execution",
                    "execution_requested": true,
                    "transport_verified": true,
                    "run_spec_sha256": prelude.runSpecSHA256,
                    "template_sha256": prelude.templateSHA256,
                    "challenge_binding_sha256": prelude.challengeBindingSHA256,
                    "execution_binding_sha256": observation.stagingReceipt.executionBindingSHA256,
                    "clone_binding_sha256": observation.stagingReceipt.cloneBindingSHA256,
                    "artifact_sha256": observation.stagingReceipt.artifactSHA256,
                    "artifact_byte_length": observation.stagingReceipt.artifactByteLength,
                    "scenario_id": prelude.scenarioID,
                    "environment": prelude.environment,
                    "vm_start_succeeded": true,
                    "vm_stop_succeeded": true,
                    "guest_authentication_verified": observation.authentication.signatureVerified,
                    "guest_staging_receipt_verified": observation.stagingReceipt.signatureVerified,
                    "guest_staging_cleanup_succeeded": true,
                    "clone_cleanup_succeeded": true,
                    "package_execution_enabled": false,
                    "sync_back_enabled": false,
                    "reason_codes": ["artifact_staged_and_destroyed_without_execution"],
                    "exit_code": 0
                ],
                exitCode: 0
            )
        } catch {
            var cloneCleanupSucceeded = pendingClone == nil
            var reasons = [String(describing: error)]
            if let clone = pendingClone {
                do {
                    try clone.cleanup()
                    pendingClone = nil
                    cloneCleanupSucceeded = true
                } catch {
                    reasons.append(String(describing: error))
                }
            }
            emit(
                fields: [
                    "schema_version": "whoathere.macos_artifact_run_nonexecuting.v1",
                    "helper_version": helperVersion,
                    "status": "error",
                    "execution_requested": true,
                    "transport_verified": false,
                    "clone_cleanup_succeeded": cloneCleanupSucceeded,
                    "package_execution_enabled": false,
                    "sync_back_enabled": false,
                    "reason_codes": reasonArray(reasons),
                    "exit_code": 65
                ],
                exitCode: 65
            )
        }
    }

    private static func wheelRun(_ options: WheelRunOptions) {
        guard options.execute else {
            emit(
                fields: [
                    "schema_version": "whoathere.macos_wheel_run_nonexecuting.v1",
                    "helper_version": helperVersion,
                    "status": "blocked",
                    "execution_requested": false,
                    "vm_execution_enabled": false,
                    "package_execution_enabled": false,
                    "sync_back_enabled": false,
                    "reason_codes": ["execute_required_for_wheel_vm_run"],
                    "exit_code": 78
                ],
                exitCode: 78
            )
        }
        var pendingClone: DisposableWheelRunClone?
        var consumedAuthority: ConsumedWheelRunAuthority?
        var authorityReplayStatePersisted = false
        do {
            let reader = try beginWheelSubmission(from: FileHandle.standardInput)
            let prelude = reader.prelude
            let stateDirectory = options.stateDir.map {
                URL(fileURLWithPath: $0, isDirectory: true)
            } ?? defaultStateDir()
            let authorityLayout = WheelRunAuthorityLayout(stateDirectory: stateDirectory)
            let timestamp = Date().timeIntervalSince1970
            guard timestamp.isFinite, timestamp >= 0, timestamp <= Double(UInt64.max) else {
                throw helperError("wheel_run_trusted_time_unavailable")
            }
            let authority: ConsumedWheelRunAuthority
            do {
                authority = try consumeWheelRunAuthority(
                    layout: authorityLayout,
                    authorityID: options.authorityID,
                    prelude: prelude,
                    nowUnixSeconds: UInt64(timestamp.rounded(.down))
                )
                authorityReplayStatePersisted = authority.replayStatePersisted
            } catch {
                authorityReplayStatePersisted = FileManager.default.fileExists(
                    atPath: authorityLayout.consumedURL(
                        authorityID: options.authorityID
                    ).path
                )
                throw error
            }
            consumedAuthority = authority
            let layout = WheelRunBaseLayout(stateDirectory: stateDirectory)
            let helperURL = URL(
                fileURLWithPath: absoluteExecutablePath(CommandLine.arguments[0])
            )
            let base = try verifyAndLockWheelRunBase(
                layout: layout,
                identity: prelude.backendIdentity,
                helperURL: helperURL
            )
            let clone = try base.createDisposableClone()
            pendingClone = clone
            let configuration = try buildWheelScenarioConfiguration(base: base, clone: clone)
            guard configuration.networkDevices.isEmpty,
                  configuration.socketDevices.count == 1 else {
                throw helperError("wheel_run_vm_configuration_contract_mismatch")
            }
            let queue = DispatchQueue(label: "whoathere.macos.wheel-run")
            let virtualMachine = VZVirtualMachine(configuration: configuration, queue: queue)
            guard let socketDevice = virtualMachine.socketDevices.first as? VZVirtioSocketDevice else {
                throw helperError("wheel_run_socket_device_missing")
            }
            let sessionResult = LockedResultBox<WheelGuestNonExecutingSessionObservation>()
            let sessionCompletion = DispatchSemaphore(value: 0)
            let listenerDelegate = WheelGuestRunListener(
                reader: reader,
                authority: authority,
                base: base,
                clone: clone,
                resultBox: sessionResult,
                completion: sessionCompletion
            )
            let socketListener = VZVirtioSocketListener()
            socketListener.delegate = listenerDelegate
            queue.sync {
                socketDevice.setSocketListener(
                    socketListener,
                    forPort: wheelGuestVSOCKPortV1
                )
            }

            var primaryError: Error?
            var sessionObservation: WheelGuestNonExecutingSessionObservation?
            var vmStartSucceeded = false
            var sessionCompleted = false
            do {
                try startArtifactVirtualMachine(virtualMachine, queue: queue)
                vmStartSucceeded = true
                guard sessionCompletion.wait(timeout: .now() + .seconds(120)) == .success else {
                    throw helperError("wheel_run_guest_session_timeout")
                }
                sessionCompleted = true
                guard let result = sessionResult.load() else {
                    throw helperError("wheel_run_guest_session_result_missing")
                }
                sessionObservation = try result.get()
            } catch {
                primaryError = error
            }

            queue.sync {
                socketDevice.removeSocketListener(forPort: wheelGuestVSOCKPortV1)
            }
            let stopResult = stopArtifactVirtualMachine(virtualMachine, queue: queue)
            if !sessionCompleted {
                sessionCompleted = sessionCompletion.wait(
                    timeout: .now() + .seconds(10)
                ) == .success
            }
            var cloneCleanupSucceeded = false
            var cleanupError: Error?
            let vmStopSucceeded: Bool
            switch stopResult {
            case .success: vmStopSucceeded = true
            case .failure: vmStopSucceeded = false
            }
            let cleanupDisposition = wheelRunCloneCleanupDisposition(
                vmStopSucceeded: vmStopSucceeded,
                guestSessionTerminated: sessionCompleted
            )
            switch cleanupDisposition {
            case .cleanupAuthorized:
                do {
                    try clone.cleanup()
                    cloneCleanupSucceeded = true
                    pendingClone = nil
                } catch {
                    cleanupError = error
                }
            case .retainBecauseVMStopUnproven:
                if case .failure(let error) = stopResult {
                    cleanupError = error
                } else {
                    cleanupError = helperError(
                        cleanupDisposition.reasonCode
                            ?? "wheel_run_clone_cleanup_disposition_invalid"
                    )
                }
            case .retainBecauseGuestSessionUnterminated:
                cleanupError = helperError(
                    cleanupDisposition.reasonCode
                        ?? "wheel_run_clone_cleanup_disposition_invalid"
                )
            }

            if primaryError != nil || cleanupError != nil {
                var reasons: [String] = []
                if let primaryError { reasons.append(String(describing: primaryError)) }
                if let cleanupError { reasons.append(String(describing: cleanupError)) }
                if !sessionCompleted {
                    reasons.append("wheel_run_guest_session_not_terminated")
                }
                if !cloneCleanupSucceeded {
                    reasons.append("wheel_run_clone_cleanup_unproven")
                }
                emit(
                    fields: [
                        "schema_version": "whoathere.macos_wheel_run_nonexecuting.v1",
                        "helper_version": helperVersion,
                        "status": "error",
                        "execution_requested": true,
                        "authority_id": authority.authorityID,
                        "authority_consumed": true,
                        "authority_replay_state_persisted": authority.replayStatePersisted,
                        "submission_prelude_verified": true,
                        "run_spec_sha256": prelude.runSpecSHA256,
                        "artifact_sha256": prelude.artifactSHA256,
                        "network_device_count": 0,
                        "wheel_vsock_port": wheelGuestVSOCKPortV1,
                        "vm_start_succeeded": vmStartSucceeded,
                        "vm_stop_succeeded": vmStopSucceeded,
                        "guest_session_completed": sessionCompleted,
                        "guest_channel_terminated": sessionCompleted,
                        "clone_cleanup_succeeded": cloneCleanupSucceeded,
                        "package_execution_enabled": false,
                        "sync_back_enabled": false,
                        "reason_codes": reasonArray(reasons),
                        "exit_code": 70
                    ],
                    exitCode: 70
                )
            }
            guard let observation = sessionObservation else {
                throw helperError("wheel_run_guest_session_observation_missing")
            }
            emit(
                fields: [
                    "schema_version": "whoathere.macos_wheel_run_nonexecuting.v1",
                    "helper_version": helperVersion,
                    "status": "staged_no_execution",
                    "execution_requested": true,
                    "authority_id": authority.authorityID,
                    "authority_record_sha256": authority.authorityRecordSHA256,
                    "authority_consumed": true,
                    "authority_replay_state_persisted": authority.replayStatePersisted,
                    "transport_verified": true,
                    "run_spec_sha256": prelude.runSpecSHA256,
                    "template_sha256": prelude.templateSHA256,
                    "challenge_binding_sha256": authority.challengeBindingSHA256,
                    "execution_binding_sha256": observation.stagingReceipt.executionBindingSHA256,
                    "clone_binding_sha256": observation.stagingReceipt.cloneBindingSHA256,
                    "artifact_sha256": observation.stagingReceipt.artifactSHA256,
                    "artifact_byte_length": observation.stagingReceipt.artifactByteLength,
                    "scenario_id": prelude.scenarioID,
                    "scenario_kind": prelude.scenarioKind,
                    "network_device_count": 0,
                    "wheel_vsock_port": wheelGuestVSOCKPortV1,
                    "vm_start_succeeded": true,
                    "vm_stop_succeeded": true,
                    "guest_authentication_verified": observation.authentication.signatureVerified,
                    "guest_staging_receipt_verified": observation.stagingReceipt.signatureVerified,
                    "guest_staging_cleanup_succeeded": true,
                    "guest_channel_terminated": true,
                    "clone_cleanup_succeeded": true,
                    "package_execution_enabled": false,
                    "sync_back_enabled": false,
                    "reason_codes": ["wheel_staged_and_destroyed_without_execution"],
                    "exit_code": 0
                ],
                exitCode: 0
            )
        } catch {
            var cloneCleanupSucceeded = pendingClone == nil
            var reasons = [String(describing: error)]
            if let clone = pendingClone {
                do {
                    try clone.cleanup()
                    pendingClone = nil
                    cloneCleanupSucceeded = true
                } catch {
                    reasons.append(String(describing: error))
                }
            }
            emit(
                fields: [
                    "schema_version": "whoathere.macos_wheel_run_nonexecuting.v1",
                    "helper_version": helperVersion,
                    "status": "error",
                    "execution_requested": true,
                    "authority_id": options.authorityID,
                    "authority_consumed": consumedAuthority != nil
                        || authorityReplayStatePersisted,
                    "authority_replay_state_persisted": authorityReplayStatePersisted,
                    "transport_verified": false,
                    "clone_cleanup_succeeded": cloneCleanupSucceeded,
                    "package_execution_enabled": false,
                    "sync_back_enabled": false,
                    "reason_codes": reasonArray(reasons),
                    "exit_code": 65
                ],
                exitCode: 65
            )
        }
    }

    private static func sdistRun(_ options: SdistRunOptions) {
        guard options.execute else {
            emit(
                fields: [
                    "schema_version": "whoathere.macos_sdist_run_nonexecuting.v1",
                    "helper_version": helperVersion,
                    "status": "blocked",
                    "execution_requested": false,
                    "vm_execution_enabled": false,
                    "package_execution_enabled": false,
                    "sync_back_enabled": false,
                    "build_closure_materialized": false,
                    "reason_codes": ["execute_required_for_sdist_vm_run"],
                    "exit_code": 78
                ],
                exitCode: 78
            )
        }
        let cancellation = SdistRunCancellationState()
        let cancellationSignalSources = installSdistRunCancellationSignals(cancellation)
        defer {
            for source in cancellationSignalSources {
                source.cancel()
            }
        }
        var pendingClone: DisposableSdistRunClone?
        var consumedAuthority: ConsumedSdistRunAuthority?
        var authorityReplayStatePersisted = false
        do {
            try cancellation.throwIfRequested()
            let stateDirectory = options.stateDir.map {
                URL(fileURLWithPath: $0, isDirectory: true)
            } ?? defaultStateDir()
            let authorityLayout = SdistRunAuthorityLayout(stateDirectory: stateDirectory)
            let timestamp = Date().timeIntervalSince1970
            guard timestamp.isFinite, timestamp >= 0, timestamp <= Double(UInt64.max) else {
                throw helperError("sdist_run_trusted_time_unavailable")
            }
            let authorized: AuthorizedSdistRunSubmission
            do {
                authorized = try beginAndAuthorizeSdistRunSubmission(
                    from: FileHandle.standardInput,
                    authorityLayout: authorityLayout,
                    authorityID: options.authorityID,
                    expectedAuthorityRecordSHA256: options.authorityRecordSHA256,
                    nowUnixSeconds: UInt64(timestamp.rounded(.down)),
                    cancellation: cancellation
                )
                consumedAuthority = authorized.authority
                authorityReplayStatePersisted = authorized.authority.replayStatePersisted
            } catch {
                authorityReplayStatePersisted = FileManager.default.fileExists(
                    atPath: authorityLayout.consumedURL(
                        authorityID: options.authorityID
                    ).path
                )
                throw error
            }
            try cancellation.throwIfRequested()
            let prelude = authorized.prelude
            guard fcntl(options.buildClosureFD, F_GETFD) >= 0 else {
                throw helperError("sdist_run_build_closure_descriptor_invalid")
            }
            var targetStatus = stat()
            var closureStatus = stat()
            guard fstat(STDIN_FILENO, &targetStatus) == 0,
                  fstat(options.buildClosureFD, &closureStatus) == 0,
                  targetStatus.st_dev != closureStatus.st_dev
                    || targetStatus.st_ino != closureStatus.st_ino else {
                throw helperError("sdist_run_build_closure_descriptor_not_distinct")
            }
            let closureHandle = FileHandle(
                fileDescriptor: options.buildClosureFD,
                closeOnDealloc: false
            )
            let authorizedClosure = try beginAuthorizedSdistBuildClosureSubmission(
                from: closureHandle,
                authorized: authorized,
                cancellation: cancellation
            )
            try cancellation.throwIfRequested()
            let layout = SdistRunBaseLayout(stateDirectory: stateDirectory)
            let helperURL = URL(
                fileURLWithPath: absoluteExecutablePath(CommandLine.arguments[0])
            )
            let base = try verifyAndLockSdistRunBase(
                layout: layout,
                identity: prelude.backendIdentity,
                helperURL: helperURL
            )
            try cancellation.throwIfRequested()
            let clone = try base.createDisposableClone()
            pendingClone = clone
            try cancellation.throwIfRequested()
            let configuration = try buildSdistScenarioConfiguration(base: base, clone: clone)
            guard configuration.networkDevices.isEmpty,
                  configuration.socketDevices.count == 1 else {
                throw helperError("sdist_run_vm_configuration_contract_mismatch")
            }
            let queue = DispatchQueue(label: "whoathere.macos.sdist-run")
            let virtualMachine = VZVirtualMachine(configuration: configuration, queue: queue)
            guard let socketDevice = virtualMachine.socketDevices.first as? VZVirtioSocketDevice else {
                throw helperError("sdist_run_socket_device_missing")
            }
            let sessionResult = LockedResultBox<SdistGuestNonExecutingSessionObservation>()
            let sessionCompletion = DispatchSemaphore(value: 0)
            let listenerDelegate = SdistGuestRunListener(
                authorized: authorized,
                closure: authorizedClosure,
                base: base,
                clone: clone,
                resultBox: sessionResult,
                completion: sessionCompletion
            )
            let socketListener = VZVirtioSocketListener()
            socketListener.delegate = listenerDelegate
            queue.sync {
                socketDevice.setSocketListener(
                    socketListener,
                    forPort: sdistGuestVSOCKPortV1
                )
            }

            var primaryError: Error?
            var sessionObservation: SdistGuestNonExecutingSessionObservation?
            var vmStartSucceeded = false
            var sessionCompleted = false
            do {
                try startArtifactVirtualMachine(
                    virtualMachine,
                    queue: queue,
                    cancellation: cancellation
                )
                vmStartSucceeded = true
                switch waitForSdistRunCompletion(
                    sessionCompletion,
                    cancellation: cancellation,
                    timeoutMilliseconds: 120_000
                ) {
                case .completed:
                    break
                case .timedOut:
                    throw helperError("sdist_run_guest_session_timeout")
                case .cancelled(let reason):
                    throw SdistRunCancellationError.cancelled(reason)
                }
                sessionCompleted = true
                guard let result = sessionResult.load() else {
                    throw helperError("sdist_run_guest_session_result_missing")
                }
                sessionObservation = try result.get()
                try cancellation.throwIfRequested()
            } catch {
                primaryError = error
            }

            queue.sync {
                socketDevice.removeSocketListener(forPort: sdistGuestVSOCKPortV1)
            }
            let stopResult = stopArtifactVirtualMachine(virtualMachine, queue: queue)
            if !sessionCompleted, listenerDelegate.hasAcceptedConnection {
                sessionCompleted = sessionCompletion.wait(
                    timeout: .now() + .seconds(10)
                ) == .success
            }
            let guestSessionTerminated = sdistGuestSessionTerminationProven(
                connectionAccepted: listenerDelegate.hasAcceptedConnection,
                sessionCompletionObserved: sessionCompleted
            )
            var cloneCleanupSucceeded = false
            var cleanupError: Error?
            let vmStopSucceeded: Bool
            switch stopResult {
            case .success: vmStopSucceeded = true
            case .failure: vmStopSucceeded = false
            }
            let cleanupDisposition = sdistRunCloneCleanupDisposition(
                vmStopSucceeded: vmStopSucceeded,
                guestSessionTerminated: guestSessionTerminated
            )
            switch cleanupDisposition {
            case .cleanupAuthorized:
                do {
                    try clone.cleanup()
                    cloneCleanupSucceeded = true
                    pendingClone = nil
                } catch {
                    cleanupError = error
                }
            case .retainBecauseVMStopUnproven:
                if case .failure(let error) = stopResult {
                    cleanupError = error
                } else {
                    cleanupError = helperError(
                        cleanupDisposition.reasonCode
                            ?? "sdist_run_clone_cleanup_disposition_invalid"
                    )
                }
            case .retainBecauseGuestSessionUnterminated:
                cleanupError = helperError(
                    cleanupDisposition.reasonCode
                        ?? "sdist_run_clone_cleanup_disposition_invalid"
                )
            }

            if primaryError != nil || cleanupError != nil {
                var reasons: [String] = []
                if let primaryError { reasons.append(String(describing: primaryError)) }
                if let cleanupError { reasons.append(String(describing: cleanupError)) }
                if !guestSessionTerminated {
                    reasons.append("sdist_run_guest_session_not_terminated")
                }
                if !cloneCleanupSucceeded {
                    reasons.append("sdist_run_clone_cleanup_unproven")
                }
                emit(
                    fields: [
                        "schema_version": "whoathere.macos_sdist_run_nonexecuting.v1",
                        "helper_version": helperVersion,
                        "status": "error",
                        "execution_requested": true,
                        "authority_id": authorized.authority.authorityID,
                        "authority_consumed": true,
                        "authority_replay_state_persisted": authorized.authority.replayStatePersisted,
                        "submission_prelude_verified": true,
                        "run_spec_sha256": prelude.runSpecSHA256,
                        "build_closure_sha256": prelude.buildClosureSHA256,
                        "artifact_sha256": prelude.artifactSHA256,
                        "network_device_count": 0,
                        "sdist_vsock_port": sdistGuestVSOCKPortV1,
                        "vm_start_succeeded": vmStartSucceeded,
                        "vm_stop_succeeded": vmStopSucceeded,
                        "guest_session_completed": sessionCompleted,
                        "guest_channel_terminated": guestSessionTerminated,
                        "clone_cleanup_succeeded": cloneCleanupSucceeded,
                        "build_closure_transport_verified": false,
                        "build_closure_staged": false,
                        "cancellation_requested": cancellation.reason != nil,
                        "cancellation_reason": cancellation.reason?.rawValue ?? NSNull(),
                        "package_execution_enabled": false,
                        "sync_back_enabled": false,
                        "build_closure_materialized": false,
                        "reason_codes": reasonArray(reasons),
                        "exit_code": 70
                    ],
                    exitCode: 70
                )
            }
            guard let observation = sessionObservation else {
                throw helperError("sdist_run_guest_session_observation_missing")
            }
            emit(
                fields: [
                    "schema_version": "whoathere.macos_sdist_run_nonexecuting.v1",
                    "helper_version": helperVersion,
                    "status": "staged_no_execution_no_closure_materialization",
                    "execution_requested": true,
                    "authority_id": authorized.authority.authorityID,
                    "authority_record_sha256": authorized.authority.authorityRecordSHA256,
                    "authority_consumed": true,
                    "authority_replay_state_persisted": authorized.authority.replayStatePersisted,
                    "transport_verified": true,
                    "run_spec_sha256": prelude.runSpecSHA256,
                    "template_sha256": prelude.templateSHA256,
                    "build_closure_sha256": observation.stagingReceipt.buildClosureSHA256,
                    "build_closure_payload_sha256": observation.closureTransport.payloadSHA256,
                    "build_closure_artifact_count": observation.closureTransport.artifactCount,
                    "build_closure_payload_byte_length": observation.closureTransport.payloadByteLength,
                    "build_closure_manifest_sha256": observation.stagingReceipt.closureManifestSHA256,
                    "build_closure_staged_device": observation.stagingReceipt.closureStagedDevice,
                    "build_closure_staged_inode": observation.stagingReceipt.closureStagedInode,
                    "challenge_binding_sha256": authorized.authority.challengeBindingSHA256,
                    "execution_binding_sha256": observation.stagingReceipt.executionBindingSHA256,
                    "clone_binding_sha256": observation.stagingReceipt.cloneBindingSHA256,
                    "artifact_sha256": observation.stagingReceipt.artifactSHA256,
                    "artifact_byte_length": observation.stagingReceipt.artifactByteLength,
                    "scenario_id": prelude.scenarioID,
                    "scenario_kind": prelude.scenarioKind,
                    "network_device_count": 0,
                    "sdist_vsock_port": sdistGuestVSOCKPortV1,
                    "vm_start_succeeded": true,
                    "vm_stop_succeeded": true,
                    "guest_authentication_verified": observation.authentication.signatureVerified,
                    "guest_staging_receipt_verified": observation.stagingReceipt.signatureVerified,
                    "guest_staging_cleanup_succeeded": true,
                    "build_closure_transport_verified": true,
                    "build_closure_staged": true,
                    "guest_channel_terminated": true,
                    "clone_cleanup_succeeded": true,
                    "cancellation_requested": false,
                    "cancellation_reason": NSNull(),
                    "package_execution_enabled": observation.packageExecutionEnabled,
                    "sync_back_enabled": observation.syncBackEnabled,
                    "build_closure_materialized": observation.buildClosureMaterialized,
                    "reason_codes": ["sdist_staged_and_destroyed_without_execution"],
                    "exit_code": 0
                ],
                exitCode: 0
            )
        } catch {
            var cloneCleanupSucceeded = pendingClone == nil
            var reasons = [String(describing: error)]
            if let clone = pendingClone {
                do {
                    try clone.cleanup()
                    pendingClone = nil
                    cloneCleanupSucceeded = true
                } catch {
                    reasons.append(String(describing: error))
                }
            }
            emit(
                fields: [
                    "schema_version": "whoathere.macos_sdist_run_nonexecuting.v1",
                    "helper_version": helperVersion,
                    "status": "error",
                    "execution_requested": true,
                    "authority_id": options.authorityID,
                    "authority_consumed": consumedAuthority != nil
                        || authorityReplayStatePersisted,
                    "authority_replay_state_persisted": authorityReplayStatePersisted,
                    "transport_verified": false,
                    "clone_cleanup_succeeded": cloneCleanupSucceeded,
                    "build_closure_transport_verified": false,
                    "build_closure_staged": false,
                    "cancellation_requested": cancellation.reason != nil,
                    "cancellation_reason": cancellation.reason?.rawValue ?? NSNull(),
                    "package_execution_enabled": false,
                    "sync_back_enabled": false,
                    "build_closure_materialized": false,
                    "reason_codes": reasonArray(reasons),
                    "exit_code": 65
                ],
                exitCode: 65
            )
        }
    }

    private static func startArtifactVirtualMachine(
        _ virtualMachine: VZVirtualMachine,
        queue: DispatchQueue,
        cancellation: SdistRunCancellationState? = nil
    ) throws {
        try cancellation?.throwIfRequested()
        let resultBox = LockedResultBox<Void>()
        let completion = DispatchSemaphore(value: 0)
        let virtualMachineBox = UncheckedSendableBox(value: virtualMachine)
        queue.async {
            virtualMachineBox.value.start { result in
                resultBox.store(result.mapError { $0 })
                completion.signal()
            }
        }
        if let cancellation {
            switch waitForSdistRunCompletion(
                completion,
                cancellation: cancellation,
                timeoutMilliseconds: 60_000
            ) {
            case .completed:
                break
            case .timedOut:
                throw helperError("artifact_run_vm_start_timeout")
            case .cancelled(let reason):
                throw SdistRunCancellationError.cancelled(reason)
            }
        } else {
            guard completion.wait(timeout: .now() + .seconds(60)) == .success else {
                throw helperError("artifact_run_vm_start_timeout")
            }
        }
        guard let result = resultBox.load() else {
            throw helperError("artifact_run_vm_start_result_missing")
        }
        try result.get()
    }

    private static func installSdistRunCancellationSignals(
        _ cancellation: SdistRunCancellationState
    ) -> [DispatchSourceSignal] {
        let queue = DispatchQueue(label: "whoathere.macos.sdist-run.signals")
        let definitions: [(Int32, SdistRunCancellationReason)] = [
            (SIGINT, .interruptSignal),
            (SIGTERM, .terminationSignal)
        ]
        let sources = definitions.map { signalNumber, reason in
            let source = DispatchSource.makeSignalSource(signal: signalNumber, queue: queue)
            _ = Darwin.signal(signalNumber, SIG_IGN)
            source.setEventHandler {
                cancellation.request(reason)
            }
            source.resume()
            return source
        }
        activeSdistCancellationSignalSources = sources
        return sources
    }

    private static func stopArtifactVirtualMachine(
        _ virtualMachine: VZVirtualMachine,
        queue: DispatchQueue
    ) -> Result<String, Error> {
        let virtualMachineBox = UncheckedSendableBox(value: virtualMachine)
        let requestResult = LockedResultBox<Void>()
        let requestCompletion = DispatchSemaphore(value: 0)
        queue.async {
            if virtualMachineBox.value.state == .stopped {
                requestResult.store(.success(()))
            } else if virtualMachineBox.value.canRequestStop {
                do {
                    try virtualMachineBox.value.requestStop()
                    requestResult.store(.success(()))
                } catch {
                    requestResult.store(.failure(error))
                }
            } else {
                requestResult.store(.failure(helperError("artifact_run_vm_request_stop_unavailable")))
            }
            requestCompletion.signal()
        }
        _ = requestCompletion.wait(timeout: .now() + .seconds(2))

        let gracefulDeadline = Date().addingTimeInterval(20)
        while Date() < gracefulDeadline {
            let stopped = queue.sync { virtualMachine.state == .stopped }
            if stopped { return .success("guest_requested_stop") }
            Thread.sleep(forTimeInterval: 0.25)
        }

        let forceResult = LockedResultBox<Void>()
        let forceCompletion = DispatchSemaphore(value: 0)
        queue.async {
            guard virtualMachineBox.value.canStop else {
                forceResult.store(.failure(helperError("artifact_run_vm_force_stop_unavailable")))
                forceCompletion.signal()
                return
            }
            virtualMachineBox.value.stop { error in
                if let error {
                    forceResult.store(.failure(error))
                } else {
                    forceResult.store(.success(()))
                }
                forceCompletion.signal()
            }
        }
        guard forceCompletion.wait(timeout: .now() + .seconds(20)) == .success else {
            return .failure(helperError("artifact_run_vm_force_stop_timeout"))
        }
        guard let result = forceResult.load() else {
            return .failure(helperError("artifact_run_vm_force_stop_result_missing"))
        }
        do {
            try result.get()
        } catch {
            return .failure(error)
        }
        guard queue.sync(execute: { virtualMachine.state == .stopped }) else {
            return .failure(helperError("artifact_run_vm_stop_unproven"))
        }
        return .success("force_stop")
    }

    private static func run(_ options: HelperOptions) {
        switch options.command {
        case .version:
            version()
        case .status:
            status(options)
        case .`init`:
            initialize(options)
        case .upgradeLocalManifest:
            upgradeLocalManifest(options)
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
        case .detonate:
            detonate(options)
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
        let runtimeHealth = runtimeHealthSummary(layout: layout, runtimePID: runtimePID)
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
                "host_runtime_health_proven": runtimeHealth.hostRuntimeHealthProven,
                "health_proven": runtimeHealth.healthProven,
                "health_proof_type": runtimeHealth.healthProofType,
                "guest_health_proven": runtimeHealth.guestHealthProven,
                "runtime_health_reason_codes": runtimeHealth.reasonCodes,
                "guest_toolchain_npm_available": runtimeHealth.guestToolchainNpmAvailable,
                "guest_toolchain_python3_available": runtimeHealth.guestToolchainPython3Available,
                "guest_toolchain_pip_available": runtimeHealth.guestToolchainPipAvailable,
                "guest_toolchain_uv_available": runtimeHealth.guestToolchainUvAvailable,
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
                        "virtualization_metadata_missing"
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
            let stopped = waitForRuntimeProcessExit(pid, timeoutSeconds: 75)
            if !stopped {
                _ = kill(pid, SIGKILL)
                let forceKilled = waitForRuntimeProcessExit(pid, timeoutSeconds: 10)
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
                        "runtime_stop_observed": forceKilled,
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

    private struct RuntimeHealthSummary {
        var runtimePID: pid_t?
        var runtimeAlive: Bool
        var hostRuntimeHealthProven: Bool
        var healthProven: Bool
        var guestHealthProven: Bool
        var healthProofType: String
        var reasonCodes: [String]
        var guestToolchainNpmAvailable: Bool
        var guestToolchainPython3Available: Bool
        var guestToolchainPipAvailable: Bool
        var guestToolchainUvAvailable: Bool
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

    private static func upgradeLocalManifest(_ options: HelperOptions) {
        let layout = BundleLayout(stateDir: stateDirURL(from: options))
        if !options.execute {
            emit(
                fields: baseFields(status: "dry_run").merging([
                    "operation": "upgrade-local-manifest",
                    "mutation": false,
                    "state_dir": layout.stateDir.path,
                    "manifest_path": layout.manifestPath.path,
                    "reason_codes": ["execute_required_for_mutation"],
                    "exit_code": 0
                ]) { _, new in new },
                exitCode: 0
            )
        }

        let validationWithoutSignature = validateManifest(layout: layout, includeSignatureReason: false)
        var reasons = validationWithoutSignature.reasonCodes
        let fields = validationWithoutSignature.fields
        let imageID = fields["image_id", default: ""]
        let signatureStatus = fields["signature_status", default: ""]

        if signatureStatus != "signature_verification_not_implemented" {
            reasons.append("manifest_upgrade_signature_status_not_legacy_local")
        }
        if imageID != "local-restore-image-install" && imageID != "local-imported-disk" {
            reasons.append("manifest_upgrade_image_id_not_local_developer")
        }
        if !fileExists(layout.configPath) {
            reasons.append("config_missing")
        }
        if !fileExists(layout.diskPath) {
            reasons.append("disk_missing")
        }
        if imageID == "local-restore-image-install" {
            if !fileExists(layout.auxiliaryStoragePath) {
                reasons.append("auxiliary_storage_missing")
            }
            if !fileExists(layout.hardwareModelPath) {
                reasons.append("hardware_model_missing")
            }
            if !fileExists(layout.machineIdentifierPath) {
                reasons.append("machine_identifier_missing")
            }
        }

        let finalReasons = reasonArray(reasons)
        guard finalReasons.isEmpty else {
            emit(
                fields: failClosedFields(layout: layout, reasons: finalReasons, exitCode: 20)
                    .merging([
                        "operation": "upgrade-local-manifest",
                        "mutation": false,
                        "manifest_path": layout.manifestPath.path,
                        "manifest_signature_status": signatureStatus.isEmpty ? "missing" : signatureStatus,
                        "image_id": imageID.isEmpty ? "missing" : imageID
                    ]) { _, new in new },
                exitCode: 20
            )
        }

        do {
            guard let contents = try? String(contentsOf: layout.manifestPath, encoding: .utf8) else {
                throw helperError("manifest_unreadable")
            }
            let upgraded = contents
                .split(separator: "\n", omittingEmptySubsequences: false)
                .map { rawLine -> String in
                    let line = String(rawLine)
                    if line.trimmingCharacters(in: .whitespaces)
                        == "signature_status=signature_verification_not_implemented" {
                        return "signature_status=local_developer_verified"
                    }
                    return line
                }
                .joined(separator: "\n")
            try (upgraded.hasSuffix("\n") ? upgraded : upgraded + "\n")
                .write(to: layout.manifestPath, atomically: true, encoding: .utf8)
            let upgradedValidation = validateManifest(layout: layout, includeSignatureReason: true)
            guard upgradedValidation.reasonCodes.isEmpty else {
                emit(
                    fields: failClosedFields(layout: layout, reasons: upgradedValidation.reasonCodes, exitCode: 70)
                        .merging([
                            "operation": "upgrade-local-manifest",
                            "mutation": true,
                            "manifest_path": layout.manifestPath.path,
                            "manifest_signature_status": upgradedValidation.signatureStatus
                        ]) { _, new in new },
                    exitCode: 70
                )
            }
            emit(
                fields: baseFields(status: "ok").merging([
                    "operation": "upgrade-local-manifest",
                    "mutation": true,
                    "state_dir": layout.stateDir.path,
                    "manifest_path": layout.manifestPath.path,
                    "image_id": imageID,
                    "previous_signature_status": signatureStatus,
                    "manifest_signature_status": upgradedValidation.signatureStatus,
                    "high_risk_package_execution_enabled": false,
                    "exit_code": 0
                ]) { _, new in new },
                exitCode: 0
            )
        } catch {
            emit(
                fields: failClosedFields(layout: layout, reasons: ["manifest_upgrade_failed", sanitizedReason(error)], exitCode: 70)
                    .merging([
                        "operation": "upgrade-local-manifest",
                        "mutation": false,
                        "manifest_path": layout.manifestPath.path
                    ]) { _, new in new },
                exitCode: 70
            )
        }
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

    private static func runtimeHealthSummary(layout: BundleLayout, runtimePID: pid_t?) -> RuntimeHealthSummary {
        guard let pid = runtimePID, runtimeProcessIsAlive(pid) else {
            return RuntimeHealthSummary(
                runtimePID: runtimePID,
                runtimeAlive: false,
                hostRuntimeHealthProven: false,
                healthProven: false,
                guestHealthProven: false,
                healthProofType: "none",
                reasonCodes: runtimePID == nil ? ["runtime_pid_missing"] : ["runtime_process_not_running"],
                guestToolchainNpmAvailable: false,
                guestToolchainPython3Available: false,
                guestToolchainPipAvailable: false,
                guestToolchainUvAvailable: false
            )
        }
        guard fileExists(layout.healthProofPath),
              let runtimeState = readJSONObject(layout.runtimeStatePath),
              let hostProof = readJSONObject(layout.healthProofPath),
              intField(runtimeState, "runtime_pid") == Int(pid),
              intField(hostProof, "runtime_pid") == Int(pid),
              let sessionID = runtimeState["vm_session_id"] as? String,
              hostProof["vm_session_id"] as? String == sessionID else {
            return RuntimeHealthSummary(
                runtimePID: pid,
                runtimeAlive: true,
                hostRuntimeHealthProven: false,
                healthProven: false,
                guestHealthProven: false,
                healthProofType: "none",
                reasonCodes: ["host_runtime_health_proof_missing_or_mismatched"],
                guestToolchainNpmAvailable: false,
                guestToolchainPython3Available: false,
                guestToolchainPipAvailable: false,
                guestToolchainUvAvailable: false
            )
        }
        guard let guestProof = readJSONObject(layout.guestHealthProofPath) else {
            return RuntimeHealthSummary(
                runtimePID: pid,
                runtimeAlive: true,
                hostRuntimeHealthProven: true,
                healthProven: false,
                guestHealthProven: false,
                healthProofType: "host_vm_start_only",
                reasonCodes: ["guest_health_proof_missing_or_mismatched"],
                guestToolchainNpmAvailable: false,
                guestToolchainPython3Available: false,
                guestToolchainPipAvailable: false,
                guestToolchainUvAvailable: false
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
            return RuntimeHealthSummary(
                runtimePID: pid,
                runtimeAlive: true,
                hostRuntimeHealthProven: true,
                healthProven: false,
                guestHealthProven: false,
                healthProofType: "host_vm_start_only",
                reasonCodes: guestProofReasons,
                guestToolchainNpmAvailable: false,
                guestToolchainPython3Available: false,
                guestToolchainPipAvailable: false,
                guestToolchainUvAvailable: false
            )
        }
        return RuntimeHealthSummary(
            runtimePID: pid,
            runtimeAlive: true,
            hostRuntimeHealthProven: true,
            healthProven: true,
            guestHealthProven: true,
            healthProofType: "guest_vsock_readiness",
            reasonCodes: [],
            guestToolchainNpmAvailable: guestProof["guest_toolchain_npm_available"] as? Bool ?? false,
            guestToolchainPython3Available: guestProof["guest_toolchain_python3_available"] as? Bool ?? false,
            guestToolchainPipAvailable: guestProof["guest_toolchain_pip_available"] as? Bool ?? false,
            guestToolchainUvAvailable: guestProof["guest_toolchain_uv_available"] as? Bool ?? false
        )
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
                "guest_toolchain_npm_available": guestProof["guest_toolchain_npm_available"] as? Bool ?? false,
                "guest_toolchain_python3_available": guestProof["guest_toolchain_python3_available"] as? Bool ?? false,
                "guest_toolchain_pip_available": guestProof["guest_toolchain_pip_available"] as? Bool ?? false,
                "guest_toolchain_uv_available": guestProof["guest_toolchain_uv_available"] as? Bool ?? false,
                "high_risk_package_execution_enabled": false,
                "exit_code": 0
            ]) { _, new in new },
            exitCode: 0
        )
    }

    private static func detonate(_ options: HelperOptions) {
        let layout = BundleLayout(stateDir: stateDirURL(from: options))
        let projectMode = options.detonationProjectPayloadPath != nil || options.detonationProjectWorkflow != nil
        if !options.execute {
            emit(
                fields: baseFields(status: "dry_run").merging([
                    "operation": "detonate",
                    "mutation": false,
                    "sync_back_enabled": options.detonationSyncBack,
                    "host_package_execution_enabled": false,
                    "high_risk_package_execution_enabled": false,
                    "state_dir": layout.stateDir.path,
                    "tool": options.detonationTool ?? "missing",
                    "command_class": options.detonationCommandClass ?? "missing",
                    "fixture": options.detonationFixture ?? "missing",
                    "project_mode": projectMode,
                    "project_workflow": options.detonationProjectWorkflow ?? "missing",
                    "timeout_seconds": options.detonationTimeoutSeconds,
                    "argv_count": options.detonationArgs.count,
                    "reason_codes": ["execute_required_for_vm_detonation"],
                    "exit_code": 0
                ]) { _, new in new },
                exitCode: 0
            )
        }
        guard let tool = options.detonationTool, ["npm", "pip", "uv"].contains(tool) else {
            emit(
                fields: failClosedFields(
                    layout: layout,
                    reasons: ["detonation_tool_required_or_unsupported"],
                    exitCode: 64
                ).merging([
                    "operation": "detonate",
                    "sync_back_enabled": false,
                    "host_package_execution_enabled": false,
                    "high_risk_package_execution_enabled": false
                ]) { _, new in new },
                exitCode: 64
            )
        }
        let commandClass = options.detonationCommandClass ?? "unsupported_detonation"
        guard commandClass != "unsupported_detonation" else {
            emit(
                fields: failClosedFields(
                    layout: layout,
                    reasons: ["detonation_workflow_unsupported"],
                    exitCode: 20
                ).merging([
                    "operation": "detonate",
                    "tool": tool,
                    "command_class": commandClass,
                    "sync_back_enabled": false,
                    "host_package_execution_enabled": false,
                    "high_risk_package_execution_enabled": false,
                    "verdict": "fail_closed_unsupported_workflow"
                ]) { _, new in new },
                exitCode: 20
            )
        }
        guard let pid = readRuntimePID(layout), runtimeProcessIsAlive(pid) else {
            emit(
                fields: failClosedFields(
                    layout: layout,
                    reasons: ["runtime_process_not_running"],
                    exitCode: 20
                ).merging([
                    "operation": "detonate",
                    "tool": tool,
                    "command_class": commandClass,
                    "sync_back_enabled": false,
                    "host_package_execution_enabled": false,
                    "high_risk_package_execution_enabled": false,
                    "verdict": "infrastructure_error_fail_closed"
                ]) { _, new in new },
                exitCode: 20
            )
        }
        let healthReasons = runtimeHealthReasonCodes(layout: layout, pid: pid)
        guard healthReasons.isEmpty else {
            emit(
                fields: failClosedFields(
                    layout: layout,
                    reasons: healthReasons,
                    exitCode: 20
                ).merging([
                    "operation": "detonate",
                    "tool": tool,
                    "command_class": commandClass,
                    "runtime_pid": Int(pid),
                    "runtime_pid_alive": true,
                    "sync_back_enabled": false,
                    "host_package_execution_enabled": false,
                    "high_risk_package_execution_enabled": false,
                    "verdict": "infrastructure_error_fail_closed"
                ]) { _, new in new },
                exitCode: 20
            )
        }
        guard !projectMode || tool == "pip" || tool == "npm" || tool == "uv" else {
            emit(
                fields: failClosedFields(
                    layout: layout,
                    reasons: ["project_detonation_tool_unsupported"],
                    exitCode: 20
                ).merging([
                    "operation": "detonate",
                    "tool": tool,
                    "command_class": commandClass,
                    "project_mode": projectMode,
                    "sync_back_enabled": false,
                    "host_package_execution_enabled": false,
                    "high_risk_package_execution_enabled": false,
                    "verdict": "fail_closed_unsupported_workflow"
                ]) { _, new in new },
                exitCode: 20
            )
        }
        let fixture = options.detonationFixture ?? (projectMode ? "project_mirror" : "")
        guard !fixture.isEmpty else {
            emit(
                fields: failClosedFields(
                    layout: layout,
                    reasons: ["detonation_fixture_required_until_project_mirror_transfer_implemented"],
                    exitCode: 20
                ).merging([
                    "operation": "detonate",
                    "tool": tool,
                    "command_class": commandClass,
                    "sync_back_enabled": false,
                    "host_package_execution_enabled": false,
                    "high_risk_package_execution_enabled": false,
                    "verdict": "fail_closed_unsupported_workflow"
                ]) { _, new in new },
                exitCode: 20
            )
        }
        let projectPayloadHex: String?
        do {
            projectPayloadHex = try validatedProjectPayloadHex(options: options, layout: layout, projectMode: projectMode)
        } catch {
            emit(
                fields: failClosedFields(
                    layout: layout,
                    reasons: ["project_payload_rejected", sanitizedReason(error)],
                    exitCode: 20
                ).merging([
                    "operation": "detonate",
                    "tool": tool,
                    "command_class": commandClass,
                    "fixture": fixture,
                    "project_mode": projectMode,
                    "sync_back_enabled": false,
                    "host_package_execution_enabled": false,
                    "high_risk_package_execution_enabled": false,
                    "verdict": "fail_closed_project_payload_rejected"
                ]) { _, new in new },
                exitCode: 20
            )
        }
        if projectMode {
            guard let workflow = options.detonationProjectWorkflow,
                  [
                    "pip_project_install",
                    "pip_requirements_install",
                    "npm_project_install",
                    "npm_ci",
                    "uv_pip_project_install",
                    "uv_pip_requirements_install"
                  ].contains(workflow) else {
                emit(
                    fields: failClosedFields(
                        layout: layout,
                        reasons: ["project_workflow_required_or_unsupported"],
                        exitCode: 20
                    ).merging([
                        "operation": "detonate",
                        "tool": tool,
                        "command_class": commandClass,
                        "fixture": fixture,
                        "project_mode": projectMode,
                        "sync_back_enabled": false,
                        "host_package_execution_enabled": false,
                        "high_risk_package_execution_enabled": false,
                        "verdict": "fail_closed_project_workflow_rejected"
                    ]) { _, new in new },
                    exitCode: 20
                )
            }
        }

        do {
            try FileManager.default.createDirectory(
                at: detonationJobsDir(layout),
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            let jobID = try randomHex(byteCount: 16)
            let requestNonce = try randomHex(byteCount: 16)
            let requestURL = detonationJobsDir(layout).appendingPathComponent("\(jobID).request.json")
            let resultURL = detonationJobsDir(layout).appendingPathComponent("\(jobID).result.json")
            try? FileManager.default.removeItem(at: requestURL)
            try? FileManager.default.removeItem(at: resultURL)
            var request: [String: Any] = [
                "schema_version": bundleSchemaVersion,
                "protocol": guestDetonationProtocol,
                "job_id": jobID,
                "request_nonce": requestNonce,
                "tool": tool,
                "command_class": commandClass,
                "fixture": fixture,
                "timeout_seconds": min(900, max(5, options.detonationTimeoutSeconds)),
                "argv_count": options.detonationArgs.count,
                "sync_back_enabled": options.detonationSyncBack,
                "host_package_execution_enabled": false,
                "high_risk_package_execution_enabled": false
            ]
            if projectMode {
                request["project_mode"] = true
                request["project_payload_hex"] = projectPayloadHex ?? ""
                request["project_workflow"] = options.detonationProjectWorkflow ?? ""
                request["project_api_probe_enabled"] = options.detonationProjectApiProbe
                if let importModule = options.detonationProjectImportModule {
                    request["project_import_module"] = importModule
                }
                if let requirementsPath = options.detonationProjectRequirementsPath {
                    request["project_requirements_path"] = requirementsPath
                }
            }
            let requestData = try JSONSerialization.data(withJSONObject: request, options: [.prettyPrinted, .sortedKeys])
            try requestData.write(to: requestURL, options: [.atomic])
            guard let result = waitForDetonationResult(
                resultURL: resultURL,
                expectedRequest: request,
                timeoutSeconds: TimeInterval(min(930, max(20, options.detonationTimeoutSeconds + 20)))
            ) else {
                emit(
                    fields: failClosedFields(
                        layout: layout,
                        reasons: ["guest_detonation_result_timeout"],
                        exitCode: 20
                    ).merging([
                        "operation": "detonate",
                        "tool": tool,
                        "command_class": commandClass,
                        "fixture": fixture,
                        "job_id": jobID,
                        "sync_back_enabled": false,
                        "host_package_execution_enabled": false,
                        "high_risk_package_execution_enabled": false,
                        "verdict": "timeout_fail_closed"
                    ]) { _, new in new },
                    exitCode: 20
                )
            }
            let resultExit = intField(result, "exit_code") ?? 20
            var fields = baseFields(status: result["status"] as? String ?? "fail_closed")
                .merging(result) { _, new in new }
            fields["operation"] = "detonate"
            fields["state_dir"] = layout.stateDir.path
            fields["bundle_dir"] = layout.bundleDir.path
            fields["runtime_pid"] = Int(pid)
            fields["runtime_pid_alive"] = true
            fields["tool"] = tool
            fields["command_class"] = commandClass
            fields["fixture"] = fixture
            fields["project_mode"] = projectMode
            fields["project_workflow"] = options.detonationProjectWorkflow ?? "none"
            fields["project_import_module"] = options.detonationProjectImportModule ?? "none"
            fields["project_api_probe_enabled"] = options.detonationProjectApiProbe
            fields["project_requirements_path"] = options.detonationProjectRequirementsPath ?? "none"
            fields["sync_back_enabled"] = result["sync_back_enabled"] as? Bool ?? false
            fields["host_package_execution_enabled"] = false
            fields["high_risk_package_execution_enabled"] = false
            fields["exit_code"] = resultExit
            emit(fields: fields, exitCode: Int32(resultExit))
        } catch {
            emit(
                fields: failClosedFields(
                    layout: layout,
                    reasons: ["detonation_job_submit_failed", sanitizedReason(error)],
                    exitCode: 70
                ).merging([
                    "operation": "detonate",
                    "tool": tool,
                    "command_class": commandClass,
                    "fixture": fixture,
                    "project_mode": projectMode,
                    "sync_back_enabled": false,
                    "host_package_execution_enabled": false,
                    "high_risk_package_execution_enabled": false,
                    "verdict": "fail_closed_runner_error"
                ]) { _, new in new },
                exitCode: 70
            )
        }
    }

    private static func runtimeHealthReasonCodes(layout: BundleLayout, pid: pid_t) -> [String] {
        guard fileExists(layout.healthProofPath),
              let runtimeState = readJSONObject(layout.runtimeStatePath),
              let hostProof = readJSONObject(layout.healthProofPath),
              intField(runtimeState, "runtime_pid") == Int(pid),
              intField(hostProof, "runtime_pid") == Int(pid),
              let sessionID = runtimeState["vm_session_id"] as? String,
              hostProof["vm_session_id"] as? String == sessionID else {
            return ["host_runtime_health_proof_missing_or_mismatched"]
        }
        guard let guestProof = readJSONObject(layout.guestHealthProofPath) else {
            return ["guest_health_proof_missing_or_mismatched"]
        }
        return validateGuestHealthProof(
            runtimeState: runtimeState,
            hostProof: hostProof,
            guestProof: guestProof,
            runtimePID: Int(pid),
            expectedHelperVersion: helperVersion,
            expectedProtocol: guestReadinessProtocol,
            expectedPort: Int(guestReadinessPort)
        )
    }

    private static func validatedProjectPayloadHex(
        options: HelperOptions,
        layout: BundleLayout,
        projectMode: Bool
    ) throws -> String? {
        guard projectMode else {
            return nil
        }
        guard let payloadPath = options.detonationProjectPayloadPath, !payloadPath.isEmpty else {
            throw helperError("project_payload_path_required")
        }
        guard payloadPath.hasPrefix("/") else {
            throw helperError("project_payload_path_not_absolute")
        }
        let payloadURL = URL(fileURLWithPath: payloadPath).standardizedFileURL
        let statePath = layout.stateDir.standardizedFileURL.path
        guard payloadURL.path == statePath || payloadURL.path.hasPrefix("\(statePath)/") else {
            throw helperError("project_payload_path_outside_state_dir")
        }
        guard fileExists(payloadURL), isRegularFile(payloadURL) else {
            throw helperError("project_payload_file_missing")
        }
        let attributes = try FileManager.default.attributesOfItem(atPath: payloadURL.path)
        let fileSize = (attributes[.size] as? NSNumber)?.intValue ?? 0
        guard fileSize > 0 else {
            throw helperError("project_payload_empty")
        }
        guard fileSize <= maxProjectPayloadHexBytes else {
            throw helperError("project_payload_too_large")
        }
        let payloadHex = try String(contentsOf: payloadURL, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !payloadHex.isEmpty, payloadHex.count % 2 == 0 else {
            throw helperError("project_payload_hex_invalid")
        }
        guard payloadHex.utf8.count <= maxProjectPayloadHexBytes else {
            throw helperError("project_payload_too_large")
        }
        guard payloadHex.allSatisfy({ character in
            character.isNumber || ("a"..."f").contains(character) || ("A"..."F").contains(character)
        }) else {
            throw helperError("project_payload_hex_invalid")
        }
        return payloadHex
    }

    private static func waitForDetonationResult(
        resultURL: URL,
        expectedRequest: [String: Any],
        timeoutSeconds: TimeInterval
    ) -> [String: Any]? {
        let deadline = Date().addingTimeInterval(timeoutSeconds)
        while Date() < deadline {
            if let result = readJSONObject(resultURL) {
                let mismatchReasons = detonationResultMismatchReasons(result, request: expectedRequest)
                if !mismatchReasons.isEmpty {
                    return detonationFailureResult(
                        jobID: expectedRequest["job_id"] as? String ?? "unknown",
                        reasons: ["guest_detonation_result_context_mismatch"] + mismatchReasons,
                        exitCode: 20
                    )
                }
                return result
            }
            Thread.sleep(forTimeInterval: 0.2)
        }
        return nil
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
            "signature_status=local_developer_verified",
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
            "signature_status=local_developer_verified",
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
            } else if signatureStatus != "verified" && signatureStatus != "local_developer_verified" {
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
