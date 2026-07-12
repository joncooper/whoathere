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
    let serialLog: URL
    let timeoutSeconds: Int

    static func parse(_ arguments: [String]) throws -> Self {
        var kernel: URL?
        var initramfs: URL?
        var expectedKernelSHA256: String?
        var expectedInitramfsSHA256: String?
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
              validSHA256(expectedKernelSHA256), validSHA256(expectedInitramfsSHA256) else {
            throw HarnessError.usage
        }
        return Self(
            kernel: kernel,
            initramfs: initramfs,
            expectedKernelSHA256: expectedKernelSHA256,
            expectedInitramfsSHA256: expectedInitramfsSHA256,
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
                "usage: whoathere-linux-vz-conformance --kernel PATH --initramfs PATH --expected-kernel-sha256 SHA256 --expected-initramfs-sha256 SHA256 --serial-log PATH [--timeout-seconds 30]\n",
                stderr
            )
            exit(64)
        } catch {
            emitJSON([
                "schema_version": "whoathere.linux_vz_inert_boot_result.v2",
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
        let processSensorMarkerPresent = linuxVzInertSerialContainsExactMarker(
            serialData,
            marker: "WHOATHERE_SENSOR_PROCESS_PROBE_OK"
        )
        let success = stopped && markerPresent && processSensorMarkerPresent
            && missingRequiredMarkers.isEmpty && rawFrameCount == 0
            && imageIdentityStable
        emitJSON([
            "schema_version": "whoathere.linux_vz_inert_boot_result.v2",
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
