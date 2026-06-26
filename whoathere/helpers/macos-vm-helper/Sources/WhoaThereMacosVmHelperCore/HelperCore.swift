import Foundation

public let helperVersion = "0.1.0"
public let bundleSchemaVersion = "whoathere.macos_vm.bundle.v1"

public enum HelperCommand: String, Sendable {
    case version
    case status
    case `init`
    case start
    case run
    case suspend
    case reset
    case prune
    case health
}

public struct HelperOptions: Equatable, Sendable {
    public var command: HelperCommand
    public var stateDir: String?
    public var execute: Bool
    public var json: Bool
    public var imagePath: String?
    public var restoreImagePath: String?
    public var memoryMiB: UInt64
    public var diskGiB: UInt64

    public init(
        command: HelperCommand,
        stateDir: String? = nil,
        execute: Bool = false,
        json: Bool = false,
        imagePath: String? = nil,
        restoreImagePath: String? = nil,
        memoryMiB: UInt64 = 6144,
        diskGiB: UInt64 = 40
    ) {
        self.command = command
        self.stateDir = stateDir
        self.execute = execute
        self.json = json
        self.imagePath = imagePath
        self.restoreImagePath = restoreImagePath
        self.memoryMiB = memoryMiB
        self.diskGiB = diskGiB
    }
}

public enum ArgumentError: Error, Equatable, CustomStringConvertible {
    case commandRequired
    case unknownCommand(String)
    case valueRequired(String)
    case invalidInteger(String)
    case unknownFlag(String)

    public var description: String {
        switch self {
        case .commandRequired:
            return "command_required"
        case .unknownCommand(let command):
            return "unknown_command:\(command)"
        case .valueRequired(let flag):
            return "value_required:\(flag)"
        case .invalidInteger(let flag):
            return "invalid_integer:\(flag)"
        case .unknownFlag(let flag):
            return "unknown_flag:\(flag)"
        }
    }
}

public func parseArguments(_ arguments: [String]) throws -> HelperOptions {
    guard let commandToken = arguments.first else {
        throw ArgumentError.commandRequired
    }
    guard let command = HelperCommand(rawValue: commandToken) else {
        throw ArgumentError.unknownCommand(commandToken)
    }

    var options = HelperOptions(command: command)
    var index = arguments.index(after: arguments.startIndex)
    while index < arguments.endIndex {
        let token = arguments[index]
        switch token {
        case "--execute":
            options.execute = true
            index += 1
        case "--json":
            options.json = true
            index += 1
        case "--state-dir":
            options.stateDir = try value(after: token, in: arguments, at: &index)
        case "--image":
            options.imagePath = try value(after: token, in: arguments, at: &index)
        case "--restore-image":
            options.restoreImagePath = try value(after: token, in: arguments, at: &index)
        case "--memory-mib":
            options.memoryMiB = try integerValue(after: token, in: arguments, at: &index)
        case "--disk-gib":
            options.diskGiB = try integerValue(after: token, in: arguments, at: &index)
        default:
            if let split = token.firstIndex(of: "="), token.starts(with: "--") {
                let flag = String(token[..<split])
                let rawValue = String(token[token.index(after: split)...])
                switch flag {
                case "--state-dir":
                    options.stateDir = rawValue
                case "--image":
                    options.imagePath = rawValue
                case "--restore-image":
                    options.restoreImagePath = rawValue
                case "--memory-mib":
                    guard let parsed = UInt64(rawValue) else {
                        throw ArgumentError.invalidInteger(flag)
                    }
                    options.memoryMiB = parsed
                case "--disk-gib":
                    guard let parsed = UInt64(rawValue) else {
                        throw ArgumentError.invalidInteger(flag)
                    }
                    options.diskGiB = parsed
                default:
                    throw ArgumentError.unknownFlag(flag)
                }
                index += 1
            } else {
                throw ArgumentError.unknownFlag(token)
            }
        }
    }
    return options
}

public struct BundleLayout: Equatable, Sendable {
    public var stateDir: URL
    public var bundleDir: URL { stateDir.appendingPathComponent("bundle", isDirectory: true) }
    public var configPath: URL { bundleDir.appendingPathComponent("config.json") }
    public var manifestPath: URL { bundleDir.appendingPathComponent("image.manifest") }
    public var diskPath: URL { bundleDir.appendingPathComponent("disk.img") }
    public var auxiliaryStoragePath: URL { bundleDir.appendingPathComponent("auxiliary-storage") }
    public var hardwareModelPath: URL { bundleDir.appendingPathComponent("hardware-model.bin") }
    public var machineIdentifierPath: URL { bundleDir.appendingPathComponent("machine-identifier.bin") }
    public var runtimeStatePath: URL { bundleDir.appendingPathComponent("runtime.json") }
    public var healthProofPath: URL { bundleDir.appendingPathComponent("health.json") }
    public var guestHealthProofPath: URL { bundleDir.appendingPathComponent("guest-health.json") }
    public var guestToolsImagePath: URL { bundleDir.appendingPathComponent("guest-tools.dmg") }
    public var runtimeShutdownPath: URL { bundleDir.appendingPathComponent("shutdown.json") }
    public var runtimePidPath: URL { bundleDir.appendingPathComponent("runtime.pid") }
    public var savedStatePath: URL { bundleDir.appendingPathComponent("saved-state.bin") }
    public var logsDir: URL { stateDir.appendingPathComponent("logs", isDirectory: true) }
    public var runsDir: URL { stateDir.appendingPathComponent("runs", isDirectory: true) }
    public var cacheDir: URL { stateDir.appendingPathComponent("cache", isDirectory: true) }
    public var reportsDir: URL { stateDir.appendingPathComponent("reports", isDirectory: true) }
    public var overlaysDir: URL { stateDir.appendingPathComponent("overlays", isDirectory: true) }

    public init(stateDir: URL) {
        self.stateDir = stateDir
    }

    public func managedDirectories() -> [URL] {
        [stateDir, bundleDir, logsDir, runsDir, cacheDir, reportsDir, overlaysDir]
    }
}

public func defaultStateDir(environment: [String: String] = ProcessInfo.processInfo.environment) -> URL {
    if let home = environment["HOME"], !home.isEmpty {
        return URL(fileURLWithPath: home)
            .appendingPathComponent(".whoathere", isDirectory: true)
            .appendingPathComponent("macos-vm", isDirectory: true)
    }
    return URL(fileURLWithPath: ".whoathere", isDirectory: true)
        .appendingPathComponent("macos-vm", isDirectory: true)
}

public func stateDirURL(from options: HelperOptions) -> URL {
    if let stateDir = options.stateDir, !stateDir.isEmpty {
        return URL(fileURLWithPath: stateDir, isDirectory: true)
    }
    return defaultStateDir()
}

public func reasonArray(_ values: [String]) -> [String] {
    Array(Set(values)).sorted()
}

public func validateGuestHealthProof(
    runtimeState: [String: Any],
    hostProof: [String: Any],
    guestProof: [String: Any],
    runtimePID: Int,
    expectedHelperVersion: String,
    expectedProtocol: String,
    expectedPort: Int
) -> [String] {
    var reasons: [String] = []

    let runtimeSessionID = stringField(runtimeState, "vm_session_id")
    let runtimeChallengeHash = stringField(runtimeState, "guest_readiness_challenge_sha256")
    let runtimeImageDigest = stringField(runtimeState, "image_digest")

    if intField(runtimeState, "runtime_pid") != runtimePID {
        reasons.append("runtime_state_pid_mismatch")
    }
    if stringField(runtimeState, "schema_version") != bundleSchemaVersion {
        reasons.append("runtime_state_schema_mismatch")
    }
    if stringField(runtimeState, "helper_version") != expectedHelperVersion {
        reasons.append("runtime_state_helper_version_mismatch")
    }
    if boolField(runtimeState, "high_risk_package_execution_enabled") != false {
        reasons.append("runtime_state_high_risk_execution_not_disabled")
    }
    if runtimeSessionID == nil {
        reasons.append("runtime_state_session_missing")
    }
    if runtimeChallengeHash == nil {
        reasons.append("runtime_state_challenge_hash_missing")
    }
    if runtimeImageDigest == nil {
        reasons.append("runtime_state_image_digest_missing")
    }

    if intField(hostProof, "runtime_pid") != runtimePID {
        reasons.append("host_proof_pid_mismatch")
    }
    if stringField(hostProof, "schema_version") != bundleSchemaVersion {
        reasons.append("host_proof_schema_mismatch")
    }
    if stringField(hostProof, "helper_version") != expectedHelperVersion {
        reasons.append("host_proof_helper_version_mismatch")
    }
    if boolField(hostProof, "high_risk_package_execution_enabled") != false {
        reasons.append("host_proof_high_risk_execution_not_disabled")
    }
    if let runtimeSessionID, stringField(hostProof, "vm_session_id") != runtimeSessionID {
        reasons.append("host_proof_session_mismatch")
    }
    if let runtimeChallengeHash, stringField(hostProof, "guest_readiness_challenge_sha256") != runtimeChallengeHash {
        reasons.append("host_proof_challenge_hash_mismatch")
    }
    if let runtimeImageDigest, stringField(hostProof, "image_digest") != runtimeImageDigest {
        reasons.append("host_proof_image_digest_mismatch")
    }
    if stringField(hostProof, "health_proof_type") != "host_vm_start_only" {
        reasons.append("host_proof_type_mismatch")
    }
    if boolField(hostProof, "host_runtime_health_proven") != true {
        reasons.append("host_runtime_health_not_proven")
    }

    if intField(guestProof, "runtime_pid") != runtimePID {
        reasons.append("guest_proof_pid_mismatch")
    }
    if stringField(guestProof, "schema_version") != bundleSchemaVersion {
        reasons.append("guest_proof_schema_mismatch")
    }
    if stringField(guestProof, "helper_version") != expectedHelperVersion {
        reasons.append("guest_proof_helper_version_mismatch")
    }
    if boolField(guestProof, "high_risk_package_execution_enabled") != false {
        reasons.append("guest_proof_high_risk_execution_not_disabled")
    }
    if let runtimeSessionID, stringField(guestProof, "vm_session_id") != runtimeSessionID {
        reasons.append("guest_proof_session_mismatch")
    }
    if let runtimeChallengeHash, stringField(guestProof, "guest_readiness_challenge_sha256") != runtimeChallengeHash {
        reasons.append("guest_proof_challenge_hash_mismatch")
    }
    if let runtimeImageDigest, stringField(guestProof, "image_digest") != runtimeImageDigest {
        reasons.append("guest_proof_image_digest_mismatch")
    }
    if stringField(guestProof, "health_proof_type") != "guest_vsock_readiness" {
        reasons.append("guest_proof_type_mismatch")
    }
    if boolField(guestProof, "guest_health_proven") != true {
        reasons.append("guest_health_not_proven")
    }
    if stringField(guestProof, "guest_readiness_protocol") != expectedProtocol {
        reasons.append("guest_proof_protocol_mismatch")
    }
    if intField(guestProof, "guest_readiness_port") != expectedPort {
        reasons.append("guest_proof_port_mismatch")
    }

    return reasonArray(reasons)
}

private func value(after flag: String, in arguments: [String], at index: inout Int) throws -> String {
    let valueIndex = arguments.index(after: index)
    guard valueIndex < arguments.endIndex else {
        throw ArgumentError.valueRequired(flag)
    }
    index = arguments.index(after: valueIndex)
    return arguments[valueIndex]
}

private func integerValue(after flag: String, in arguments: [String], at index: inout Int) throws -> UInt64 {
    let rawValue = try value(after: flag, in: arguments, at: &index)
    guard let parsed = UInt64(rawValue) else {
        throw ArgumentError.invalidInteger(flag)
    }
    return parsed
}

private func stringField(_ fields: [String: Any], _ key: String) -> String? {
    fields[key] as? String
}

private func boolField(_ fields: [String: Any], _ key: String) -> Bool? {
    if let value = fields[key] as? Bool {
        return value
    }
    if let value = fields[key] as? NSNumber {
        return value.boolValue
    }
    return nil
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
