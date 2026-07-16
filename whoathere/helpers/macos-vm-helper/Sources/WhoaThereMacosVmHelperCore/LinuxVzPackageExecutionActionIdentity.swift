import Foundation

public enum LinuxVzPackageExecutionActionIdentityError: Error, Equatable {
    case invalidTranscript
    case bindingMismatch
}

public struct LinuxVzPackageExecutionActionIdentityV1: Equatable, Sendable {
    public let actionIndex: UInt32
    public let stageName: String
}

/// Binds the process-action evidence selected for the flat compatibility aliases to the
/// authenticated execution transcript. In particular, an early process failure must retain its
/// real stage identity instead of being mistaken for a later package trigger that never ran.
public func selectedLinuxVzPackageExecutionActionIdentityV1(
    _ result: ParsedLinuxVzPackageRootRuntimeResultV1
) throws -> LinuxVzPackageExecutionActionIdentityV1 {
    guard sha256(result.transcript) == result.transcriptSHA256,
          let value = try? JSONSerialization.jsonObject(with: result.transcript)
            as? [String: Any],
          try canonicalJSONData(value) == result.transcript,
          value["schema_version"] as? String
            == "whoathere.linux_vz_package_execution_sequence_transcript.v2",
          value["execution_request_sha256"] as? String == result.executionRequestSHA256,
          value["execution_grant_sha256"] as? String == result.executionGrantSHA256,
          value["attempt_binding_sha256"] as? String == result.attemptBindingSHA256,
          value["process_plan_sha256"] as? String == result.processPlanSHA256,
          value["artifact_sha256"] as? String == result.artifactSHA256,
          let processes = value["processes"] as? [[String: Any]],
          processes.count == result.actions.count else {
        throw LinuxVzPackageExecutionActionIdentityError.invalidTranscript
    }

    let identities = try zip(processes, result.actions).map { process, action in
        guard let rawActionIndex = process["action_index"] as? String,
              let parsedActionIndex = linuxVzPackageExecutionActionIdentityDecimalV1(
                  rawActionIndex
              ),
              parsedActionIndex == UInt64(action.actionIndex),
              let stageName = process["stage_name"] as? String,
              linuxVzPackageExecutionStageNameV1(stageName),
              process["supervisor_evidence_sha256"] as? String
                == sha256(action.supervisor),
              process["process_sensor_evidence_sha256"] as? String
                == sha256(action.process),
              process["file_sensor_evidence_sha256"] as? String
                == sha256(action.file),
              process["network_sensor_evidence_sha256"] as? String
                == sha256(action.network) else {
            throw LinuxVzPackageExecutionActionIdentityError.bindingMismatch
        }
        return LinuxVzPackageExecutionActionIdentityV1(
            actionIndex: action.actionIndex,
            stageName: stageName
        )
    }
    guard let selected = identities.last else {
        throw LinuxVzPackageExecutionActionIdentityError.bindingMismatch
    }
    return selected
}

private func linuxVzPackageExecutionActionIdentityDecimalV1(_ value: String) -> UInt64? {
    guard !value.isEmpty, value == "0" || value.first != "0",
          value.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) else { return nil }
    return UInt64(value)
}

private func linuxVzPackageExecutionStageNameV1(_ value: String) -> Bool {
    !value.isEmpty && value.utf8.count <= 128 && value.utf8.allSatisfy { byte in
        (byte >= 97 && byte <= 122) || (byte >= 48 && byte <= 57) || byte == 95
    }
}
