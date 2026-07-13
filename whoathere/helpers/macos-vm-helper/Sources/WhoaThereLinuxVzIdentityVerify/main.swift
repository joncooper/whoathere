import Foundation
import WhoaThereMacosVmHelperCore

@main
private struct LinuxVzIdentityVerify {
    static func main() {
        do {
            if CommandLine.arguments.count == 3,
               CommandLine.arguments[1] == "--qualification",
               CommandLine.arguments[2].hasPrefix("/") {
                try verifyQualificationRecord(path: CommandLine.arguments[2])
                return
            }
            if CommandLine.arguments.count == 3,
               CommandLine.arguments[1] == "--package-authority-request",
               CommandLine.arguments[2].hasPrefix("/") {
                try verifyPackageAuthorityRequest(path: CommandLine.arguments[2])
                return
            }
            guard CommandLine.arguments.count == 3,
                  CommandLine.arguments[1].hasPrefix("/") else {
                throw LinuxVzTelemetryBackendIdentityError.invalidIdentity
            }
            let url = URL(fileURLWithPath: CommandLine.arguments[1])
            let values = try url.resourceValues(forKeys: [
                .isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey
            ])
            guard values.isRegularFile == true, values.isSymbolicLink != true,
                  let size = values.fileSize, size > 0,
                  size <= maximumLinuxVzTelemetryBackendIdentityBytesV1 else {
                throw LinuxVzTelemetryBackendIdentityError.invalidIdentity
            }
            let data = try Data(contentsOf: url, options: [.mappedIfSafe])
            let identity = try decodeUnqualifiedLinuxVzTelemetryBackendIdentity(
                data,
                expectedTelemetryRequirementsSHA256: CommandLine.arguments[2]
            )
            let result: [String: Any] = [
                "execution_authority": identity.executionAuthorityPermitted,
                "identity_sha256": identity.identitySHA256,
                "package_execution": false,
                "package_gid": String(identity.packageGID),
                "package_uid": String(identity.packageUID),
                "qualification_state": "candidate_unqualified",
                "schema_version": "whoathere.linux_vz_backend_identity_verification.v1",
                "sync_back": false
            ]
            let output = try JSONSerialization.data(
                withJSONObject: result,
                options: [.sortedKeys, .withoutEscapingSlashes]
            )
            print(String(decoding: output, as: UTF8.self))
        } catch {
            fputs("whoathere Linux VZ identity verification failed: \(error)\n", stderr)
            exit(70)
        }
    }

    private static func verifyQualificationRecord(path: String) throws {
        let url = URL(fileURLWithPath: path)
        let values = try url.resourceValues(forKeys: [
            .isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey
        ])
        guard values.isRegularFile == true, values.isSymbolicLink != true,
              let size = values.fileSize, size > 0,
              size <= maximumLinuxVzTelemetryConformanceEvidenceBytesV1 else {
            throw LinuxVzTelemetryQualificationRecordError.invalidSchema
        }
        let data = try Data(contentsOf: url, options: [.mappedIfSafe])
        let record = try decodeLinuxVzTelemetryQualificationRecord(data)
        let result: [String: Any] = [
            "backend_identity_sha256": record.backendIdentitySHA256,
            "conformance_case_count": String(record.caseCount),
            "conformance_evidence_set_sha256": record.conformanceEvidenceSetSHA256,
            "execution_authority": record.packageExecutionAuthorityPermitted,
            "package_execution": false,
            "qualified_backend_sha256": record.recordSHA256,
            "schema_version": "whoathere.linux_vz_telemetry_qualification_verification.v1",
            "status": "verified",
            "sync_back": record.syncBackPermitted
        ]
        let output = try JSONSerialization.data(
            withJSONObject: result,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        print(String(decoding: output, as: UTF8.self))
    }

    private static func verifyPackageAuthorityRequest(path: String) throws {
        let url = URL(fileURLWithPath: path)
        let values = try url.resourceValues(forKeys: [
            .isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey
        ])
        guard values.isRegularFile == true, values.isSymbolicLink != true,
              let size = values.fileSize, size > 0,
              size <= maximumLinuxVzPackageAuthorityRequestBytesV1 else {
            throw LinuxVzPackageAuthorityRequestError.invalidSchema
        }
        let data = try Data(contentsOf: url, options: [.mappedIfSafe])
        let request = try decodeLinuxVzPackageAuthorityRequest(data)
        let result: [String: Any] = [
            "artifact_kind": request.artifactKind,
            "artifact_sha256": request.artifactSHA256,
            "execution_authority": request.packageExecutionAuthorityPermitted,
            "package_execution": false,
            "qualified_backend_sha256": request.qualifiedTelemetryBackendSHA256,
            "request_sha256": request.requestSHA256,
            "scenario_plan_sha256": request.scenarioPlanSHA256,
            "scenario_template_sha256": request.scenarioTemplateSHA256,
            "schema_version": "whoathere.linux_vz_package_authority_request_verification.v1",
            "status": "verified_candidate_runtime_unqualified",
            "sync_back": request.syncBackPermitted
        ]
        let output = try JSONSerialization.data(
            withJSONObject: result,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        print(String(decoding: output, as: UTF8.self))
    }
}
