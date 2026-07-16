import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func selectedPackageExecutionActionIdentityRetainsEarlyFailedStage() throws {
    let first = packageExecutionActionEvidence(actionIndex: 2, label: "venv")
    let second = packageExecutionActionEvidence(actionIndex: 3, label: "install")
    let result = packageExecutionRuntimeResult(
        actions: [first, second],
        stageNames: [
            "python_create_fresh_wheel_virtual_environment",
            "python_pip_install_exact_wheel",
        ]
    )

    let selected = try selectedLinuxVzPackageExecutionActionIdentityV1(result)

    #expect(selected.actionIndex == 3)
    #expect(selected.stageName == "python_pip_install_exact_wheel")

    let earlyFailure = packageExecutionRuntimeResult(
        actions: [first],
        stageNames: ["python_create_fresh_wheel_virtual_environment"]
    )
    let earlySelected = try selectedLinuxVzPackageExecutionActionIdentityV1(earlyFailure)
    #expect(earlySelected.actionIndex == 2)
    #expect(earlySelected.stageName == "python_create_fresh_wheel_virtual_environment")
}

@Test func selectedPackageExecutionActionIdentityRejectsTranscriptEvidenceMismatch() throws {
    let action = packageExecutionActionEvidence(actionIndex: 2, label: "venv")
    var result = packageExecutionRuntimeResult(
        actions: [action],
        stageNames: ["python_create_fresh_wheel_virtual_environment"]
    )
    let badTranscript = try canonicalJSONData([
        "schema_version": "whoathere.linux_vz_package_execution_sequence_transcript.v2",
        "execution_request_sha256": result.executionRequestSHA256,
        "execution_grant_sha256": result.executionGrantSHA256,
        "attempt_binding_sha256": result.attemptBindingSHA256,
        "process_plan_sha256": result.processPlanSHA256,
        "artifact_sha256": result.artifactSHA256,
        "processes": [[
            "action_index": "2",
            "stage_name": "python_import_root_probe",
            "supervisor_evidence_sha256": sha256(action.supervisor),
            "process_sensor_evidence_sha256": sha256(Data("wrong".utf8)),
            "file_sensor_evidence_sha256": sha256(action.file),
            "network_sensor_evidence_sha256": sha256(action.network),
        ]],
    ])
    result = ParsedLinuxVzPackageRootRuntimeResultV1(
        transcript: badTranscript,
        transcriptSHA256: sha256(badTranscript),
        actions: result.actions,
        summary: result.summary,
        summarySHA256: result.summarySHA256,
        executionRequestSHA256: result.executionRequestSHA256,
        executionGrantSHA256: result.executionGrantSHA256,
        attemptBindingSHA256: result.attemptBindingSHA256,
        processPlanSHA256: result.processPlanSHA256,
        artifactSHA256: result.artifactSHA256,
        terminal: result.terminal,
        rootEvidenceAuthenticated: result.rootEvidenceAuthenticated,
        hostCompositionRequired: result.hostCompositionRequired,
        authoritativeVerdictPermitted: result.authoritativeVerdictPermitted,
        publicNetworkRoutePresent: result.publicNetworkRoutePresent,
        packageExecution: result.packageExecution,
        syncBackPermitted: result.syncBackPermitted
    )

    #expect(throws: LinuxVzPackageExecutionActionIdentityError.bindingMismatch) {
        try selectedLinuxVzPackageExecutionActionIdentityV1(result)
    }
}

private func packageExecutionActionEvidence(
    actionIndex: UInt32,
    label: String
) -> LinuxVzPackageRootRuntimeActionEvidenceV1 {
    LinuxVzPackageRootRuntimeActionEvidenceV1(
        actionIndex: actionIndex,
        supervisor: Data("supervisor-\(label)".utf8),
        rootReceipt: Data("receipt-\(label)".utf8),
        process: Data("process-\(label)".utf8),
        file: Data("file-\(label)".utf8),
        network: Data("network-\(label)".utf8)
    )
}

private func packageExecutionRuntimeResult(
    actions: [LinuxVzPackageRootRuntimeActionEvidenceV1],
    stageNames: [String]
) -> ParsedLinuxVzPackageRootRuntimeResultV1 {
    let request = sha256(Data("request".utf8))
    let grant = sha256(Data("grant".utf8))
    let attempt = sha256(Data("attempt".utf8))
    let plan = sha256(Data("plan".utf8))
    let artifact = sha256(Data("artifact".utf8))
    let processes: [[String: Any]] = zip(actions, stageNames).map { action, stageName in
        [
            "action_index": String(action.actionIndex),
            "stage_name": stageName,
            "supervisor_evidence_sha256": sha256(action.supervisor),
            "process_sensor_evidence_sha256": sha256(action.process),
            "file_sensor_evidence_sha256": sha256(action.file),
            "network_sensor_evidence_sha256": sha256(action.network),
        ]
    }
    let transcript = try! canonicalJSONData([
        "schema_version": "whoathere.linux_vz_package_execution_sequence_transcript.v2",
        "execution_request_sha256": request,
        "execution_grant_sha256": grant,
        "attempt_binding_sha256": attempt,
        "process_plan_sha256": plan,
        "artifact_sha256": artifact,
        "processes": processes,
    ])
    let summary = Data("summary".utf8)
    return ParsedLinuxVzPackageRootRuntimeResultV1(
        transcript: transcript,
        transcriptSHA256: sha256(transcript),
        actions: actions,
        summary: summary,
        summarySHA256: sha256(summary),
        executionRequestSHA256: request,
        executionGrantSHA256: grant,
        attemptBindingSHA256: attempt,
        processPlanSHA256: plan,
        artifactSHA256: artifact,
        terminal: actions.count == stageNames.count ? "process_failed" : "complete",
        rootEvidenceAuthenticated: true,
        hostCompositionRequired: true,
        authoritativeVerdictPermitted: false,
        publicNetworkRoutePresent: false,
        packageExecution: true,
        syncBackPermitted: false
    )
}
