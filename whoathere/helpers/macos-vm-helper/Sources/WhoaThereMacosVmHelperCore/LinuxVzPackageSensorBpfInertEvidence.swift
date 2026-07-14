import Foundation

public let linuxVzPackageSensorBpfInertEvidenceSchemaV12 =
    "whoathere.linux_vz_package_sensor_bpf_inert_probe.v12"
public let linuxVzPackageSensorBpfInertEvidenceSerialPrefixV1 =
    "WHOATHERE_PACKAGE_SENSOR_BPF_INERT_EVIDENCE "

public let linuxVzPackageSensorBpfInertRequiredMarkersV1 = [
    "WHOATHERE_PACKAGE_SENSOR_BPF_INERT_BEGIN",
    "WHOATHERE_CAPABILITY kernel_release=6.18.35-0-virt",
    "WHOATHERE_CAPABILITY architecture=aarch64",
    "WHOATHERE_CAPABILITY cgroup_v2=mounted",
    "WHOATHERE_CAPABILITY bpf_fs=mounted",
    "WHOATHERE_CAPABILITY tracefs=mounted",
    "WHOATHERE_PACKAGE_SENSOR_BPF_INERT_OK",
    "WHOATHERE_CAPABILITY inert_fixture_execution=true",
    "WHOATHERE_CAPABILITY external_route_configured=false",
    "WHOATHERE_CAPABILITY package_execution=false",
    "WHOATHERE_CAPABILITY malware_execution=false",
    "WHOATHERE_CAPABILITY sync_back=false",
]

public enum LinuxVzPackageSensorBpfInertEvidenceError: Error, Equatable {
    case missing
    case duplicate
    case limitExceeded
    case invalidJSON
    case nonCanonical
    case invalidSchema
}

public struct LinuxVzPackageSensorBpfInertEvidenceV12: Equatable, Sendable {
    public let canonicalJSON: Data
    public let payloadSHA256: String
    public let evidenceByteLength: UInt64
    public let cgroupID: UInt64
    public let fixturePID: UInt64
    public let fixtureSHA256: String
    public let runtimeBTFSHA256: String
    public let taskExitCodeByteOffset: UInt64
    public let kernelExitWaitStatus: UInt64
    public let waitpidWaitStatus: UInt64
    public let attachmentCPU: UInt64
    public let fixtureCPU: UInt64
    public let observedEventCPUs: [UInt64]
    public let collectorDrainMode: String
    public let collectorMode: String
    public let activeDrainPollCount: UInt64
    public let activeNonemptyDrainCount: UInt64
    public let sourceEventCountBeforeFinish: UInt64
    public let finishDrainEventCount: UInt64
    public let maximumDrainBatchRecordCount: UInt64
    public let networkIntentCount: UInt64
    public let faultCgroupID: UInt64
    public let faultFixturePID: UInt64
    public let faultSignalLatencyMicroseconds: UInt64
    public let faultFixtureTerminationSignal: UInt64
    public let fileActiveDrainPollCount: UInt64
    public let fileActiveNonemptyDrainCount: UInt64
    public let fileSourceEventCount: UInt64
    public let fileDiffChangeCount: UInt64
    public let filePermissionResponseCount: UInt64
    public let fileIgnoredNonCgroupEventCount: UInt64
    public let fileFanotifyMarkScope: [String]
    public let fileFanotifyUnobservedMounts: [String]
    public let fileGlobalMountCoverageComplete: Bool
    public let leaderExecCount: UInt64
    public let preReleaseEventCount: UInt64
    public let processCollectorCoverageComplete: Bool
    public let rootProcessEvidenceByteLength: UInt64
    public let rootProcessEvidenceObservationCount: UInt64
    public let rootProcessEvidenceSHA256: String
    public let rootProcessEvidenceSourceEventCount: UInt64
    public let rootNetworkEvidenceByteLength: UInt64
    public let rootNetworkEvidenceEventCount: UInt64
    public let rootNetworkEvidenceSHA256: String
    public let rootNetworkEvidenceUnobservedCapabilities: [String]
    public let rootFileEvidenceByteLength: UInt64
    public let rootFileEvidenceChangeCount: UInt64
    public let rootFileEvidenceSHA256: String
    public let rootFileEvidenceSourceEventCount: UInt64
    public let rootFileEvidenceBaselineSnapshotSHA256: String
    public let rootFileEvidenceFinalSnapshotSHA256: String
    public let rootFileEvidenceWorkspaceDiffSHA256: String
    public let tracepointFormatSHA256: [String: String]
}

public func decodeLinuxVzPackageSensorBpfInertEvidenceV12(
    _ serialData: Data,
    expectedFixtureSHA256: String,
    expectedRuntimeBTFSHA256: String,
    expectedTaskExitCodeByteOffset: UInt64
) throws -> LinuxVzPackageSensorBpfInertEvidenceV12 {
    guard packageSensorBpfInertDigest(expectedFixtureSHA256),
          packageSensorBpfInertDigest(expectedRuntimeBTFSHA256),
          expectedTaskExitCodeByteOffset > 0,
          expectedTaskExitCodeByteOffset <= UInt64(Int32.max) else {
        throw LinuxVzPackageSensorBpfInertEvidenceError.invalidSchema
    }
    let prefix = Array(linuxVzPackageSensorBpfInertEvidenceSerialPrefixV1.utf8)
    var payloads = [Data]()
    for rawLine in serialData.split(separator: 0x0A) {
        var line = Array(rawLine)
        if line.last == 0x0D { line.removeLast() }
        guard line.starts(with: prefix) else { continue }
        payloads.append(Data(line.dropFirst(prefix.count)))
    }
    guard !payloads.isEmpty else {
        throw LinuxVzPackageSensorBpfInertEvidenceError.missing
    }
    guard payloads.count == 1 else {
        throw LinuxVzPackageSensorBpfInertEvidenceError.duplicate
    }
    let payload = payloads[0]
    guard !payload.isEmpty, payload.count <= 16 * 1024 else {
        throw LinuxVzPackageSensorBpfInertEvidenceError.limitExceeded
    }
    guard let value = try? JSONSerialization.jsonObject(with: payload) as? [String: Any] else {
        throw LinuxVzPackageSensorBpfInertEvidenceError.invalidJSON
    }
    guard try canonicalJSONData(value) == payload else {
        throw LinuxVzPackageSensorBpfInertEvidenceError.nonCanonical
    }
    let expectedKeys = Set([
        "active_drain_poll_count", "active_nonempty_drain_count",
        "attachment_cpu", "attachment_scope", "cgroup_id", "collector_drain_mode",
        "collector_mode",
        "discarded_record_count", "dropped_event_count", "event_count", "event_kinds",
        "event_sequence_end", "event_sequence_start", "exit_attachment", "exit_status_source",
        "fault_cgroup_id", "fault_cgroup_kill_used", "fault_fixture_pid",
        "fault_fixture_termination_signal", "fault_maximum_source_events", "fault_signal_kind",
        "fault_signal_latency_microseconds", "fault_signal_observed", "fault_trigger",
        "file_active_drain_poll_count", "file_active_nonempty_drain_count",
        "file_collector_declared_scope_complete",
        "file_collector_global_mount_coverage_complete", "file_diff_change_count",
        "file_diff_completed_after_process_exit", "file_fanotify_overflow_count",
        "file_fanotify_mark_scope", "file_fanotify_unobserved_mounts",
        "file_ignored_non_cgroup_event_count", "file_maximum_drain_batch_event_count",
        "file_permission_denied_count", "file_permission_response_count",
        "file_required_fanotify_mark_count", "file_source_event_count",
        "finish_drain_event_count", "fixture_cpu", "fixture_exit_status", "fixture_pid",
        "fixture_sha256",
        "kernel_exit_wait_status", "leader_exec_count", "malware_execution",
        "maximum_drain_batch_record_count", "network_connect_destination_class",
        "network_connect_family", "network_connect_port", "network_connect_result",
        "network_intent_count", "network_raw_addresses_captured",
        "network_sendto_destination_class", "network_sendto_family", "network_sendto_port",
        "network_sendto_result", "observed_event_cpus", "online_cpus",
        "package_execution", "package_gid", "package_uid", "pre_release_event_count",
        "process_collector_coverage_complete", "root_process_evidence_byte_length",
        "root_process_evidence_canonical", "root_process_evidence_coverage_complete",
        "root_process_evidence_observation_count",
        "root_process_evidence_raw_arguments_captured",
        "root_process_evidence_raw_exec_paths_captured", "root_process_evidence_schema",
        "root_process_evidence_sha256", "root_process_evidence_source_event_count",
        "root_network_evidence_byte_length", "root_network_evidence_canonical",
        "root_network_evidence_composite_coverage_complete",
        "root_network_evidence_connect_sendto_coverage_complete",
        "root_network_evidence_dns_coverage_complete", "root_network_evidence_event_count",
        "root_network_evidence_guest_intent_coverage_complete",
        "root_network_evidence_host_frame_correlation_complete",
        "root_network_evidence_http_observation_complete",
        "root_network_evidence_process_sha256",
        "root_network_evidence_raw_addresses_serialized", "root_network_evidence_schema",
        "root_network_evidence_sha256", "root_network_evidence_unobserved_capabilities",
        "root_file_evidence_baseline_snapshot_sha256", "root_file_evidence_byte_length",
        "root_file_evidence_canonical", "root_file_evidence_change_count",
        "root_file_evidence_declared_scope_complete",
        "root_file_evidence_global_mount_coverage_complete",
        "root_file_evidence_final_snapshot_sha256",
        "root_file_evidence_raw_paths_captured", "root_file_evidence_schema",
        "root_file_evidence_sha256", "root_file_evidence_source_event_count",
        "root_file_evidence_workspace_diff_sha256",
        "runtime_btf_sha256", "schema_version",
        "source_event_count_before_finish", "sync_back",
        "task_exit_code_byte_offset", "tracepoint_format_sha256", "waitpid_wait_status",
    ])
    guard Set(value.keys) == expectedKeys,
          value["schema_version"] as? String == linuxVzPackageSensorBpfInertEvidenceSchemaV12,
          let activeDrainPollCount = packageSensorBpfInertDecimal(
              value["active_drain_poll_count"]
          ),
          activeDrainPollCount >= 1, activeDrainPollCount <= 10_000,
          let activeNonemptyDrainCount = packageSensorBpfInertDecimal(
              value["active_nonempty_drain_count"]
          ),
          activeNonemptyDrainCount >= 1,
          activeNonemptyDrainCount <= activeDrainPollCount,
          let attachmentCPU = packageSensorBpfInertDecimal(value["attachment_cpu"]),
          attachmentCPU == 0,
          value["attachment_scope"] as? String == "tracepoint_wide",
          value["collector_drain_mode"] as? String == "continuous_worker",
          value["collector_mode"] as? String == "root_bpf_ring_correlator",
          packageSensorBpfInertDecimal(value["discarded_record_count"]) == 0,
          packageSensorBpfInertDecimal(value["dropped_event_count"]) == 0,
          packageSensorBpfInertDecimal(value["event_count"]) == 18,
          value["event_kinds"] as? [String] == [
              "setgroups_enter", "setgroups_exit", "setgid_enter", "setgid_exit",
              "setuid_enter", "setuid_exit", "exec",
              "mmap_enter", "mmap_exit", "mmap_enter", "mmap_exit",
              "mmap_enter", "mmap_exit", "connect_enter", "connect_exit",
              "sendto_enter", "sendto_exit", "exit",
          ],
          packageSensorBpfInertDecimal(value["event_sequence_start"]) == 1,
          packageSensorBpfInertDecimal(value["event_sequence_end"]) == 18,
          value["exit_attachment"] as? String == "raw_tracepoint:sched_process_exit",
          value["exit_status_source"] as? String == "runtime_btf:task_struct.exit_code",
          let faultCgroupID = packageSensorBpfInertDecimal(value["fault_cgroup_id"]),
          faultCgroupID > 0,
          value["fault_cgroup_kill_used"] as? Bool == true,
          let faultFixturePID = packageSensorBpfInertDecimal(value["fault_fixture_pid"]),
          faultFixturePID >= 2, faultFixturePID <= UInt64(Int32.max),
          packageSensorBpfInertDecimal(value["fault_fixture_termination_signal"]) == 9,
          packageSensorBpfInertDecimal(value["fault_maximum_source_events"]) == 8,
          value["fault_signal_kind"] as? String == "nonblocking_pipe_marker",
          let faultSignalLatencyMicroseconds = packageSensorBpfInertDecimal(
              value["fault_signal_latency_microseconds"]
          ),
          faultSignalLatencyMicroseconds >= 1,
          faultSignalLatencyMicroseconds <= 2_000_000,
          value["fault_signal_observed"] as? Bool == true,
          value["fault_trigger"] as? String == "source_event_limit",
          let fileActiveDrainPollCount = packageSensorBpfInertDecimal(
              value["file_active_drain_poll_count"]
          ),
          fileActiveDrainPollCount >= 1, fileActiveDrainPollCount <= 10_000,
          let fileActiveNonemptyDrainCount = packageSensorBpfInertDecimal(
              value["file_active_nonempty_drain_count"]
          ),
          fileActiveNonemptyDrainCount >= 1,
          fileActiveNonemptyDrainCount <= fileActiveDrainPollCount,
          value["file_collector_declared_scope_complete"] as? Bool == true,
          value["file_collector_global_mount_coverage_complete"] as? Bool == false,
          packageSensorBpfInertDecimal(value["file_diff_change_count"]) == 1,
          value["file_diff_completed_after_process_exit"] as? Bool == true,
          packageSensorBpfInertDecimal(value["file_fanotify_overflow_count"]) == 0,
          let fileFanotifyMarkScope = value["file_fanotify_mark_scope"] as? [String],
          fileFanotifyMarkScope == [
              "dev_mount", "root_mount", "run_mount", "sys_mount", "workspace_mount",
          ],
          let fileFanotifyUnobservedMounts =
              value["file_fanotify_unobserved_mounts"] as? [String],
          fileFanotifyUnobservedMounts == ["proc_mount"],
          let fileIgnoredNonCgroupEventCount = packageSensorBpfInertDecimal(
              value["file_ignored_non_cgroup_event_count"]
          ),
          fileIgnoredNonCgroupEventCount <= 1_000_000,
          let fileMaximumDrainBatchEventCount = packageSensorBpfInertDecimal(
              value["file_maximum_drain_batch_event_count"]
          ),
          fileMaximumDrainBatchEventCount >= 1,
          fileMaximumDrainBatchEventCount <= 4_096,
          packageSensorBpfInertDecimal(value["file_permission_denied_count"]) == 0,
          let filePermissionResponseCount = packageSensorBpfInertDecimal(
              value["file_permission_response_count"]
          ),
          filePermissionResponseCount >= 1,
          packageSensorBpfInertDecimal(value["file_required_fanotify_mark_count"]) == 5,
          let fileSourceEventCount = packageSensorBpfInertDecimal(
              value["file_source_event_count"]
          ),
          fileSourceEventCount >= 5, fileSourceEventCount <= 4_096,
          filePermissionResponseCount <= fileSourceEventCount,
          let finishDrainEventCount = packageSensorBpfInertDecimal(
              value["finish_drain_event_count"]
          ),
          finishDrainEventCount <= 1,
          let fixtureCPU = packageSensorBpfInertDecimal(value["fixture_cpu"]),
          fixtureCPU == 1, fixtureCPU != attachmentCPU,
          packageSensorBpfInertDecimal(value["fixture_exit_status"]) == 0,
          let cgroupID = packageSensorBpfInertDecimal(value["cgroup_id"]),
          cgroupID > 0,
          let fixturePID = packageSensorBpfInertDecimal(value["fixture_pid"]),
          fixturePID >= 2, fixturePID <= UInt64(Int32.max), fixturePID != faultFixturePID,
          value["fixture_sha256"] as? String == expectedFixtureSHA256,
          let kernelExitWaitStatus = packageSensorBpfInertDecimal(
              value["kernel_exit_wait_status"]
          ),
          kernelExitWaitStatus == 0,
          packageSensorBpfInertDecimal(value["leader_exec_count"]) == 1,
          value["malware_execution"] as? Bool == false,
          let maximumDrainBatchRecordCount = packageSensorBpfInertDecimal(
              value["maximum_drain_batch_record_count"]
          ),
          maximumDrainBatchRecordCount >= 1, maximumDrainBatchRecordCount <= 18,
          value["network_connect_destination_class"] as? String == "documentation",
          value["network_connect_family"] as? String == "ipv4",
          packageSensorBpfInertDecimal(value["network_connect_port"]) == 443,
          value["network_connect_result"] as? String == "-101",
          let networkIntentCount = packageSensorBpfInertDecimal(value["network_intent_count"]),
          networkIntentCount == 2,
          value["network_raw_addresses_captured"] as? Bool == false,
          value["network_sendto_destination_class"] as? String == "documentation",
          value["network_sendto_family"] as? String == "ipv6",
          packageSensorBpfInertDecimal(value["network_sendto_port"]) == 53,
          value["network_sendto_result"] as? String == "-99",
          let observedEventCPUs = packageSensorBpfInertDecimalArray(
              value["observed_event_cpus"]
          ),
          observedEventCPUs == [fixtureCPU],
          value["online_cpus"] as? [String] == ["0", "1"],
          value["package_execution"] as? Bool == false,
          packageSensorBpfInertDecimal(value["package_gid"]) == 65534,
          packageSensorBpfInertDecimal(value["package_uid"]) == 65534,
          packageSensorBpfInertDecimal(value["pre_release_event_count"]) == 0,
          value["process_collector_coverage_complete"] as? Bool == true,
          let rootProcessEvidenceByteLength = packageSensorBpfInertDecimal(
              value["root_process_evidence_byte_length"]
          ),
          rootProcessEvidenceByteLength >= 1, rootProcessEvidenceByteLength <= 256 * 1024,
          value["root_process_evidence_canonical"] as? Bool == true,
          value["root_process_evidence_coverage_complete"] as? Bool == true,
          let rootProcessEvidenceObservationCount = packageSensorBpfInertDecimal(
              value["root_process_evidence_observation_count"]
          ),
          rootProcessEvidenceObservationCount == 10,
          value["root_process_evidence_raw_arguments_captured"] as? Bool == false,
          value["root_process_evidence_raw_exec_paths_captured"] as? Bool == false,
          value["root_process_evidence_schema"] as? String ==
              "whoathere.linux_vz_package_root_process_evidence.v1",
          let rootProcessEvidenceSHA256 = value["root_process_evidence_sha256"] as? String,
          packageSensorBpfInertDigest(rootProcessEvidenceSHA256),
          rootProcessEvidenceSHA256 != expectedFixtureSHA256,
          rootProcessEvidenceSHA256 != expectedRuntimeBTFSHA256,
          let rootProcessEvidenceSourceEventCount = packageSensorBpfInertDecimal(
              value["root_process_evidence_source_event_count"]
          ),
          rootProcessEvidenceSourceEventCount == 18,
          let rootNetworkEvidenceByteLength = packageSensorBpfInertDecimal(
              value["root_network_evidence_byte_length"]
          ),
          rootNetworkEvidenceByteLength >= 1,
          rootNetworkEvidenceByteLength <= 256 * 1024,
          value["root_network_evidence_canonical"] as? Bool == true,
          value["root_network_evidence_composite_coverage_complete"] as? Bool == false,
          value["root_network_evidence_connect_sendto_coverage_complete"] as? Bool == true,
          value["root_network_evidence_dns_coverage_complete"] as? Bool == false,
          let rootNetworkEvidenceEventCount = packageSensorBpfInertDecimal(
              value["root_network_evidence_event_count"]
          ),
          rootNetworkEvidenceEventCount == 2,
          value["root_network_evidence_guest_intent_coverage_complete"] as? Bool == false,
          value["root_network_evidence_host_frame_correlation_complete"] as? Bool == false,
          value["root_network_evidence_http_observation_complete"] as? Bool == false,
          value["root_network_evidence_process_sha256"] as? String == rootProcessEvidenceSHA256,
          value["root_network_evidence_raw_addresses_serialized"] as? Bool == false,
          value["root_network_evidence_schema"] as? String ==
              "whoathere.linux_vz_package_root_network_evidence.v1",
          let rootNetworkEvidenceSHA256 = value["root_network_evidence_sha256"] as? String,
          packageSensorBpfInertDigest(rootNetworkEvidenceSHA256),
          rootNetworkEvidenceSHA256 != rootProcessEvidenceSHA256,
          rootNetworkEvidenceSHA256 != expectedFixtureSHA256,
          rootNetworkEvidenceSHA256 != expectedRuntimeBTFSHA256,
          let rootNetworkEvidenceUnobservedCapabilities =
              value["root_network_evidence_unobserved_capabilities"] as? [String],
          rootNetworkEvidenceUnobservedCapabilities == [
              "dns_intent", "guest_intent_syscalls_beyond_connect_sendto",
              "host_frame_correlation", "http_observation",
          ],
          let rootFileEvidenceByteLength = packageSensorBpfInertDecimal(
              value["root_file_evidence_byte_length"]
          ),
          rootFileEvidenceByteLength >= 1, rootFileEvidenceByteLength <= 256 * 1024,
          value["root_file_evidence_canonical"] as? Bool == true,
          let rootFileEvidenceChangeCount = packageSensorBpfInertDecimal(
              value["root_file_evidence_change_count"]
          ),
          rootFileEvidenceChangeCount == 1,
          value["root_file_evidence_declared_scope_complete"] as? Bool == true,
          value["root_file_evidence_global_mount_coverage_complete"] as? Bool == false,
          value["root_file_evidence_raw_paths_captured"] as? Bool == false,
          value["root_file_evidence_schema"] as? String ==
              "whoathere.linux_vz_package_root_file_evidence.v1",
          let rootFileEvidenceSHA256 = value["root_file_evidence_sha256"] as? String,
          let rootFileEvidenceBaselineSnapshotSHA256 =
              value["root_file_evidence_baseline_snapshot_sha256"] as? String,
          let rootFileEvidenceFinalSnapshotSHA256 =
              value["root_file_evidence_final_snapshot_sha256"] as? String,
          let rootFileEvidenceWorkspaceDiffSHA256 =
              value["root_file_evidence_workspace_diff_sha256"] as? String,
          [rootFileEvidenceSHA256, rootFileEvidenceBaselineSnapshotSHA256,
           rootFileEvidenceFinalSnapshotSHA256, rootFileEvidenceWorkspaceDiffSHA256]
              .allSatisfy(packageSensorBpfInertDigest),
          Set([rootFileEvidenceSHA256, rootFileEvidenceBaselineSnapshotSHA256,
               rootFileEvidenceFinalSnapshotSHA256, rootFileEvidenceWorkspaceDiffSHA256,
               rootProcessEvidenceSHA256, rootNetworkEvidenceSHA256,
               expectedFixtureSHA256, expectedRuntimeBTFSHA256]).count == 8,
          let rootFileEvidenceSourceEventCount = packageSensorBpfInertDecimal(
              value["root_file_evidence_source_event_count"]
          ),
          rootFileEvidenceSourceEventCount == fileSourceEventCount,
          value["runtime_btf_sha256"] as? String == expectedRuntimeBTFSHA256,
          let sourceEventCountBeforeFinish = packageSensorBpfInertDecimal(
              value["source_event_count_before_finish"]
          ),
          sourceEventCountBeforeFinish >= 17, sourceEventCountBeforeFinish <= 18,
          sourceEventCountBeforeFinish + finishDrainEventCount == 18,
          value["sync_back"] as? Bool == false,
          let taskExitCodeByteOffset = packageSensorBpfInertDecimal(
              value["task_exit_code_byte_offset"]
          ),
          taskExitCodeByteOffset == expectedTaskExitCodeByteOffset,
          let tracepoints = value["tracepoint_format_sha256"] as? [String: String],
          Set(tracepoints.keys) == Set([
              "sched_process_exec", "sched_process_exit", "sched_process_fork",
              "sys_enter", "sys_exit",
          ]),
          tracepoints.values.allSatisfy(packageSensorBpfInertDigest),
          Set(tracepoints.values).count == tracepoints.count,
          let waitpidWaitStatus = packageSensorBpfInertDecimal(value["waitpid_wait_status"]),
          waitpidWaitStatus == kernelExitWaitStatus else {
        throw LinuxVzPackageSensorBpfInertEvidenceError.invalidSchema
    }
    return LinuxVzPackageSensorBpfInertEvidenceV12(
        canonicalJSON: payload,
        payloadSHA256: sha256(payload),
        evidenceByteLength: UInt64(payload.count),
        cgroupID: cgroupID,
        fixturePID: fixturePID,
        fixtureSHA256: expectedFixtureSHA256,
        runtimeBTFSHA256: expectedRuntimeBTFSHA256,
        taskExitCodeByteOffset: taskExitCodeByteOffset,
        kernelExitWaitStatus: kernelExitWaitStatus,
        waitpidWaitStatus: waitpidWaitStatus,
        attachmentCPU: attachmentCPU,
        fixtureCPU: fixtureCPU,
        observedEventCPUs: observedEventCPUs,
        collectorDrainMode: "continuous_worker",
        collectorMode: "root_bpf_ring_correlator",
        activeDrainPollCount: activeDrainPollCount,
        activeNonemptyDrainCount: activeNonemptyDrainCount,
        sourceEventCountBeforeFinish: sourceEventCountBeforeFinish,
        finishDrainEventCount: finishDrainEventCount,
        maximumDrainBatchRecordCount: maximumDrainBatchRecordCount,
        networkIntentCount: networkIntentCount,
        faultCgroupID: faultCgroupID,
        faultFixturePID: faultFixturePID,
        faultSignalLatencyMicroseconds: faultSignalLatencyMicroseconds,
        faultFixtureTerminationSignal: 9,
        fileActiveDrainPollCount: fileActiveDrainPollCount,
        fileActiveNonemptyDrainCount: fileActiveNonemptyDrainCount,
        fileSourceEventCount: fileSourceEventCount,
        fileDiffChangeCount: rootFileEvidenceChangeCount,
        filePermissionResponseCount: filePermissionResponseCount,
        fileIgnoredNonCgroupEventCount: fileIgnoredNonCgroupEventCount,
        fileFanotifyMarkScope: fileFanotifyMarkScope,
        fileFanotifyUnobservedMounts: fileFanotifyUnobservedMounts,
        fileGlobalMountCoverageComplete: false,
        leaderExecCount: 1,
        preReleaseEventCount: 0,
        processCollectorCoverageComplete: true,
        rootProcessEvidenceByteLength: rootProcessEvidenceByteLength,
        rootProcessEvidenceObservationCount: rootProcessEvidenceObservationCount,
        rootProcessEvidenceSHA256: rootProcessEvidenceSHA256,
        rootProcessEvidenceSourceEventCount: rootProcessEvidenceSourceEventCount,
        rootNetworkEvidenceByteLength: rootNetworkEvidenceByteLength,
        rootNetworkEvidenceEventCount: rootNetworkEvidenceEventCount,
        rootNetworkEvidenceSHA256: rootNetworkEvidenceSHA256,
        rootNetworkEvidenceUnobservedCapabilities: rootNetworkEvidenceUnobservedCapabilities,
        rootFileEvidenceByteLength: rootFileEvidenceByteLength,
        rootFileEvidenceChangeCount: rootFileEvidenceChangeCount,
        rootFileEvidenceSHA256: rootFileEvidenceSHA256,
        rootFileEvidenceSourceEventCount: rootFileEvidenceSourceEventCount,
        rootFileEvidenceBaselineSnapshotSHA256: rootFileEvidenceBaselineSnapshotSHA256,
        rootFileEvidenceFinalSnapshotSHA256: rootFileEvidenceFinalSnapshotSHA256,
        rootFileEvidenceWorkspaceDiffSHA256: rootFileEvidenceWorkspaceDiffSHA256,
        tracepointFormatSHA256: tracepoints
    )
}

public func linuxVzPackageSensorBpfInertMissingMarkersV1(_ serialData: Data) -> [String] {
    let lines = packageSensorBpfInertSerialLines(serialData)
    return linuxVzPackageSensorBpfInertRequiredMarkersV1.filter { !lines.contains($0) }
}

public func linuxVzPackageSensorBpfInertFailurePresentV1(_ serialData: Data) -> Bool {
    packageSensorBpfInertSerialLines(serialData).contains { line in
        line == "WHOATHERE_PACKAGE_SENSOR_BPF_INERT_FAILED"
            || line.hasPrefix("WHOATHERE_PACKAGE_SENSOR_BPF_INERT_FAILED ")
    }
}

private func packageSensorBpfInertSerialLines(_ serialData: Data) -> Set<String> {
    Set(serialData.split(separator: 0x0A).map { rawLine in
        var line = Array(rawLine)
        if line.last == 0x0D { line.removeLast() }
        return String(decoding: line, as: UTF8.self)
    })
}

private func packageSensorBpfInertDecimal(_ value: Any?) -> UInt64? {
    guard let value = value as? String, !value.isEmpty,
          value == "0" || !value.hasPrefix("0"),
          value.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) else {
        return nil
    }
    return UInt64(value)
}

private func packageSensorBpfInertDecimalArray(_ value: Any?) -> [UInt64]? {
    guard let values = value as? [String] else { return nil }
    let decoded = values.compactMap { packageSensorBpfInertDecimal($0) }
    return decoded.count == values.count ? decoded : nil
}

private func packageSensorBpfInertDigest(_ value: String) -> Bool {
    value.utf8.count == 71 && value.hasPrefix("sha256:")
        && value.dropFirst(7).utf8.allSatisfy { byte in
            (byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102)
        }
}
