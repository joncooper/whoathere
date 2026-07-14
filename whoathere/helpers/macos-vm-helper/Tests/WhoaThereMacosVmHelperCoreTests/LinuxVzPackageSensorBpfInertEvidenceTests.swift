import Foundation
@testable import WhoaThereMacosVmHelperCore
import Testing

private let fixtureSHA256 =
    "sha256:09933b6efc035a0d6c43ca3cf63e76e5d49ada432c7418e7e929b60c9d613b7e"
private let runtimeBTFSHA256 =
    "sha256:d7f143446e11cfd67fa53392616afdbca6511a6af432e6bd56fb053aa4e7becb"
private let taskExitCodeByteOffset: UInt64 = 1_964

@Test func packageSensorBpfInertEvidenceBindsExactLifecycleAndLossState() throws {
    let serial = packageSensorBpfInertSerial(value: packageSensorBpfInertValue())
    let evidence = try decodeLinuxVzPackageSensorBpfInertEvidenceV11(
        serial,
        expectedFixtureSHA256: fixtureSHA256,
        expectedRuntimeBTFSHA256: runtimeBTFSHA256,
        expectedTaskExitCodeByteOffset: taskExitCodeByteOffset
    )
    #expect(evidence.cgroupID == 21)
    #expect(evidence.fixturePID == 387)
    #expect(evidence.fixtureSHA256 == fixtureSHA256)
    #expect(evidence.runtimeBTFSHA256 == runtimeBTFSHA256)
    #expect(evidence.taskExitCodeByteOffset == taskExitCodeByteOffset)
    #expect(evidence.kernelExitWaitStatus == 0)
    #expect(evidence.waitpidWaitStatus == 0)
    #expect(evidence.attachmentCPU == 0)
    #expect(evidence.fixtureCPU == 1)
    #expect(evidence.observedEventCPUs == [1])
    #expect(evidence.collectorDrainMode == "continuous_worker")
    #expect(evidence.collectorMode == "root_bpf_ring_correlator")
    #expect(evidence.activeDrainPollCount == 38)
    #expect(evidence.activeNonemptyDrainCount == 1)
    #expect(evidence.sourceEventCountBeforeFinish == 17)
    #expect(evidence.finishDrainEventCount == 1)
    #expect(evidence.maximumDrainBatchRecordCount == 13)
    #expect(evidence.networkIntentCount == 2)
    #expect(evidence.faultCgroupID == 22)
    #expect(evidence.faultFixturePID == 388)
    #expect(evidence.faultSignalLatencyMicroseconds == 1_250)
    #expect(evidence.faultFixtureTerminationSignal == 9)
    #expect(evidence.fileActiveDrainPollCount == 38)
    #expect(evidence.fileActiveNonemptyDrainCount == 2)
    #expect(evidence.fileSourceEventCount == 7)
    #expect(evidence.fileDiffChangeCount == 1)
    #expect(evidence.filePermissionResponseCount == 6)
    #expect(evidence.fileIgnoredNonCgroupEventCount == 20)
    #expect(evidence.fileFanotifyMarkScope == [
        "dev_mount", "root_mount", "run_mount", "sys_mount", "workspace_mount",
    ])
    #expect(evidence.fileFanotifyUnobservedMounts == ["proc_mount"])
    #expect(!evidence.fileGlobalMountCoverageComplete)
    #expect(evidence.leaderExecCount == 1)
    #expect(evidence.preReleaseEventCount == 0)
    #expect(evidence.processCollectorCoverageComplete)
    #expect(evidence.rootProcessEvidenceByteLength == 4_096)
    #expect(evidence.rootProcessEvidenceObservationCount == 10)
    #expect(evidence.rootProcessEvidenceSHA256.hasPrefix("sha256:"))
    #expect(evidence.rootProcessEvidenceSourceEventCount == 18)
    #expect(evidence.rootFileEvidenceByteLength == 3_072)
    #expect(evidence.rootFileEvidenceChangeCount == 1)
    #expect(evidence.rootFileEvidenceSourceEventCount == 7)
    #expect(evidence.rootFileEvidenceSHA256.hasPrefix("sha256:"))
    #expect(evidence.tracepointFormatSHA256.count == 5)
    #expect(evidence.payloadSHA256.hasPrefix("sha256:"))
    #expect(linuxVzPackageSensorBpfInertMissingMarkersV1(serial).isEmpty)
    #expect(!linuxVzPackageSensorBpfInertFailurePresentV1(serial))
}

@Test func packageSensorBpfInertEvidenceRejectsUnsafeRebindingAndDuplicatePayloads() throws {
    var value = packageSensorBpfInertValue()
    value["dropped_event_count"] = "1"
    #expect(throws: LinuxVzPackageSensorBpfInertEvidenceError.invalidSchema) {
        try decodeLinuxVzPackageSensorBpfInertEvidenceV11(
            packageSensorBpfInertSerial(value: value),
            expectedFixtureSHA256: fixtureSHA256,
            expectedRuntimeBTFSHA256: runtimeBTFSHA256,
            expectedTaskExitCodeByteOffset: taskExitCodeByteOffset
        )
    }

    value = packageSensorBpfInertValue()
    value["package_execution"] = true
    #expect(throws: LinuxVzPackageSensorBpfInertEvidenceError.invalidSchema) {
        try decodeLinuxVzPackageSensorBpfInertEvidenceV11(
            packageSensorBpfInertSerial(value: value),
            expectedFixtureSHA256: fixtureSHA256,
            expectedRuntimeBTFSHA256: runtimeBTFSHA256,
            expectedTaskExitCodeByteOffset: taskExitCodeByteOffset
        )
    }

    value = packageSensorBpfInertValue()
    value["collector_mode"] = "standalone_probe"
    #expect(throws: LinuxVzPackageSensorBpfInertEvidenceError.invalidSchema) {
        try decodeLinuxVzPackageSensorBpfInertEvidenceV11(
            packageSensorBpfInertSerial(value: value),
            expectedFixtureSHA256: fixtureSHA256,
            expectedRuntimeBTFSHA256: runtimeBTFSHA256,
            expectedTaskExitCodeByteOffset: taskExitCodeByteOffset
        )
    }

    value = packageSensorBpfInertValue()
    value["collector_drain_mode"] = "finish_only"
    #expect(throws: LinuxVzPackageSensorBpfInertEvidenceError.invalidSchema) {
        try decodeLinuxVzPackageSensorBpfInertEvidenceV11(
            packageSensorBpfInertSerial(value: value),
            expectedFixtureSHA256: fixtureSHA256,
            expectedRuntimeBTFSHA256: runtimeBTFSHA256,
            expectedTaskExitCodeByteOffset: taskExitCodeByteOffset
        )
    }

    value = packageSensorBpfInertValue()
    value["active_nonempty_drain_count"] = "0"
    #expect(throws: LinuxVzPackageSensorBpfInertEvidenceError.invalidSchema) {
        try decodeLinuxVzPackageSensorBpfInertEvidenceV11(
            packageSensorBpfInertSerial(value: value),
            expectedFixtureSHA256: fixtureSHA256,
            expectedRuntimeBTFSHA256: runtimeBTFSHA256,
            expectedTaskExitCodeByteOffset: taskExitCodeByteOffset
        )
    }

    value = packageSensorBpfInertValue()
    value["source_event_count_before_finish"] = "12"
    value["finish_drain_event_count"] = "2"
    #expect(throws: LinuxVzPackageSensorBpfInertEvidenceError.invalidSchema) {
        try decodeLinuxVzPackageSensorBpfInertEvidenceV11(
            packageSensorBpfInertSerial(value: value),
            expectedFixtureSHA256: fixtureSHA256,
            expectedRuntimeBTFSHA256: runtimeBTFSHA256,
            expectedTaskExitCodeByteOffset: taskExitCodeByteOffset
        )
    }

    value = packageSensorBpfInertValue()
    value["fault_signal_observed"] = false
    #expect(throws: LinuxVzPackageSensorBpfInertEvidenceError.invalidSchema) {
        try decodeLinuxVzPackageSensorBpfInertEvidenceV11(
            packageSensorBpfInertSerial(value: value),
            expectedFixtureSHA256: fixtureSHA256,
            expectedRuntimeBTFSHA256: runtimeBTFSHA256,
            expectedTaskExitCodeByteOffset: taskExitCodeByteOffset
        )
    }

    value = packageSensorBpfInertValue()
    value["fault_signal_latency_microseconds"] = "2000001"
    #expect(throws: LinuxVzPackageSensorBpfInertEvidenceError.invalidSchema) {
        try decodeLinuxVzPackageSensorBpfInertEvidenceV11(
            packageSensorBpfInertSerial(value: value),
            expectedFixtureSHA256: fixtureSHA256,
            expectedRuntimeBTFSHA256: runtimeBTFSHA256,
            expectedTaskExitCodeByteOffset: taskExitCodeByteOffset
        )
    }

    value = packageSensorBpfInertValue()
    value["process_collector_coverage_complete"] = false
    #expect(throws: LinuxVzPackageSensorBpfInertEvidenceError.invalidSchema) {
        try decodeLinuxVzPackageSensorBpfInertEvidenceV11(
            packageSensorBpfInertSerial(value: value),
            expectedFixtureSHA256: fixtureSHA256,
            expectedRuntimeBTFSHA256: runtimeBTFSHA256,
            expectedTaskExitCodeByteOffset: taskExitCodeByteOffset
        )
    }

    value = packageSensorBpfInertValue()
    value["file_fanotify_overflow_count"] = "1"
    #expect(throws: LinuxVzPackageSensorBpfInertEvidenceError.invalidSchema) {
        try decodeLinuxVzPackageSensorBpfInertEvidenceV11(
            packageSensorBpfInertSerial(value: value),
            expectedFixtureSHA256: fixtureSHA256,
            expectedRuntimeBTFSHA256: runtimeBTFSHA256,
            expectedTaskExitCodeByteOffset: taskExitCodeByteOffset
        )
    }

    value = packageSensorBpfInertValue()
    value["file_fanotify_unobserved_mounts"] = []
    #expect(throws: LinuxVzPackageSensorBpfInertEvidenceError.invalidSchema) {
        try decodeLinuxVzPackageSensorBpfInertEvidenceV11(
            packageSensorBpfInertSerial(value: value),
            expectedFixtureSHA256: fixtureSHA256,
            expectedRuntimeBTFSHA256: runtimeBTFSHA256,
            expectedTaskExitCodeByteOffset: taskExitCodeByteOffset
        )
    }

    value = packageSensorBpfInertValue()
    value["root_file_evidence_raw_paths_captured"] = true
    #expect(throws: LinuxVzPackageSensorBpfInertEvidenceError.invalidSchema) {
        try decodeLinuxVzPackageSensorBpfInertEvidenceV11(
            packageSensorBpfInertSerial(value: value),
            expectedFixtureSHA256: fixtureSHA256,
            expectedRuntimeBTFSHA256: runtimeBTFSHA256,
            expectedTaskExitCodeByteOffset: taskExitCodeByteOffset
        )
    }

    value = packageSensorBpfInertValue()
    value["root_process_evidence_coverage_complete"] = false
    #expect(throws: LinuxVzPackageSensorBpfInertEvidenceError.invalidSchema) {
        try decodeLinuxVzPackageSensorBpfInertEvidenceV11(
            packageSensorBpfInertSerial(value: value),
            expectedFixtureSHA256: fixtureSHA256,
            expectedRuntimeBTFSHA256: runtimeBTFSHA256,
            expectedTaskExitCodeByteOffset: taskExitCodeByteOffset
        )
    }

    value = packageSensorBpfInertValue()
    value["root_process_evidence_raw_arguments_captured"] = true
    #expect(throws: LinuxVzPackageSensorBpfInertEvidenceError.invalidSchema) {
        try decodeLinuxVzPackageSensorBpfInertEvidenceV11(
            packageSensorBpfInertSerial(value: value),
            expectedFixtureSHA256: fixtureSHA256,
            expectedRuntimeBTFSHA256: runtimeBTFSHA256,
            expectedTaskExitCodeByteOffset: taskExitCodeByteOffset
        )
    }

    value = packageSensorBpfInertValue()
    value["root_process_evidence_observation_count"] = "7"
    #expect(throws: LinuxVzPackageSensorBpfInertEvidenceError.invalidSchema) {
        try decodeLinuxVzPackageSensorBpfInertEvidenceV11(
            packageSensorBpfInertSerial(value: value),
            expectedFixtureSHA256: fixtureSHA256,
            expectedRuntimeBTFSHA256: runtimeBTFSHA256,
            expectedTaskExitCodeByteOffset: taskExitCodeByteOffset
        )
    }

    value = packageSensorBpfInertValue()
    value["attachment_cpu"] = "1"
    #expect(throws: LinuxVzPackageSensorBpfInertEvidenceError.invalidSchema) {
        try decodeLinuxVzPackageSensorBpfInertEvidenceV11(
            packageSensorBpfInertSerial(value: value),
            expectedFixtureSHA256: fixtureSHA256,
            expectedRuntimeBTFSHA256: runtimeBTFSHA256,
            expectedTaskExitCodeByteOffset: taskExitCodeByteOffset
        )
    }

    value = packageSensorBpfInertValue()
    value["observed_event_cpus"] = ["0"]
    #expect(throws: LinuxVzPackageSensorBpfInertEvidenceError.invalidSchema) {
        try decodeLinuxVzPackageSensorBpfInertEvidenceV11(
            packageSensorBpfInertSerial(value: value),
            expectedFixtureSHA256: fixtureSHA256,
            expectedRuntimeBTFSHA256: runtimeBTFSHA256,
            expectedTaskExitCodeByteOffset: taskExitCodeByteOffset
        )
    }

    value = packageSensorBpfInertValue()
    value["kernel_exit_wait_status"] = "9"
    #expect(throws: LinuxVzPackageSensorBpfInertEvidenceError.invalidSchema) {
        try decodeLinuxVzPackageSensorBpfInertEvidenceV11(
            packageSensorBpfInertSerial(value: value),
            expectedFixtureSHA256: fixtureSHA256,
            expectedRuntimeBTFSHA256: runtimeBTFSHA256,
            expectedTaskExitCodeByteOffset: taskExitCodeByteOffset
        )
    }

    value = packageSensorBpfInertValue()
    value["runtime_btf_sha256"] =
        "sha256:3333333333333333333333333333333333333333333333333333333333333333"
    #expect(throws: LinuxVzPackageSensorBpfInertEvidenceError.invalidSchema) {
        try decodeLinuxVzPackageSensorBpfInertEvidenceV11(
            packageSensorBpfInertSerial(value: value),
            expectedFixtureSHA256: fixtureSHA256,
            expectedRuntimeBTFSHA256: runtimeBTFSHA256,
            expectedTaskExitCodeByteOffset: taskExitCodeByteOffset
        )
    }

    value = packageSensorBpfInertValue()
    value["task_exit_code_byte_offset"] = "1965"
    #expect(throws: LinuxVzPackageSensorBpfInertEvidenceError.invalidSchema) {
        try decodeLinuxVzPackageSensorBpfInertEvidenceV11(
            packageSensorBpfInertSerial(value: value),
            expectedFixtureSHA256: fixtureSHA256,
            expectedRuntimeBTFSHA256: runtimeBTFSHA256,
            expectedTaskExitCodeByteOffset: taskExitCodeByteOffset
        )
    }

    let line = Data(linuxVzPackageSensorBpfInertEvidenceSerialPrefixV1.utf8)
        + (try canonicalJSONData(packageSensorBpfInertValue())) + Data("\n".utf8)
    #expect(throws: LinuxVzPackageSensorBpfInertEvidenceError.duplicate) {
        try decodeLinuxVzPackageSensorBpfInertEvidenceV11(
            line + line,
            expectedFixtureSHA256: fixtureSHA256,
            expectedRuntimeBTFSHA256: runtimeBTFSHA256,
            expectedTaskExitCodeByteOffset: taskExitCodeByteOffset
        )
    }
}

@Test func packageSensorBpfInertEvidenceRejectsNoncanonicalAndFailureTranscripts() throws {
    let noncanonical = Data(
        (linuxVzPackageSensorBpfInertEvidenceSerialPrefixV1
            + "{\"schema_version\":\"whoathere.linux_vz_package_sensor_bpf_inert_probe.v11\",\"attachment_cpu\":\"0\"}\n").utf8
    )
    #expect(throws: LinuxVzPackageSensorBpfInertEvidenceError.nonCanonical) {
        try decodeLinuxVzPackageSensorBpfInertEvidenceV11(
            noncanonical,
            expectedFixtureSHA256: fixtureSHA256,
            expectedRuntimeBTFSHA256: runtimeBTFSHA256,
            expectedTaskExitCodeByteOffset: taskExitCodeByteOffset
        )
    }

    let failed = packageSensorBpfInertSerial(value: packageSensorBpfInertValue())
        + Data("WHOATHERE_PACKAGE_SENSOR_BPF_INERT_FAILED reason\n".utf8)
    #expect(linuxVzPackageSensorBpfInertFailurePresentV1(failed))
    #expect(
        linuxVzPackageSensorBpfInertMissingMarkersV1(
            Data("WHOATHERE_PACKAGE_SENSOR_BPF_INERT_BEGIN\n".utf8)
        ).count == linuxVzPackageSensorBpfInertRequiredMarkersV1.count - 1
    )
}

private func packageSensorBpfInertSerial(value: [String: Any]) -> Data {
    let lines = linuxVzPackageSensorBpfInertRequiredMarkersV1
        + [linuxVzPackageSensorBpfInertEvidenceSerialPrefixV1
            + String(decoding: try! canonicalJSONData(value), as: UTF8.self)]
    return Data((lines.joined(separator: "\r\n") + "\r\n").utf8)
}

private func packageSensorBpfInertValue() -> [String: Any] {
    [
        "active_drain_poll_count": "38",
        "active_nonempty_drain_count": "1",
        "attachment_cpu": "0",
        "attachment_scope": "tracepoint_wide",
        "cgroup_id": "21",
        "collector_drain_mode": "continuous_worker",
        "collector_mode": "root_bpf_ring_correlator",
        "discarded_record_count": "0",
        "dropped_event_count": "0",
        "event_count": "18",
        "event_kinds": [
            "setgroups_enter", "setgroups_exit", "setgid_enter", "setgid_exit",
            "setuid_enter", "setuid_exit", "exec",
            "mmap_enter", "mmap_exit", "mmap_enter", "mmap_exit",
            "mmap_enter", "mmap_exit", "connect_enter", "connect_exit",
            "sendto_enter", "sendto_exit", "exit",
        ],
        "event_sequence_end": "18",
        "event_sequence_start": "1",
        "exit_attachment": "raw_tracepoint:sched_process_exit",
        "exit_status_source": "runtime_btf:task_struct.exit_code",
        "fault_cgroup_id": "22",
        "fault_cgroup_kill_used": true,
        "fault_fixture_pid": "388",
        "fault_fixture_termination_signal": "9",
        "fault_maximum_source_events": "8",
        "fault_signal_kind": "nonblocking_pipe_marker",
        "fault_signal_latency_microseconds": "1250",
        "fault_signal_observed": true,
        "fault_trigger": "source_event_limit",
        "file_active_drain_poll_count": "38",
        "file_active_nonempty_drain_count": "2",
        "file_collector_declared_scope_complete": true,
        "file_collector_global_mount_coverage_complete": false,
        "file_diff_change_count": "1",
        "file_diff_completed_after_process_exit": true,
        "file_fanotify_overflow_count": "0",
        "file_fanotify_mark_scope": [
            "dev_mount", "root_mount", "run_mount", "sys_mount", "workspace_mount",
        ],
        "file_fanotify_unobserved_mounts": ["proc_mount"],
        "file_ignored_non_cgroup_event_count": "20",
        "file_maximum_drain_batch_event_count": "8",
        "file_permission_denied_count": "0",
        "file_permission_response_count": "6",
        "file_required_fanotify_mark_count": "5",
        "file_source_event_count": "7",
        "finish_drain_event_count": "1",
        "fixture_cpu": "1",
        "fixture_exit_status": "0",
        "fixture_pid": "387",
        "fixture_sha256": fixtureSHA256,
        "kernel_exit_wait_status": "0",
        "leader_exec_count": "1",
        "malware_execution": false,
        "maximum_drain_batch_record_count": "13",
        "network_connect_destination_class": "documentation",
        "network_connect_family": "ipv4",
        "network_connect_port": "443",
        "network_connect_result": "-101",
        "network_intent_count": "2",
        "network_raw_addresses_captured": false,
        "network_sendto_destination_class": "documentation",
        "network_sendto_family": "ipv6",
        "network_sendto_port": "53",
        "network_sendto_result": "-101",
        "observed_event_cpus": ["1"],
        "online_cpus": ["0", "1"],
        "package_execution": false,
        "package_gid": "65534",
        "package_uid": "65534",
        "pre_release_event_count": "0",
        "process_collector_coverage_complete": true,
        "root_process_evidence_byte_length": "4096",
        "root_process_evidence_canonical": true,
        "root_process_evidence_coverage_complete": true,
        "root_process_evidence_observation_count": "10",
        "root_process_evidence_raw_arguments_captured": false,
        "root_process_evidence_raw_exec_paths_captured": false,
        "root_process_evidence_schema":
            "whoathere.linux_vz_package_root_process_evidence.v1",
        "root_process_evidence_sha256":
            "sha256:4444444444444444444444444444444444444444444444444444444444444444",
        "root_process_evidence_source_event_count": "18",
        "root_file_evidence_baseline_snapshot_sha256":
            "sha256:6666666666666666666666666666666666666666666666666666666666666666",
        "root_file_evidence_byte_length": "3072",
        "root_file_evidence_canonical": true,
        "root_file_evidence_change_count": "1",
        "root_file_evidence_declared_scope_complete": true,
        "root_file_evidence_global_mount_coverage_complete": false,
        "root_file_evidence_final_snapshot_sha256":
            "sha256:7777777777777777777777777777777777777777777777777777777777777777",
        "root_file_evidence_raw_paths_captured": false,
        "root_file_evidence_schema":
            "whoathere.linux_vz_package_root_file_evidence.v1",
        "root_file_evidence_sha256":
            "sha256:5555555555555555555555555555555555555555555555555555555555555555",
        "root_file_evidence_source_event_count": "7",
        "root_file_evidence_workspace_diff_sha256":
            "sha256:8888888888888888888888888888888888888888888888888888888888888888",
        "runtime_btf_sha256": runtimeBTFSHA256,
        "schema_version": linuxVzPackageSensorBpfInertEvidenceSchemaV11,
        "source_event_count_before_finish": "17",
        "sync_back": false,
        "task_exit_code_byte_offset": String(taskExitCodeByteOffset),
        "tracepoint_format_sha256": [
            "sched_process_exec":
                "sha256:f8af16db8c47534beaff9b2f477b6d309df3512f9386e0bdc079b7a5618043ba",
            "sched_process_exit":
                "sha256:b04a7c7b2e0c473705fe812851c161126b0a68f3eab604e92da952a241eb5870",
            "sched_process_fork":
                "sha256:84863bfaed832693cea3a4be6992a28a4d578c9bfc5cbef787a251c81a12e52f",
            "sys_enter":
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "sys_exit":
                "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        ],
        "waitpid_wait_status": "0",
    ]
}
