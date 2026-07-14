import Foundation
@testable import WhoaThereMacosVmHelperCore
import Testing

private let fixtureSHA256 =
    "sha256:c660520c04d3221694022f5546facf84a338982783d4d81ded75a7ae5165c0e6"
private let runtimeBTFSHA256 =
    "sha256:d7f143446e11cfd67fa53392616afdbca6511a6af432e6bd56fb053aa4e7becb"
private let taskExitCodeByteOffset: UInt64 = 1_964

@Test func packageSensorBpfInertEvidenceBindsExactLifecycleAndLossState() throws {
    let serial = packageSensorBpfInertSerial(value: packageSensorBpfInertValue())
    let evidence = try decodeLinuxVzPackageSensorBpfInertEvidenceV4(
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
    #expect(evidence.tracepointFormatSHA256.count == 5)
    #expect(evidence.payloadSHA256.hasPrefix("sha256:"))
    #expect(linuxVzPackageSensorBpfInertMissingMarkersV1(serial).isEmpty)
    #expect(!linuxVzPackageSensorBpfInertFailurePresentV1(serial))
}

@Test func packageSensorBpfInertEvidenceRejectsUnsafeRebindingAndDuplicatePayloads() throws {
    var value = packageSensorBpfInertValue()
    value["dropped_event_count"] = "1"
    #expect(throws: LinuxVzPackageSensorBpfInertEvidenceError.invalidSchema) {
        try decodeLinuxVzPackageSensorBpfInertEvidenceV4(
            packageSensorBpfInertSerial(value: value),
            expectedFixtureSHA256: fixtureSHA256,
            expectedRuntimeBTFSHA256: runtimeBTFSHA256,
            expectedTaskExitCodeByteOffset: taskExitCodeByteOffset
        )
    }

    value = packageSensorBpfInertValue()
    value["package_execution"] = true
    #expect(throws: LinuxVzPackageSensorBpfInertEvidenceError.invalidSchema) {
        try decodeLinuxVzPackageSensorBpfInertEvidenceV4(
            packageSensorBpfInertSerial(value: value),
            expectedFixtureSHA256: fixtureSHA256,
            expectedRuntimeBTFSHA256: runtimeBTFSHA256,
            expectedTaskExitCodeByteOffset: taskExitCodeByteOffset
        )
    }

    value = packageSensorBpfInertValue()
    value["attachment_cpu"] = "1"
    #expect(throws: LinuxVzPackageSensorBpfInertEvidenceError.invalidSchema) {
        try decodeLinuxVzPackageSensorBpfInertEvidenceV4(
            packageSensorBpfInertSerial(value: value),
            expectedFixtureSHA256: fixtureSHA256,
            expectedRuntimeBTFSHA256: runtimeBTFSHA256,
            expectedTaskExitCodeByteOffset: taskExitCodeByteOffset
        )
    }

    value = packageSensorBpfInertValue()
    value["observed_event_cpus"] = ["0"]
    #expect(throws: LinuxVzPackageSensorBpfInertEvidenceError.invalidSchema) {
        try decodeLinuxVzPackageSensorBpfInertEvidenceV4(
            packageSensorBpfInertSerial(value: value),
            expectedFixtureSHA256: fixtureSHA256,
            expectedRuntimeBTFSHA256: runtimeBTFSHA256,
            expectedTaskExitCodeByteOffset: taskExitCodeByteOffset
        )
    }

    value = packageSensorBpfInertValue()
    value["kernel_exit_wait_status"] = "9"
    #expect(throws: LinuxVzPackageSensorBpfInertEvidenceError.invalidSchema) {
        try decodeLinuxVzPackageSensorBpfInertEvidenceV4(
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
        try decodeLinuxVzPackageSensorBpfInertEvidenceV4(
            packageSensorBpfInertSerial(value: value),
            expectedFixtureSHA256: fixtureSHA256,
            expectedRuntimeBTFSHA256: runtimeBTFSHA256,
            expectedTaskExitCodeByteOffset: taskExitCodeByteOffset
        )
    }

    value = packageSensorBpfInertValue()
    value["task_exit_code_byte_offset"] = "1965"
    #expect(throws: LinuxVzPackageSensorBpfInertEvidenceError.invalidSchema) {
        try decodeLinuxVzPackageSensorBpfInertEvidenceV4(
            packageSensorBpfInertSerial(value: value),
            expectedFixtureSHA256: fixtureSHA256,
            expectedRuntimeBTFSHA256: runtimeBTFSHA256,
            expectedTaskExitCodeByteOffset: taskExitCodeByteOffset
        )
    }

    let line = Data(linuxVzPackageSensorBpfInertEvidenceSerialPrefixV1.utf8)
        + (try canonicalJSONData(packageSensorBpfInertValue())) + Data("\n".utf8)
    #expect(throws: LinuxVzPackageSensorBpfInertEvidenceError.duplicate) {
        try decodeLinuxVzPackageSensorBpfInertEvidenceV4(
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
            + "{\"schema_version\":\"whoathere.linux_vz_package_sensor_bpf_inert_probe.v4\",\"attachment_cpu\":\"0\"}\n").utf8
    )
    #expect(throws: LinuxVzPackageSensorBpfInertEvidenceError.nonCanonical) {
        try decodeLinuxVzPackageSensorBpfInertEvidenceV4(
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
        "attachment_cpu": "0",
        "attachment_scope": "tracepoint_wide",
        "cgroup_id": "21",
        "discarded_record_count": "0",
        "dropped_event_count": "0",
        "event_count": "14",
        "event_kinds": [
            "setgroups_enter", "setgroups_exit", "setgid_enter", "setgid_exit",
            "setuid_enter", "setuid_exit", "exec",
            "mmap_enter", "mmap_exit", "mmap_enter", "mmap_exit",
            "mmap_enter", "mmap_exit", "exit",
        ],
        "event_sequence_end": "14",
        "event_sequence_start": "1",
        "exit_attachment": "raw_tracepoint:sched_process_exit",
        "exit_status_source": "runtime_btf:task_struct.exit_code",
        "fixture_cpu": "1",
        "fixture_exit_status": "0",
        "fixture_pid": "387",
        "fixture_sha256": fixtureSHA256,
        "kernel_exit_wait_status": "0",
        "malware_execution": false,
        "observed_event_cpus": ["1"],
        "online_cpus": ["0", "1"],
        "package_execution": false,
        "package_gid": "65534",
        "package_uid": "65534",
        "runtime_btf_sha256": runtimeBTFSHA256,
        "schema_version": linuxVzPackageSensorBpfInertEvidenceSchemaV4,
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
