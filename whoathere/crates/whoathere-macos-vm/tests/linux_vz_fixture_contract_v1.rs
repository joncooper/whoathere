use std::collections::BTreeSet;
use whoathere_macos_vm::{
    expected_terminal_for_case_v1, fixture_for_case_v1, LinuxVzTelemetryConformanceCaseV1,
    ALL_LINUX_VZ_TELEMETRY_CONFORMANCE_CASES_V1,
};

const FIXTURE_CASES: &str =
    include_str!("../../../helpers/linux-vz-conformance/guest/fixture_cases.def");
const INSPECTOR_SOURCE: &str =
    include_str!("../../../helpers/linux-vz-conformance/tools/fixture_contract_inspector.c");

#[derive(Debug)]
struct FixtureContract<'a> {
    fixture_case: &'a str,
    family: &'a str,
    expected_terminal: &'a str,
    trigger_owner: &'a str,
    action: &'a str,
    network_policy: &'a str,
}

fn parse_contracts() -> Vec<FixtureContract<'static>> {
    FIXTURE_CASES
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let inner = line
                .strip_prefix("WHOATHERE_FIXTURE_CASE(")
                .and_then(|value| value.strip_suffix(')'))
                .expect("closed fixture macro");
            let quoted = inner
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
                .expect("quoted fixture fields");
            let fields = quoted.split("\", \"").collect::<Vec<_>>();
            assert_eq!(fields.len(), 6, "exact fixture field count");
            FixtureContract {
                fixture_case: fields[0],
                family: fields[1],
                expected_terminal: fields[2],
                trigger_owner: fields[3],
                action: fields[4],
                network_policy: fields[5],
            }
        })
        .collect()
}

fn wire_name<T: serde::Serialize>(value: T) -> String {
    serde_json::to_value(value)
        .expect("serialize conformance enum")
        .as_str()
        .expect("string conformance enum")
        .to_owned()
}

fn expected_trigger_owner(case: LinuxVzTelemetryConformanceCaseV1) -> &'static str {
    use LinuxVzTelemetryConformanceCaseV1 as Case;
    match case {
        Case::RawFrameAttachment => "guest_and_host",
        Case::BpfReservationFailure | Case::FanotifyQueueOverflow | Case::GuestSensorDeath => {
            "guest_sensor_fault_injector"
        }
        Case::HostFrameOverflow
        | Case::ChannelInterruption
        | Case::VmStop
        | Case::HostSensorDeath => "host_harness",
        _ => "guest_fixture",
    }
}

fn expected_network_policy(case: LinuxVzTelemetryConformanceCaseV1) -> &'static str {
    use LinuxVzTelemetryConformanceCaseV1 as Case;
    match case {
        Case::HostFrameOverflow => "host_sinkhole_overflow",
        Case::RawFrameAttachment
        | Case::Ipv4Connect
        | Case::Ipv6Connect
        | Case::UdpSend
        | Case::LoopbackConnect
        | Case::PrivateAddressConnect
        | Case::LinkLocalConnect
        | Case::MetadataAddressConnect
        | Case::PublicAddressConnect
        | Case::DnsPlaintext
        | Case::DnsMalformed
        | Case::EncryptedDnsConnect => "guest_sinkhole_only",
        _ => "none",
    }
}

#[test]
fn fixture_contract_matches_every_canonical_case_family_terminal_and_owner() {
    let contracts = parse_contracts();
    assert_eq!(contracts.len(), 38);
    assert_eq!(
        contracts.len(),
        ALL_LINUX_VZ_TELEMETRY_CONFORMANCE_CASES_V1.len()
    );

    let mut cases = BTreeSet::new();
    let mut actions = BTreeSet::new();
    for (contract, fixture_case) in contracts
        .iter()
        .zip(ALL_LINUX_VZ_TELEMETRY_CONFORMANCE_CASES_V1)
    {
        assert_eq!(contract.fixture_case, wire_name(fixture_case));
        assert_eq!(
            contract.family,
            wire_name(fixture_for_case_v1(fixture_case))
        );
        assert_eq!(
            contract.expected_terminal,
            wire_name(expected_terminal_for_case_v1(fixture_case))
        );
        assert_eq!(contract.trigger_owner, expected_trigger_owner(fixture_case));
        assert_eq!(
            contract.network_policy,
            expected_network_policy(fixture_case)
        );
        assert!(
            cases.insert(contract.fixture_case),
            "duplicate fixture case"
        );
        assert!(actions.insert(contract.action), "duplicate fixture action");
        assert!(contract
            .action
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'));
    }
}

#[test]
fn fixture_inspector_is_description_only_and_has_no_execution_input_surface() {
    assert!(INSPECTOR_SOURCE.contains("--list"));
    assert!(INSPECTOR_SOURCE.contains("--describe"));
    for forbidden in [
        "--execute",
        "--command",
        "--path",
        "--environment",
        "getenv(",
        "system(",
        "execv",
        "socket(",
    ] {
        assert!(
            !INSPECTOR_SOURCE.contains(forbidden),
            "unexpected inspector input or execution surface: {forbidden}"
        );
    }
}
