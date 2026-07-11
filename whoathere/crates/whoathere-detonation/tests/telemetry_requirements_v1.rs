use whoathere_detonation::{
    decode_artifact_protected_telemetry_requirements_v1,
    ArtifactProtectedTelemetryRequirementsErrorV1, ArtifactProtectedTelemetryRequirementsV1,
    ArtifactTelemetryBackendClassV1, ArtifactTelemetryDropPolicyV1,
    ArtifactTelemetryNetworkTopologyV1, ArtifactTelemetrySyncBackPolicyV1,
    ARTIFACT_PROTECTED_TELEMETRY_REQUIREMENTS_SCHEMA_V1,
};

#[test]
fn linux_vz_bulk_requirements_are_closed_complete_and_digest_stable() {
    let requirements = ArtifactProtectedTelemetryRequirementsV1::linux_vz_bulk_v1();
    let bytes = requirements
        .canonical_json_v1()
        .expect("canonical telemetry requirements");
    let decoded = decode_artifact_protected_telemetry_requirements_v1(&bytes)
        .expect("decode telemetry requirements");
    assert_eq!(decoded, requirements);
    assert_eq!(
        decoded.backend_class(),
        ArtifactTelemetryBackendClassV1::LinuxVzBulk
    );
    assert_eq!(decoded.required_sensors().len(), 16);
    assert_eq!(
        decoded.network_topology(),
        ArtifactTelemetryNetworkTopologyV1::HostRawFrameSinkholeNoExternalRoute
    );
    assert_eq!(
        decoded.drop_policy(),
        ArtifactTelemetryDropPolicyV1::IncompleteOnAnyGap
    );
    assert_eq!(
        decoded.sync_back_policy(),
        ArtifactTelemetrySyncBackPolicyV1::StructurallyAbsent
    );
    assert_eq!(decoded.limitations().len(), 3);
    assert_eq!(
        decoded
            .requirements_sha256_v1()
            .expect("requirements digest"),
        requirements
            .requirements_sha256_v1()
            .expect("same requirements digest")
    );
    let text = String::from_utf8(bytes).expect("requirements UTF-8");
    assert!(text.contains(ARTIFACT_PROTECTED_TELEMETRY_REQUIREMENTS_SCHEMA_V1));
    assert!(text.contains("host_raw_frame_sinkhole_no_external_route"));
    assert!(text.contains("incomplete_on_any_gap"));
    assert!(text.contains("structurally_absent"));
}

#[test]
fn telemetry_requirements_reject_gaps_unknowns_cross_schema_and_noncanonical_wire() {
    let requirements = ArtifactProtectedTelemetryRequirementsV1::linux_vz_bulk_v1();
    let bytes = requirements
        .canonical_json_v1()
        .expect("canonical telemetry requirements");
    let mut value: serde_json::Value =
        serde_json::from_slice(&bytes).expect("telemetry requirements value");

    value["required_sensors"]
        .as_array_mut()
        .expect("required sensors")
        .pop();
    let missing = serde_json_canonicalizer::to_vec(&value).expect("missing sensor wire");
    assert_eq!(
        decode_artifact_protected_telemetry_requirements_v1(&missing),
        Err(ArtifactProtectedTelemetryRequirementsErrorV1::InvalidPolicy)
    );

    let mut unknown: serde_json::Value =
        serde_json::from_slice(&bytes).expect("unknown field value");
    unknown["observed_clean"] = serde_json::json!(true);
    let unknown = serde_json_canonicalizer::to_vec(&unknown).expect("unknown field wire");
    assert_eq!(
        decode_artifact_protected_telemetry_requirements_v1(&unknown),
        Err(ArtifactProtectedTelemetryRequirementsErrorV1::InvalidPolicy)
    );

    let mut cross_schema: serde_json::Value =
        serde_json::from_slice(&bytes).expect("cross schema value");
    cross_schema["schema_version"] = serde_json::json!("whoathere.macos_sdist_run_spec.v1");
    let cross_schema = serde_json_canonicalizer::to_vec(&cross_schema).expect("cross schema wire");
    assert_eq!(
        decode_artifact_protected_telemetry_requirements_v1(&cross_schema),
        Err(ArtifactProtectedTelemetryRequirementsErrorV1::InvalidSchema)
    );

    let mut noncanonical = bytes;
    noncanonical.push(b'\n');
    assert_eq!(
        decode_artifact_protected_telemetry_requirements_v1(&noncanonical),
        Err(ArtifactProtectedTelemetryRequirementsErrorV1::NonCanonical)
    );
}
