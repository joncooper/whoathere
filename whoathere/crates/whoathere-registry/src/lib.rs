use whoathere_admission::ServableGeneration;
use whoathere_vault_api::ArtifactRef;

pub fn render_npm_packument(generation: &ServableGeneration, tarball_base: &str) -> String {
    let artifact = &generation.artifact;
    let tarball_url = format!(
        "{}/{}/{}",
        tarball_base.trim_end_matches('/'),
        percent_encode_component(&artifact.name),
        percent_encode_component(&artifact.version)
    );
    format!(
        "{{\"name\":\"{}\",\"versions\":{{\"{}\":{{\"dist\":{{\"tarball\":\"{}\",\"integrity\":\"{}\"}}}}}},\"dist-tags\":{{\"latest\":\"{}\"}}}}",
        escape_json(&artifact.name),
        escape_json(&artifact.version),
        escape_json(&tarball_url),
        escape_json(&artifact.digest),
        escape_json(&artifact.version)
    )
}

pub fn render_pypi_simple(generations: &[ServableGeneration]) -> String {
    render_pypi_simple_with_file_base(generations, "")
}

pub fn render_pypi_simple_with_file_base(
    generations: &[ServableGeneration],
    file_base: &str,
) -> String {
    let links = generations
        .iter()
        .map(|generation| {
            let artifact = &generation.artifact;
            let href = if file_base.is_empty() {
                format!(
                    "/{}/{}/{}#{}",
                    percent_encode_component(&artifact.ecosystem),
                    percent_encode_component(&artifact.name),
                    percent_encode_component(&artifact.version),
                    percent_encode_component(&artifact.digest)
                )
            } else {
                format!(
                    "{}/{}/{}/{}#{}",
                    file_base.trim_end_matches('/'),
                    percent_encode_component(&artifact.ecosystem),
                    percent_encode_component(&artifact.name),
                    percent_encode_component(&artifact.version),
                    percent_encode_component(&artifact.digest)
                )
            };
            format!(
                "<a href=\"{}\">{}-{}</a>",
                href,
                html_escape(&artifact.name),
                html_escape(&artifact.version)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!("<!doctype html><html><body>\n{links}\n</body></html>")
}

pub fn deny_unpromoted(artifact: &ArtifactRef) -> String {
    format!(
        "status=503\nreason_code=artifact_not_promoted\necosystem={}\nname={}\nversion={}",
        artifact.ecosystem, artifact.name, artifact.version
    )
}

fn escape_json(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                escaped.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => escaped.push(character),
        }
    }
    escaped
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn percent_encode_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(*byte as char);
            }
            byte => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    const ABC_DIGEST: &str =
        "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const ABC_OBJECT_KEY: &str =
        "blobs/sha256/ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn renders_npm_packument_from_promoted_generation() {
        let generation = sample_generation();
        let packument = render_npm_packument(&generation, "https://vault.test/npm");
        assert!(packument.contains("\"name\":\"fixture\""));
        assert!(packument.contains(ABC_DIGEST));
    }

    #[test]
    fn npm_packument_percent_encodes_tarball_components() {
        let mut generation = sample_generation();
        generation.artifact.name = "@scope/pkg name".to_string();
        generation.artifact.version = "1.0.0+build".to_string();
        let packument = render_npm_packument(&generation, "https://vault.test/npm/");
        assert!(packument.contains("\"name\":\"@scope/pkg name\""));
        assert!(packument.contains(
            "\"tarball\":\"https://vault.test/npm/%40scope%2Fpkg%20name/1.0.0%2Bbuild\""
        ));
    }

    #[test]
    fn pypi_simple_percent_encodes_href_and_escapes_text() {
        let mut generation = sample_generation();
        generation.artifact.ecosystem = "pypi".to_string();
        generation.artifact.name = "bad<name>/pkg".to_string();
        generation.artifact.version = "1.0.0+local".to_string();
        let simple = render_pypi_simple(&[generation]);
        assert!(simple.contains(
            "href=\"/pypi/bad%3Cname%3E%2Fpkg/1.0.0%2Blocal#sha256%3Aba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\""
        ));
        assert!(simple.contains("bad&lt;name&gt;/pkg-1.0.0+local"));
    }

    #[test]
    fn pypi_simple_file_base_points_at_local_file_route() {
        let mut generation = sample_generation();
        generation.artifact.ecosystem = "pypi".to_string();
        let simple =
            render_pypi_simple_with_file_base(&[generation], "http://127.0.0.1:4873/files/");
        assert!(simple.contains("href=\"http://127.0.0.1:4873/files/pypi/fixture/1.0.0#sha256%3A"));
        assert!(!simple.contains("files.pythonhosted.org"));
        assert!(!simple.contains("pypi.org"));
    }

    #[test]
    fn unpromoted_artifact_is_fail_closed_response() {
        let artifact = sample_generation().artifact;
        let response = deny_unpromoted(&artifact);
        assert!(response.contains("status=503"));
        assert!(response.contains("artifact_not_promoted"));
    }

    fn sample_generation() -> ServableGeneration {
        ServableGeneration {
            generation_id: 1,
            tenant_id: "tenant-1".to_string(),
            request_id: "req-1".to_string(),
            cache_object_key: ABC_OBJECT_KEY.to_string(),
            fetch_job_id: "fetch-req-1".to_string(),
            fetch_quarantine_id: "quarantine-fetch-req-1".to_string(),
            fetch_byte_len: 3,
            fetch_byte_limit: 1024,
            fetch_audit_event_id: "audit-fetch-req-1".to_string(),
            evidence_profile_id: "npm.registry_tarball.v1".to_string(),
            policy_version: "policy-1".to_string(),
            audit_event_id: "audit-req-1".to_string(),
            artifact: ArtifactRef {
                ecosystem: "npm".to_string(),
                name: "fixture".to_string(),
                version: "1.0.0".to_string(),
                digest: ABC_DIGEST.to_string(),
                source: "registry".to_string(),
            },
        }
    }
}
