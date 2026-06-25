use whoathere_core::{ExecutionMode, OutageBehavior};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny,
    Quarantine,
    ManualReview,
    BreakGlassRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    Internal,
    Public,
    DirectUrl,
    Git,
    LocalPath,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceOwnership {
    InternalOnly,
    PublicAllowed,
    ExplicitDeny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceRule {
    pub prefix: String,
    pub ownership: NamespaceOwnership,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceEvaluation {
    pub decision: PolicyDecision,
    pub reason_code: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDocument {
    pub schema_version: String,
    pub policy_version: String,
    pub namespace_rules: Vec<NamespaceRule>,
    pub fail_closed: bool,
}

impl Default for PolicyDocument {
    fn default() -> Self {
        Self {
            schema_version: "0.1.0".to_string(),
            policy_version: "local".to_string(),
            namespace_rules: Vec::new(),
            fail_closed: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyParseError {
    UnknownKey(String),
    InvalidValue { key: String, value: String },
    EmptyNamespace(String),
}

pub fn parse_policy_document(input: &str) -> Result<PolicyDocument, PolicyParseError> {
    let mut document = PolicyDocument::default();
    for raw_line in input.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(PolicyParseError::InvalidValue {
                key: line.to_string(),
                value: String::new(),
            });
        };
        let key = key.trim();
        let value = value.trim();
        match key {
            "schema_version" => {
                if value != "0.1.0" {
                    return Err(PolicyParseError::InvalidValue {
                        key: key.to_string(),
                        value: value.to_string(),
                    });
                }
                document.schema_version = value.to_string();
            }
            "policy_version" => document.policy_version = value.to_string(),
            "fail_closed" => {
                document.fail_closed =
                    parse_bool(value).ok_or_else(|| PolicyParseError::InvalidValue {
                        key: key.to_string(),
                        value: value.to_string(),
                    })?
            }
            "internal_namespace" => {
                push_namespace(&mut document, value, NamespaceOwnership::InternalOnly, key)?
            }
            "public_namespace" => {
                push_namespace(&mut document, value, NamespaceOwnership::PublicAllowed, key)?
            }
            "deny_namespace" => {
                push_namespace(&mut document, value, NamespaceOwnership::ExplicitDeny, key)?
            }
            _ => return Err(PolicyParseError::UnknownKey(key.to_string())),
        }
    }
    Ok(document)
}

fn push_namespace(
    document: &mut PolicyDocument,
    prefix: &str,
    ownership: NamespaceOwnership,
    key: &str,
) -> Result<(), PolicyParseError> {
    if prefix.is_empty() {
        return Err(PolicyParseError::EmptyNamespace(key.to_string()));
    }
    document.namespace_rules.push(NamespaceRule {
        prefix: prefix.to_string(),
        ownership,
    });
    Ok(())
}

fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

pub fn evaluate_source_policy(
    package_name: &str,
    source: SourceKind,
    namespace_rules: &[NamespaceRule],
    mode: ExecutionMode,
) -> SourceEvaluation {
    let ownership = namespace_rules
        .iter()
        .filter(|rule| package_name.starts_with(&rule.prefix))
        .max_by_key(|rule| rule.prefix.len())
        .map(|rule| rule.ownership)
        .unwrap_or(NamespaceOwnership::PublicAllowed);

    match (ownership, source) {
        (NamespaceOwnership::ExplicitDeny, _) => SourceEvaluation {
            decision: PolicyDecision::Deny,
            reason_code: "namespace_explicit_deny",
        },
        (NamespaceOwnership::InternalOnly, SourceKind::Internal) => SourceEvaluation {
            decision: PolicyDecision::Allow,
            reason_code: "internal_namespace_internal_source",
        },
        (NamespaceOwnership::InternalOnly, SourceKind::Public) => SourceEvaluation {
            decision: PolicyDecision::Deny,
            reason_code: "dependency_confusion_public_source_denied",
        },
        (NamespaceOwnership::InternalOnly, _) => SourceEvaluation {
            decision: unsupported_source_decision(mode),
            reason_code: "internal_namespace_untrusted_source",
        },
        (NamespaceOwnership::PublicAllowed, SourceKind::DirectUrl | SourceKind::Git) => {
            SourceEvaluation {
                decision: unsupported_source_decision(mode),
                reason_code: "untrusted_direct_source",
            }
        }
        (NamespaceOwnership::PublicAllowed, _) => SourceEvaluation {
            decision: PolicyDecision::Allow,
            reason_code: "public_source_allowed",
        },
    }
}

pub fn outage_decision(
    mode: ExecutionMode,
    behavior: OutageBehavior,
    approved_stale_digest: bool,
) -> PolicyDecision {
    match mode {
        ExecutionMode::CiFailClosed => {
            if approved_stale_digest
                && matches!(
                    behavior,
                    OutageBehavior::AllowApprovedStale | OutageBehavior::WarnApprovedStale
                )
            {
                PolicyDecision::Allow
            } else {
                PolicyDecision::Deny
            }
        }
        ExecutionMode::Protected | ExecutionMode::BetaContainment | ExecutionMode::Observe => {
            match behavior {
                OutageBehavior::Block => PolicyDecision::Deny,
                OutageBehavior::AllowApprovedStale | OutageBehavior::WarnApprovedStale
                    if approved_stale_digest =>
                {
                    PolicyDecision::Allow
                }
                OutageBehavior::AllowApprovedStale | OutageBehavior::WarnApprovedStale => {
                    PolicyDecision::Deny
                }
            }
        }
    }
}

pub fn unsupported_source_decision(mode: ExecutionMode) -> PolicyDecision {
    match mode {
        ExecutionMode::CiFailClosed => PolicyDecision::Deny,
        ExecutionMode::Protected | ExecutionMode::BetaContainment => PolicyDecision::ManualReview,
        ExecutionMode::Observe => PolicyDecision::ManualReview,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ci_outage_denies_unknown_artifact() {
        let decision = outage_decision(
            ExecutionMode::CiFailClosed,
            OutageBehavior::WarnApprovedStale,
            false,
        );
        assert_eq!(decision, PolicyDecision::Deny);
    }

    #[test]
    fn developer_warn_only_allows_approved_stale() {
        let decision = outage_decision(
            ExecutionMode::Protected,
            OutageBehavior::WarnApprovedStale,
            true,
        );
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn unsupported_source_fails_closed_in_ci() {
        assert_eq!(
            unsupported_source_decision(ExecutionMode::CiFailClosed),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn internal_namespace_blocks_public_dependency_confusion() {
        let rules = vec![NamespaceRule {
            prefix: "@company/".to_string(),
            ownership: NamespaceOwnership::InternalOnly,
        }];
        let evaluation = evaluate_source_policy(
            "@company/build-tools",
            SourceKind::Public,
            &rules,
            ExecutionMode::CiFailClosed,
        );
        assert_eq!(evaluation.decision, PolicyDecision::Deny);
        assert_eq!(
            evaluation.reason_code,
            "dependency_confusion_public_source_denied"
        );
    }

    #[test]
    fn direct_url_requires_review_or_deny() {
        let evaluation =
            evaluate_source_policy("left-pad", SourceKind::Git, &[], ExecutionMode::Protected);
        assert_eq!(evaluation.decision, PolicyDecision::ManualReview);
        assert_eq!(evaluation.reason_code, "untrusted_direct_source");
    }

    #[test]
    fn parses_policy_document_namespace_rules() {
        let document = parse_policy_document(
            r#"
            schema_version=0.1.0
            policy_version=policy-2026-06-24
            fail_closed=true
            internal_namespace=@company/
            deny_namespace=bad-
            "#,
        )
        .expect("policy should parse");
        assert_eq!(document.policy_version, "policy-2026-06-24");
        assert!(document.fail_closed);
        assert_eq!(document.namespace_rules.len(), 2);
    }

    #[test]
    fn rejects_unknown_policy_key() {
        let error = parse_policy_document("collect_source=true").unwrap_err();
        assert_eq!(
            error,
            PolicyParseError::UnknownKey("collect_source".to_string())
        );
    }

    #[test]
    fn rejects_unknown_policy_schema_version() {
        let error = parse_policy_document("schema_version=9.9.9").unwrap_err();
        assert_eq!(
            error,
            PolicyParseError::InvalidValue {
                key: "schema_version".to_string(),
                value: "9.9.9".to_string()
            }
        );
    }
}
