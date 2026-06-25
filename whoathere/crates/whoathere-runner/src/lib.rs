use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionDecision {
    ExecuteReadonly,
    Refuse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionPlan {
    pub decision: ExecutionDecision,
    pub reason_code: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionOutput {
    pub status_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

pub fn plan_protected_execution(
    tool: &str,
    args: &[String],
    execute_requested: bool,
) -> ExecutionPlan {
    if !execute_requested {
        return ExecutionPlan {
            decision: ExecutionDecision::Refuse,
            reason_code: "execution_not_requested",
        };
    }

    if !is_supported_tool(tool) {
        return ExecutionPlan {
            decision: ExecutionDecision::Refuse,
            reason_code: "unsupported_tool_execution_refused",
        };
    }

    if is_readonly_version_probe(args) {
        if !is_absolute_tool_path(tool) {
            return ExecutionPlan {
                decision: ExecutionDecision::Refuse,
                reason_code: "real_binary_required_for_readonly_execution",
            };
        }
        return ExecutionPlan {
            decision: ExecutionDecision::ExecuteReadonly,
            reason_code: "readonly_version_probe",
        };
    }

    ExecutionPlan {
        decision: ExecutionDecision::Refuse,
        reason_code: "package_manager_execution_gated",
    }
}

pub fn execute_readonly(
    tool: &str,
    args: &[String],
    plan: &ExecutionPlan,
) -> std::io::Result<ExecutionOutput> {
    if plan.decision != ExecutionDecision::ExecuteReadonly {
        return Ok(ExecutionOutput {
            status_code: Some(70),
            stdout: String::new(),
            stderr: format!("refused: {}", plan.reason_code),
        });
    }

    if !is_absolute_tool_path(tool) {
        return Ok(ExecutionOutput {
            status_code: Some(70),
            stdout: String::new(),
            stderr: "refused: real_binary_required_for_readonly_execution".to_string(),
        });
    }

    let output = Command::new(tool)
        .env_clear()
        .env("WHOA_THERE_READONLY_PROBE", "1")
        .args(args)
        .output()?;
    Ok(ExecutionOutput {
        status_code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

fn is_supported_tool(tool: &str) -> bool {
    matches!(
        basename(tool),
        "npm" | "npx" | "pip" | "pip3" | "python" | "python3"
    )
}

fn is_readonly_version_probe(args: &[String]) -> bool {
    matches!(args, [arg] if arg == "--version" || arg == "-V" || arg == "-v")
}

fn is_absolute_tool_path(tool: &str) -> bool {
    std::path::Path::new(tool).is_absolute()
}

fn basename(value: &str) -> &str {
    value.rsplit(['/', '\\']).next().unwrap_or(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_execution_when_not_requested() {
        let args = vec!["--version".to_string()];
        let plan = plan_protected_execution("npm", &args, false);
        assert_eq!(plan.decision, ExecutionDecision::Refuse);
        assert_eq!(plan.reason_code, "execution_not_requested");
    }

    #[test]
    fn refuses_relative_readonly_version_probe_when_requested() {
        let args = vec!["--version".to_string()];
        let plan = plan_protected_execution("npm", &args, true);
        assert_eq!(plan.decision, ExecutionDecision::Refuse);
        assert_eq!(
            plan.reason_code,
            "real_binary_required_for_readonly_execution"
        );
    }

    #[test]
    fn allows_absolute_readonly_version_probe_when_requested() {
        let args = vec!["--version".to_string()];
        let tool = if cfg!(windows) {
            "C:\\npm"
        } else {
            "/usr/bin/npm"
        };
        let plan = plan_protected_execution(tool, &args, true);
        assert_eq!(plan.decision, ExecutionDecision::ExecuteReadonly);
        assert_eq!(plan.reason_code, "readonly_version_probe");
    }

    #[test]
    fn refuses_install_even_when_requested() {
        let args = vec!["ci".to_string()];
        let plan = plan_protected_execution("npm", &args, true);
        assert_eq!(plan.decision, ExecutionDecision::Refuse);
        assert_eq!(plan.reason_code, "package_manager_execution_gated");
    }

    #[test]
    fn refused_plan_does_not_spawn_process() {
        let args = vec!["ci".to_string()];
        let plan = plan_protected_execution("npm", &args, true);
        let output = execute_readonly("npm", &args, &plan).expect("refusal is local");
        assert_eq!(output.status_code, Some(70));
        assert!(output.stderr.contains("package_manager_execution_gated"));
    }
}
