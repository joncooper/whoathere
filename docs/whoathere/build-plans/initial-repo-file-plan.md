# Initial Repo File Plan

## Principle

Keep WhoaThere product implementation isolated in `/Users/jdc/src/whoathere/whoathere` so the existing Swift timer app remains untouched.

## Created/Planned Structure

```text
whoathere/
  Cargo.toml
  README.md
  crates/
    whoathere-core/
    whoathere-policy/
    whoathere-audit/
    whoathere-sandbox/
    whoathere-cli/
  tests/
    fixtures/
      npm/postinstall-exfil/
      pypi/pep517-backend/
```

## Crate Responsibilities

| Crate | Responsibility |
| --- | --- |
| `whoathere-core` | Shared modes, config, package context, endpoint events. |
| `whoathere-policy` | Fail-closed local policy primitives. |
| `whoathere-audit` | Redacted audit records. |
| `whoathere-sandbox` | Backend traits and containment labels. |
| `whoathere-cli` | CLI skeleton and command routing. |

