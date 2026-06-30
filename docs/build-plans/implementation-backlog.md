# Implementation Backlog

## Sprint 0: Foundation

| ID | Task | Phase | Status |
| --- | --- | --- | --- |
| WT-0001 | Create isolated Rust workspace under `whoathere/`. | Phase 1 | started |
| WT-0002 | Add core config and endpoint event types. | Phase 1 | started |
| WT-0003 | Add policy decision primitives. | Phase 1 | started |
| WT-0004 | Add audit redaction primitives. | Phase 1 | started |
| WT-0005 | Add sandbox backend trait and beta labels. | Phase 1 | started |
| WT-0006 | Add CLI skeleton for `doctor`, `status`, `protect`, `shim`. | Phase 1 | started |
| WT-0007 | Add fixture directory scaffolding. | Phase 1 | started |

## Sprint 1: CLI MVP

| ID | Task | Phase | Gate |
| --- | --- | --- | --- |
| WT-0101 | Implement config file loading. | Phase 1 | local schema complete |
| WT-0102 | Implement command classification for npm/pip. | Phase 1 | CT-002/003/007 fixtures |
| WT-0103 | Implement shim dry-run manifest. | Phase 1 | no host mutation |
| WT-0104 | Implement local audit JSONL writer. | Phase 1 | redaction tests |

## Later Backlog

- Linux namespace runner.
- macOS VM beta helper.
- Vault schema/API prototype.
- Allow-verdict evidence profile research.
- AWS IaC plan.
- Static scanner prototype.

