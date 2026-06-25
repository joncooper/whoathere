# System Context

## Context Diagram

```mermaid
flowchart LR
  Dev["Developer laptop\nmacOS/Linux"] --> CLI["WhoaThere CLI\nPATH shims"]
  CI["CI runner"] --> CLI
  CLI --> PM["npm / pip"]
  CLI --> LocalPolicy["Local policy cache"]
  CLI --> Sandbox["Sandbox runner"]
  PM --> Vault["WhoaThere Vault\nregistry proxy"]
  Vault --> Policy["Policy service"]
  Vault --> CAS["CAS object store"]
  Vault --> Scan["Scan/detonation workers"]
  Vault --> Audit["Audit pipeline"]
  Scan --> Upstream["npmjs / PyPI"]
  Admin["Security admin"] --> Policy
  Admin --> Audit
```

## Container Diagram

```mermaid
flowchart TB
  subgraph Endpoint["Endpoint"]
    Shim["PATH shims"]
    CLI["whoathere-cli"]
    Engine["local-engine"]
    Runner["sandbox-runner"]
    LocalAudit["local audit buffer"]
    Shim --> CLI --> Engine --> Runner
    Engine --> LocalAudit
  end

  subgraph Vault["Vault"]
    DataPlane["vault-data-plane"]
    Registry["registry-adapters"]
    Admission["admission API"]
    PolicySvc["policy-service"]
    Workers["scan-detonation-workers"]
    AuditPipe["audit-event-pipeline"]
    Store["CAS + metadata DB"]
    DataPlane --> Registry
    DataPlane --> Admission
    Admission --> PolicySvc
    Admission --> Workers
    Admission --> Store
    Workers --> Store
    Admission --> AuditPipe
  end

  Endpoint --> Vault
```

## Trust Boundaries

- Shim to real package manager: command preservation and attribution.
- Local engine to sandbox: untrusted install/build execution boundary.
- Endpoint to Vault: authenticated registry/proxy boundary.
- Quarantine CAS to promoted CAS: scan-before-serve boundary.
- Policy/admin to enforcement: signed policy provenance boundary.

