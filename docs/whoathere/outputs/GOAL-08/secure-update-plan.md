# Secure Update Plan

## Endpoint Binaries

- macOS binaries are signed and notarized.
- Linux binaries are signed with checksums and package metadata signatures.
- Update manifests are signed.
- Endpoint verifies signature before install.
- Rollback protection prevents downgrade to known-vulnerable versions unless explicitly approved.

## Vault Components

- Container images are signed.
- SBOM generated for releases.
- Deployment requires provenance-attested build.
- Production rollout uses staged deployment and health checks.

## Update Channels

- Stable.
- Preview/internal.
- Emergency security channel with explicit audit.

## Required ADR Before External Distribution

Before any external endpoint distribution, produce a secure-update ADR covering signing-key custody, threshold signing or equivalent release approval, manifest expiry, rollback protection, revocation, emergency kill switch, channel promotion, emergency release authority, and transparency/Sigstore/TUF-style metadata decision.
