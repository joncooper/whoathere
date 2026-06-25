# Policy Model

## Subjects

- `tenant`
- `project`
- `repository`
- `user`
- `machine`
- `ci_runner`
- `team`
- `service_account`

## Resources

- `ecosystem`
- `package_name`
- `version`
- `artifact_digest`
- `source_registry`
- `dependency_edge`
- `lockfile_entry`
- `lifecycle_script`
- `build_backend`
- `native_extension`
- `network_destination`
- `source_type`

## Decisions

- `allow`
- `deny`
- `quarantine`
- `manual_review`
- `break_glass`

## Defaults

- CI fails closed for unsupported source types, internal namespace conflicts, scanner/proxy/policy outage, and ambiguous verdict.
- Developer warning mode requires explicit policy.
- Internal package names and scopes never fall back to public registries unless explicit approved mapping exists.
- Lifecycle/build/import execution requires allow verdict or sandboxed detonation.

## Example Rules

```yaml
rules:
  - id: internal-scope-private-only
    when:
      ecosystem: npm
      package_name_prefix: "@company/"
    require:
      source_registry: "https://vault.example/npm/company"
    decision_on_violation: deny

  - id: ci-direct-url-deny
    when:
      environment: ci
      source_type: [git, tarball_url, direct_url, editable]
    decision: deny

  - id: developer-git-review
    when:
      environment: developer
      source_type: [git, tarball_url]
    decision: manual_review
```

