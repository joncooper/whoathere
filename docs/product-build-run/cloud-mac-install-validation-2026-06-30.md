# Cloud Mac Install Validation - 2026-06-30

## Scope

Validated GitHub-auth-free distribution and clean-host install behavior on a disposable Apple
Silicon cloud Mac.

Host:

- Provider class: remote Apple M1 Mac mini
- Initial OS: macOS 26.3.2 build 25D2140
- Updated OS during test: macOS 26.5.2 build 25F84
- Architecture: arm64

Artifact:

- Archive: `whoathere-macos-arm64-preview-ff1bb24.tar.gz`
- Install prefix: `/Users/m1/.whoathere-ff1bb24`

## Results

- SSH/SCP distribution works without GitHub authentication on the target host.
- `scripts/whoathere-copy-release-over-ssh.sh` copies the archive plus a portable basename-only
  SHA-256 sidecar.
- Remote `shasum -a 256 -c whoathere-macos-arm64-preview-ff1bb24.tar.gz.sha256` passed.
- `install-macos-preview.sh --prefix "$HOME/.whoathere-ff1bb24" --force` passed.
- Packaged CLI and VM helper passed `codesign --verify`.
- `whoathere doctor --json` ran successfully and reported expected pre-VM fail-closed state.

## VM Initialization Findings

The first VM init attempt used a 30 GiB disk:

```sh
whoathere vm init --state-dir "$WHOATHERE_STATE" \
  --fetch-latest-restore-image \
  --memory-mib 4096 \
  --disk-gib 30 \
  --execute
```

It failed closed with:

```text
restore_disk_below_minimum_64_gib
```

Current implementation therefore requires at least 64 GiB for restore-image VM creation, despite
earlier planning notes targeting 25-40 GiB.

The second attempt used 64 GiB on macOS 26.3.2. It failed closed with Apple
Virtualization.framework error:

```text
Installation requires a software update.
```

After updating the host to macOS 26.5.2 and rebooting, the 64 GiB init progressed further but
failed closed with:

```text
The virtual machine encountered a security error.
Unable to access security information.
Failed_to_get_current_host_key.
```

System logs showed:

```text
This user is not allowed access to the window system right now.
SecKeyCreateRandomKey_ios failed: errSecInteractionNotAllowed
```

Session checks showed:

```text
console_user=root
kCGSessionUserNameKey=unknown
kCGSessionLoginDoneKey=FALSE
launchctl print gui/$(id -u): Domain does not support specified action
kern.hv_support: 1
```

Interpretation: hardware virtualization is present, but the VM installer is being launched from an
SSH-only session with no logged-in Aqua/window-system session for the `m1` user. Apple
Virtualization.framework cannot generate/access required host security material in that session.

Attempted workaround:

```sh
sudo sysadminctl -autologin set -userName m1 -password -
sysadminctl -autologin status
```

Result:

```text
SACSetAutoLoginPassword error:22
Automatic login is OFF.
```

Automatic graphical login could not be enabled from SSH on this host.

## GUI Session Continuation

After a graphical login as `m1`, SSH-side checks reported:

```text
console_user=m1
gui_session=ok
```

VM initialization then succeeded with a 64 GiB disk and 4096 MiB memory. The fetched Apple restore
image was:

```text
macOS 26.5.2 build 25F84
sha256:065abd295a1a456a46c1155217eab92ee95816520ec9aeed83f249f074f68a04
```

This confirms the earlier `Failed_to_get_current_host_key` error was a headless session problem,
not a fundamental cloud-Mac or WhoaThere VM-init incompatibility.

## Guest Runtime Provisioning

The cloud Mac needed explicit guest toolchain staging before npm and uv validation could run. Added
`scripts/whoathere-bootstrap-cloud-mac-runtimes.sh` to stage:

- `uv 0.11.26`
- CPython `3.12.13`
- pip `26.1.2`
- setuptools `68.2.2`
- packaging `26.2`
- wheel `0.47.0`
- Node `v22.23.1`
- npm `10.9.8`

Provisioning receipt after rerun:

```text
offline_python_runtime_status=installed
offline_python_wheels_status=installed
wheel_package_status=installed
offline_node_runtime_status=installed
offline_uv_binary_status=installed
host_home_mounted=false
host_secrets_mounted=false
high_risk_package_execution_enabled=false
```

During validation, clean `uv pip install .` initially failed closed because the guest agent only put
pip, setuptools, and wheel on `PYTHONPATH`; current wheel imports `packaging` during metadata/wheel
builds. The fix was to:

- stage the `packaging` wheel with the runtime inputs
- copy all staged wheels into the guest, clearing stale wheels first
- build guest `PYTHONPATH` from all staged wheels rather than only three hardcoded wheel names

## VM Detonation Validation

After the runtime and guest-agent fix, live VM validation passed:

```text
whoathere vm validate-npm-uv --state-dir "$WHOATHERE_STATE" --execute
validate_status=0
npm_uv_detonation_validation=ok
```

Covered outcomes:

- clean `npm install` allowed in the VM
- clean `npm ci` allowed in the VM
- npm lifecycle canary denied in the VM before host execution
- npm API-use canary denied in the VM before host execution
- public npm dependency resolution deferred/fail-closed
- clean `uv pip install .` allowed in the VM
- uv import-time canary denied in the VM before host execution
- uv public requirement deferred/fail-closed
- `uv sync` deferred/fail-closed until lock/source policy is explicit

Final doctor summary on the cloud Mac:

```text
status=ok
vm_ready=true
vm_runtime_ready=true
vm_lifecycle_ready=true
release_ready=false
```

The remaining `release_ready=false` reasons on this patched preview tree were notarization and
sync-back validation receipts, not VM runtime or npm/uv detonation blockers.

## Packaged `aaa5dc1` Follow-Up

After committing the runtime/provisioning fix, a new Developer-ID-signed preview archive was built:

```text
dist/whoathere-macos-arm64-preview-aaa5dc1.tar.gz
sha256:a27ca7379233515e342faa7e56e6782a644a7f8c3418d9e66d110a1cbf78b718
```

Archive smoke validation passed locally, including checksum verification, install dry-run, install
to a path containing spaces, binary signature verification, `doctor`, stale-tooling fail-closed
checks, scanner readiness checks, and helper script syntax checks.

The archive was copied to the cloud Mac, checksum-verified, installed into:

```text
/Users/m1/.whoathere-aaa5dc1
```

The existing validation VM was then reprovisioned from the packaged `aaa5dc1` helper tree and
validated without patching the installed package in place:

```text
validate_aaa5dc1_status=0
npm_uv_detonation_validation=ok
```

The packaged run wrote a signed release-validation receipt with:

```text
npm_vm_detonation_verified=true
uv_vm_detonation_verified=true
live_guest_toolchains_verified=true
host_package_execution_enabled=false
sync_back_enabled=false
high_risk_package_execution_enabled=false
package_acquisition_policy=local_only_no_public_resolver
```

The VM was suspended cleanly after validation.

GitHub pre-release:

```text
https://github.com/joncooper/whoathere/releases/tag/macos-local-beta-aaa5dc1
```

Apple notarization was completed from an interactive shell that could access the
`whoathere-notary` keychain profile. Apple returned `Accepted` for the packaged notary zip:

```text
notarytool_id=89b83bb6-a060-4b09-9090-adc8f683bda9
notarytool_status=Accepted
notarization_receipt=/Users/jdc/.whoathere/macos-vm-validation/bundle/release-notarization.json
```

The accepted notary JSON is attached to the GitHub pre-release alongside the archive and checksum.

## Six-Stage Validation Status

Current status for the `aaa5dc1` macOS local beta candidate:

| Stage | Status | Evidence |
| --- | --- | --- |
| 1. Fresh Mac access and baseline | Passed | Disposable Apple Silicon cloud Mac reached, updated to macOS 26.5.2, and confirmed to require an active GUI session for Virtualization.framework VM install. |
| 2. Distribution and install | Passed | SSH/SCP archive transfer passed, GitHub pre-release is available, checksum validation passed, clean temporary HOME install qualification passed for the notarized archive. |
| 3. VM creation and provisioning | Passed with known operator requirement | VM init succeeded after GUI login. Guest runtime provisioning succeeded after staging Python, Node/npm, uv, and required wheels. |
| 4. Synthetic VM safety validation | Passed | Packaged `aaa5dc1` VM validation reported `npm_uv_detonation_validation=ok`, with clean npm/uv cases allowed inside the VM and canary/public-resolution cases fail-closed. |
| 5. Signed/notarized release artifact | Passed | CLI and helper are Developer ID signed. Apple notarization returned `Accepted` for submission `89b83bb6-a060-4b09-9090-adc8f683bda9`; the notary JSON is attached to the GitHub pre-release. |
| 6. Real-project trials | Partially passed | Offline package-risk trials against six local npm/uv/Python workspaces completed without host package execution; all stayed `manual_review` in fresh package memory, which is secure but friction-heavy. Scanner-backed trials on private projects were kept offline to avoid disclosing private dependency metadata to external services. |

Local validation on the development Mac also reran:

```text
scripts/whoathere-clean-install-qualification.sh --archive dist/whoathere-macos-arm64-preview-aaa5dc1.tar.gz --notarization-receipt /Users/jdc/.whoathere/macos-vm-validation/bundle/release-notarization.json
clean_install_fully_qualified=true
```

The same-host runtime qualification preflight is ready but currently stops at the admin
reprovision step because `sudo` is not cached:

```text
runtime_reprovision_required=true
runtime_reprovision_handoff=/Users/jdc/src/whoathere/dist/whoathere-macos-arm64-preview-aaa5dc1-runtime-reprovision.sh
sudo: a password is required
```

That handoff re-extracts the signed archive, runs the guest provisioning script from the extracted
artifact, and then resumes runtime qualification. Until it is run, local `doctor --json` correctly
keeps `release_ready=false` because the current sync-validation receipt is stale for the
`aaa5dc1` CLI/helper digests.

The packaged artifact readiness gate is now repeatable:

```sh
scripts/whoathere-macos-beta-readiness-check.sh --version aaa5dc1 --state-dir /Users/jdc/.whoathere/macos-vm-validation
```

Current output is intentionally not ready:

```text
ready=false
checksum_verified=true
cli_signature_valid=true
helper_signature_valid=true
notary_accepted=true
clean_install_qualified=true
doctor_release_ready=false
doctor_release_blocking_reason_codes=["macos_vm_guest_agent_source_digest_mismatch","release_sync_back_validation_not_verified","sync_validation_cli_digest_mismatch","sync_validation_helper_digest_mismatch"]
```

## Next Steps

1. If validating the cloud Mac again, enable/use provider console, Screen Sharing, or VNC.
2. Log in graphically as `m1`.
3. Confirm:

   ```sh
   stat -f 'console_user=%Su' /dev/console
   launchctl print gui/$(id -u) >/dev/null
   ```

4. Rerun:

   ```sh
   export PATH="$HOME/.whoathere-ff1bb24/bin:$PATH"
   export WHOATHERE_STATE="$HOME/.whoathere/macos-vm-validation-ff1bb24"
   whoathere vm prune --state-dir "$WHOATHERE_STATE" --execute
   whoathere vm init --state-dir "$WHOATHERE_STATE" \
     --fetch-latest-restore-image \
     --memory-mib 4096 \
     --disk-gib 64 \
     --execute
   ```

5. On the development Mac, run:

   ```sh
   dist/whoathere-macos-arm64-preview-aaa5dc1-runtime-reprovision.sh
   ```

   This should refresh guest provisioning and rerun same-host runtime qualification, including
   current sync-back validation.

6. After runtime qualification passes, rerun `doctor --json --state-dir
   /Users/jdc/.whoathere/macos-vm-validation --helper
   /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/release/whoathere-macos-vm-helper`
   and confirm no sync-validation or guest-agent digest blockers remain.

   The simpler final gate is:

   ```sh
   scripts/whoathere-macos-beta-readiness-check.sh --version aaa5dc1 --state-dir /Users/jdc/.whoathere/macos-vm-validation
   ```

   It must report `ready=true` before the six-stage validation path is complete.

7. For private real projects, keep networked scanners opt-in because they may disclose dependency
   metadata to external services. Use offline package-risk by default and controlled public fixtures
   for networked scanner testing.

## Product Follow-Ups

- Update docs to state the current restore-image disk floor is 64 GiB.
- Improve `vm init` progress output during restore image download/install.
- Detect and explain SSH-only/no-GUI-session Virtualization.framework failures explicitly.
- Consider a preflight check for active `gui/<uid>` launchd domain before macOS guest install.
- Keep the runtime bootstrap script as the repeatable path for disposable cloud Mac validation.
- Consider adding a provisioning receipt field that records all staged Python helper wheels, not
  only pip/setuptools/wheel.
