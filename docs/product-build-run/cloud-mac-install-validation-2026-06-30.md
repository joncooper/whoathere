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

## Current Blocker

Cloud-host VM validation cannot continue over SSH alone on this machine until there is an active
GUI login/session for the target user, or the provider supplies a supported way to run
Virtualization.framework macOS guests from a headless session.

## Next Steps

1. Enable/use provider console, Screen Sharing, or VNC.
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

5. If init succeeds, continue with guest provisioning, VM health, detonation, sync validation, and
   real-project trials.

## Product Follow-Ups

- Update docs to state the current restore-image disk floor is 64 GiB.
- Improve `vm init` progress output during restore image download/install.
- Detect and explain SSH-only/no-GUI-session Virtualization.framework failures explicitly.
- Consider a preflight check for active `gui/<uid>` launchd domain before macOS guest install.
