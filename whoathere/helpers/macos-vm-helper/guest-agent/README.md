# WhoaThere Guest Readiness Agent

This directory contains the minimal guest-side source used by macOS VM Goal 1 to prove that a
guest booted far enough to answer a local readiness challenge.

Build inside the macOS guest:

```sh
cc -O2 -Wall -Wextra -o whoathere-guest-ready whoathere-guest-ready.c
```

Run inside the guest after the host helper has started the VM:

```sh
./whoathere-guest-ready
```

For repeatable local VM proof without using the guest UI, provision it as a root-owned launchd
daemon from the host while the VM is stopped:

```sh
sudo ../scripts/provision-guest-readiness.sh /absolute/path/to/vm-state-dir
```

The agent connects to the host over `AF_VSOCK` port `47078`, reads a one-time challenge from the
helper, and returns a `whoathere.guest_ready.v1` response. It does not run npm, pip, uv, shell
installers, package imports, network probes, or sync-back logic. It must be treated only as a
guest-readiness primitive for the local VM lifecycle foundation.
