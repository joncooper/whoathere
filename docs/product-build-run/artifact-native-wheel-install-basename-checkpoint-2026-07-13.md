# Artifact-Native Wheel Install Basename Checkpoint

Date: 2026-07-13

Status: the exact normalization-validated wheel basename is bound through typed scenarios and the
closed runner request; no package was executed

## Outcome

WhoaThere no longer drops the wheel filename before the future pip install boundary. Every wheel
scenario template now includes the exact original `.whl` basename that passed normalization, and
strict decoding exposes that value to the closed wheel operation. The execution request carries the
same basename for install, `.pth`, import-root, and console-entry-point scenarios.

This matters because pip selects and validates wheels partly from the filename. Replacing the name
with an arbitrary generic value would be unreliable, while accepting an unvalidated caller path
would reopen the runner surface.

## Closed grammar and binding

Artifact normalization now requires:

- an ASCII basename of at most 255 bytes;
- no slash, backslash, leading dot, control byte, or unsupported character;
- exactly distribution, version, optional build tag, Python tag, ABI tag, and platform tag fields;
- an optional build tag beginning with a digit;
- nonempty compatibility-tag components;
- WHEEL metadata tags with one Python/ABI/platform triple; and
- filename distribution, version, and compatibility tags corroborated by normalized metadata.

The strict scenario decoder repeats the safe-basename and package-identity checks. The runner
request decoder independently rejects a missing, malformed, path-bearing, or cross-ecosystem wheel
name. The basename is typed data; the request still accepts no artifact path, working directory,
executable, argv vector, or shell fragment.

## Verification

Focused tests pass for:

- complete wheel normalization;
- rejection of traversal-like names, ambiguous wheel fields, and malformed build tags;
- canonical scenario round trips carrying the exact basename;
- scenario-wire filename tampering;
- closed wheel-operation derivation; and
- all 109 macOS/Linux VZ library tests.

Two clean offline Linux/aarch64 builds produced the same stripped static runner:

- byte length: `932664`;
- SHA-256: `83ea03c288f7003c5150c7212d00a69a1f57c31a27233c8bc4ae13bfc8e692d9`.

Its fixed false-authority probe passed in the pinned Alpine container with `--network none`, a
read-only root filesystem, and no package input. No protected execution mode was invoked.

No npm, pip, Python import, package lifecycle hook, VM, or sample ran while building this checkpoint.

## Malware handling boundary

Real malware runs only on the approved cloud Mac under the restricted lab workflow. This change
used only deterministic inert wheel bytes in Rust tests. It did not download, inspect, unpack,
transfer, or execute any real sample and did not enable sync-back or an external route.

## Claim boundary and next gate

This is a prerequisite for reliable pip detonation, not a behavior detection. The malicious-package
result remains 7/11. Next, derive fixed no-caller-command npm and wheel process sequences from the
closed operation enum, bind the root-created immutable input basename to the already rehashed
artifact descriptor, and add cgroup-bounded execution plus authenticated evidence. Actual inert
package execution belongs in a fresh Linux VZ clone on the approved cloud Mac; real samples remain
later, after the inert execution runtime is physically qualified.
