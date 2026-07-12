# Artifact-Native Linux VZ Reparented-Child Checkpoint

Date: 2026-07-12

Status: `reparented_child` plus the twenty-six earlier physical cases pass on one exact measured
backend identity; the backend remains `candidate_unqualified` with 11 of 38 cases pending

## Outcome

The fifth teardown-stress gate proves cgroup-backed teardown of a descendant after its package
launcher exits. The protected sensor is the process subreaper. A bounded readiness record binds the
descendant PID; launcher exit, procfs parent identity, package credentials, and cgroup membership
prove adoption before a guest-monotonic one-second deadline begins.

At the deadline the sensor re-proves the descendant is live under the protected subreaper and in the
measured cgroup, delivers exactly one `SIGTERM`, and reaps signal 15. It requires strict
exec/fork/reparent/TERM/exit order, exactly two forks and two reaps, no remaining descendant, closed
sensors, and an empty removed cgroup. Rust and Swift reject forged targets, counts, signals, lineage,
cleanup, health, heartbeat, drop, and canonicalization claims.

| Binding or observation | Final reparented-child case |
| --- | --- |
| Backend identity | `sha256:8cf8ce6e71cd01d02adb7e108b9f3d816d722a7c7cc593434f936259da39dd64` |
| Entitled signed host helper | `sha256:8ee69709ae65a113195ca1f28ed5534023722a546d155b9d4e3784e34ac0162f` |
| Linux kernel | `sha256:8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Signed initramfs | `sha256:cb888f59c0ae1f3915940c0476231929ea4ce5ed41093fa502c9c36751121370` |
| Guest signer | `sha256:655834c37c83e29973f80585c7dd3ed17ec3cce1fd9b76ab7c4f604f5cf91d1e` |
| Protected sensor | `sha256:9e9b9c18815b2c03ae69273a9077099e1b1fe15a5686ace7359fb3f0dc522212` |
| Unprivileged fixture child | `sha256:fd6d0daae7ef889350961eb1a60086bd7297c1fb4afe18b0e1cfc1c4f8e156e1` |
| Fixture bundle | `sha256:49619aa7f10f8063d3522b64d79fcb61143ddf7f5c0d070187a1d6ea73689f75` |
| Signed-image manifest | `sha256:23067e420824fdbc17ffcd88737bfd8fad4d35ac97a50fe9cceb80252e66cb46` |
| Challenge | `sha256:a406dead4b1869af80d86a69f398a6cac4910237bd2d89c5025d12423882234a` |
| Run spec | `sha256:52fc8f09d8425f5a7d3f4c78336c2d67697fd68e7750542c59ff8e1bb7c63577` |
| Guest teardown evidence | `sha256:c0eaff0d2c79b696ce9af5e45cad3ff4b692467f8100ccba9c829381da6405a4` |
| Guest receipt | `sha256:027c22447fb97d978bafe63f4b161d061d5b441b4ad48d3689041fd587049fc1` |
| Host lifecycle evidence | `sha256:bd2049bd510ac327823ae3358fc4a7ae33f099641a8466d4a6ce707d32e36669` |
| Host receipt | `sha256:bdee039376949023d766799121190e6d73b7cacc91585a8b9d802795d2b3f7d0` |
| Sanitized serial | `sha256:f89255c8d0645a99d45f309361af703267bafd69407da62b14e0183e712adb84` |
| Guest event order | `exec -> fork -> reparent -> signal_term -> exit` |
| Forks / reaps / TERM / KILL | `2` / `2` / `1` / `0` |
| Reparent target | `protected_subreaper_at_deadline` |
| Guest / host terminal | `timeout_with_teardown` / `timeout_with_teardown` |
| VM stopped / clone destroyed | `true` / `true` |
| Execution authority / package execution / sync-back | `false` / `false` / `false` |

Two clean signed-image builds were recursively byte-identical and independently verified. All 27
implemented cases then ran physically on this identity. All 81 downloaded request inputs matched
locally and every signed complete case passed the independent Rust verifier using pinned guest and
remote-host public keys. The restricted, gitignored sanitized 27-case archive has SHA-256
`e31a8577e6c7aab4af18392ed784bddd66a5402046f9cd498d7b543403bf9fb4`.

## Boundary and next gate

This remains telemetry qualification, not package detection. No npm, PyPI, unknown, restricted, or
malware package code ran. The backend cannot issue package-execution authority. The next closed gate
is `background_listener`.
