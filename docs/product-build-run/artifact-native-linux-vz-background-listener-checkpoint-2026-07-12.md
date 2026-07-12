# Artifact-Native Linux VZ Background-Listener Checkpoint

Date: 2026-07-12

Status: `background_listener` plus the twenty-seven earlier physical cases pass on one exact
measured backend identity; the backend remains `candidate_unqualified` with 10 of 38 cases pending

## Outcome

The sixth teardown-stress gate proves ownership and removal of a background loopback listener after
its package launcher exits. The measured unprivileged launcher forks a descendant and exits. The
protected sensor, acting as subreaper, accepts one bounded readiness record and correlates the
descendant PID, package credentials, measured cgroup, socket file-descriptor inode, and the exact
`127.0.0.1:40552` LISTEN row in `/proc/net/tcp`.

Only after those checks pass does the one-second guest-monotonic deadline begin. At the deadline the
sensor re-proves the procfs parent, cgroup, file-descriptor, and listener identities, delivers
exactly one `SIGTERM`, and reaps signal 15. It then requires that exact listener to be absent,
closes its protected sensors, proves the cgroup empty, and removes it. Rust and Swift reject forged
owner, address, port, removal, reparenting, signal, count, cleanup, health, drop, event-lineage, and
canonicalization claims.

| Binding or observation | Final background-listener case |
| --- | --- |
| Backend identity | `sha256:68842c72560eb0be95d50dedd3eeb61a0434de50f33b46002132389b193f5e29` |
| Entitled signed host helper | `sha256:99d29a0c9900df6b4ceeebe2aa7d1e2b925aaf293ed17c17b10e854763986edb` |
| Linux kernel | `sha256:8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Signed initramfs | `sha256:f811659aa67554f42678ee1abcf85f46b4b0034a6d5ff396bcf5309648582ad0` |
| Guest signer | `sha256:2de86caeeefc46f5a9b2ee2cad43307c4e378c8e6cef0461e0513f0105b1b759` |
| Protected sensor | `sha256:0fa373c6050059ef74c5da9f0b1f9ff3acb1ed05a1a61a02aa77f7747c23fa98` |
| Unprivileged fixture child | `sha256:44b231a05f55debf85052e58309df8bcbf2c76d666b0794ff1bdea24ecfe2392` |
| Fixture bundle | `sha256:4aa9f3438f350e1b11d893dd0db21f39e92538f4152fcbe0bc9123b3fce95662` |
| Signed-image manifest | `sha256:96d5d6cd77e2c25556046361f25207fc048533da33de87cd8e3bd4d0a035f97f` |
| Challenge | `sha256:5b86fa3e080a4e884ab73ca8618a08ab865da516143868f83abf090fdacf1778` |
| Run spec | `sha256:626e6609ca9461ac5a0d63285542e5eda9108b8e800ea5710fb7b8576ac0fed0` |
| Guest teardown evidence | `sha256:a205dfaede321cac648f3958767e450e18e0be4411d7fe30639f219a949180ce` |
| Guest receipt | `sha256:d16905a5a3a7e3e5d0ddb26130c58c748b3103c7c681d202df072ffffe4cfb6d` |
| Host lifecycle evidence | `sha256:bd2049bd510ac327823ae3358fc4a7ae33f099641a8466d4a6ce707d32e36669` |
| Host receipt | `sha256:b8f92146b7c823c571f0e3f44b1024f3ca8aa9b7cac25beacd25359bce8136e4` |
| Sanitized serial | `sha256:2d247ce3f6d5e76261bcb538a0721e47df617fa8d63fd384100f052b9c95f0db` |
| Guest event order | `exec -> fork -> reparent -> listener_ready -> signal_term -> exit` |
| Forks / reaps / TERM / KILL | `2` / `2` / `1` / `0` |
| Listener | `127.0.0.1:40552`, owner `reparented_descendant_at_deadline`, removed `true` |
| Reparent target | `protected_subreaper_at_deadline` |
| Guest / host terminal | `timeout_with_teardown` / `timeout_with_teardown` |
| VM stopped / clone destroyed | `true` / `true` |
| Execution authority / package execution / sync-back | `false` / `false` / `false` |

Two clean signed-image builds were recursively byte-identical and independently verified. All 28
implemented cases then ran physically on this identity. All 84 downloaded request inputs matched
locally and every signed complete case passed the independent Rust verifier using pinned guest and
remote-host public keys. The restricted, gitignored sanitized 28-case archive contains 224 files
and has SHA-256 `901e1e859c9fefbaeef5b4c0ca9495d035ac889b809a141539fefdf757b6ddd3`.

## Boundary and next gate

This remains telemetry qualification, not package detection. No npm, PyPI, unknown, restricted, or
malware package code ran. The backend cannot issue package-execution authority. The next closed gate
is `channel_interruption`.
