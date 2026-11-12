# Cooperating-process race audit

This audit covers production paths that create, select, launch against, recover or retire network resources. Its authority model is deliberately narrow. Nord Tools coordinates its own processes through protected files and advisory locks; it does not exclude an independent process with equivalent kernel or filesystem privileges.

## Lock order and continuity

Namespace lifecycle operations use one stable lock derived from the lifecycle journal. Generation selection, application launch and consumer-aware retirement then acquire the consumer lease lock in that order. No production path acquires those locks in reverse. Host-default protection has a separate store and lock because it owns host-wide resources rather than namespace generations.

The lifecycle, host and consumer locks open a private parent directory without following symlinks. After waiting, each lock rechecks its own inode and the parent directory identity. The consumer lock now also verifies directory and lock ownership, permissions and link count. A replaced directory or lock causes refusal before evidence is read or mutation begins.

Declared consumer references and runtime leases cannot use the same path. That would require acquiring the same lock twice and could deadlock a retirement. Startup configuration also rejects non-canonical paths and aliases between policy, lifecycle, binding, intent, run-record, graph, provider, credential and handover roles. Several profiles may deliberately reference the same provider credential, but that credential cannot also be a lifecycle or handover store. Separate evidence types cannot silently overwrite one another.

## Mutation paths

| Path | Coordination and evidence | Interruption behavior |
| --- | --- | --- |
| Namespace restoration and create-only apply | Lifecycle lock; fresh ownership reconciliation; durable create intent before the first kernel callback; creation-time namespace and interface bindings | A failure makes the intent uncertain. Recovery uses fresh absence or matching recorded identity and never adopts a name match. |
| Cleanup and generation retirement | Lifecycle lock followed by applicable consumer locks; exact scope and lease checks; retiring journal state and intent before deletion; identity recheck immediately before mutation | Pending retire intents become uncertain on failure. Later resources are not touched, and recovery or cleanup refuses disputed evidence. |
| Interrupted-operation recovery | Lifecycle lock; fresh journal, binding, intent and kernel evidence; whole-profile quarantine for a dispute | Record-only convergence and identity-bound rollback are explicit. Lookalikes and unbound host resources remain untouched. |
| Generation replacement | Lifecycle then consumer lock for preparation, verification, activation and retirement; durable handover identity binds A and B | Provisioning occurs while A remains selected. B is selected only after fresh ownership and packet verification. Interrupted phases remain prepared, verified, active or draining for explicit recovery. |
| Registered application launch | Lifecycle then consumer lock; child is stopped inside the selected namespace; creation-time ownership and process identity are checked before a durable lease is written | The child is released only after lease reservation and final generation confinement checks. Failure terminates the child and releases a verified reservation. |
| Host-default protection | Stable host-store lock; one intent and readback record per barrier, endpoint, WireGuard, route and resolver step | Failed mutation is recorded as uncertain. Recovery retains the barrier, and retirement removes it last with explicit exposure authority. |

The offline provider import and startup-unit installers do not mutate kernel network state. Their atomic private-file writes remain separate from the lifecycle authority above.

## Remaining limits

The locks do not make several JSON stores and kernel operations one atomic transaction. Recovery exists for those interruption windows. Namespace deletion and indexed link deletion also cannot atomically bind a prior observation to the kernel mutation. Fresh identity checks narrow that interval but do not prevent a separately privileged process from replacing an object immediately afterwards.

For that reason, a successful audit or preflight is not mutation authority on a shared or adversarially administered host. The supported guarantee requires an administratively controlled authority domain in which privileged network and mount mutators cooperate with these locks. The final exact-tree interruption and privileged lifecycle matrices passed within that boundary; they do not broaden it.
