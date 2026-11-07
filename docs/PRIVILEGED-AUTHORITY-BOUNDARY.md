# Privileged mutation authority and threat boundary

## Supported authority model

Nord Tools coordinates cooperating restoration, cleanup and recovery processes using one journal-specific execution lock. The lock directory must belong to the effective execution identity and must not be writable by group or other users. A stable lock inode, descriptor-relative opening and directory continuity checks prevent accidental split-lock operation among cooperating processes using the same protected directory. A process with equivalent privileges that intentionally bypasses the lock is not a cooperating actor.

The kernel namespace descriptor and nsfs type attestation establish the identity of an observed network namespace. The owner-binding journal records the observed identity at creation. The cleanup executor also checks the observed host link name and index, then requests indexed rtnetlink deletion. The indexed rtnetlink deletion client validates the entire response datagram before accepting a matching kernel acknowledgement, including rejecting malformed trailing messages. These measures reject many stale, accidental or unprivileged substitutions. They are not atomic compare-and-delete operations.

## Excluded adversary and residual risk

An independent actor able to mount or replace network namespace entries with `CAP_SYS_ADMIN`, or delete, recreate and reuse interface indices with `CAP_NET_ADMIN`, can change kernel objects between verification and mutation. Neither `ip netns del NAME` nor `RTM_DELLINK` by index guarantees that the object deleted is the object previously verified. A filesystem lock cannot exclude a privileged actor who ignores it. Nord Tools must not describe these operations as safe against such actors or as having kernel-enforced exclusive ownership.

Consequently, privileged lifecycle execution is appropriate only within an administratively controlled host authority domain where competing privileged network/mount mutators are excluded by deployment policy and service isolation. This is an operational precondition, not a runtime proof: Nord Tools cannot discover every privileged actor or automatically certify that the condition holds. On shared or adversarially administered hosts, destructive operations must not be considered safe merely because preflight passes. Run privileged acceptance on a disposable-capable test system.

## Verification scope

Adversarial substitution tests and the privileged lifecycle matrix have passed within the cooperating-process authority model. These results do not establish kernel-enforced exclusion of independent privileged network or mount mutators. Broader production claims remain subject to that limitation.

## Deterministic adversarial coverage

The adversarial race validation regression suite injects lock inode replacement, journal-directory replacement, symlink substitution and insecure directory or hard-link state at the acquisition boundary. These checks demonstrate refusal before entering a protected operation for those specific substitutions. They do not establish continuous kernel-enforced authority once an operation has begun. Privileged namespace and link replacement tests must be performed on disposable resources in an administratively controlled test environment; testing with unrestricted competing privileged actors cannot turn the operational exclusion into a kernel guarantee.

Generation activation and application launch use the same lifecycle-then-consumer lock order. This makes the durable selected generation, fresh ownership check and process-bound lease reservation atomic with respect to cooperating Nord Tools processes. Old-generation retirement retains both locks through the cleanup executor's final ownership revalidation and mutation. This boundary does not prevent an unrelated privileged process from changing kernel objects, routes or nftables outside those locks; such interference is detected where fresh observation permits and otherwise remains outside the claimed authority model.

### Real-process lifecycle lock acceptance

Run `python tools/probe_lifecycle_lock_concurrency.py --run` on Linux to verify that a second cooperating process waits for the shared lock, inherits the lock after the first holder is killed, and preserves the same lock inode across later acquisitions. It additionally replaces the lock inode after a contender has opened the original and verifies that the waiting contender refuses execution when the original holder dies. This replacement test uses `/proc` to confirm the contender actually opened the original inode before substitution; it is not an assertion that a hostile directory owner cannot establish a second lock domain. The probe uses a disposable private directory and requires no root privileges or network changes. It does not test independent privileged resource replacement or establish kernel mutation authority.

## privileged lifecycle authority privileged acceptance

Run `sudo python tools/probe_provisioning_authority_acceptance.py --run-privileged` only on a disposable-capable Arch Linux test system. The runner executes ownership preflight, restoration, confirmed cleanup, interruption recovery and the integrated startup restoration and cleanup matrix sequentially; it stops at the first failure and preserves the individual probe’s diagnostic evidence. The default invocation is a dry run. Passing these tests establishes only the stated cooperating-process and disposable-resource guarantees, not atomic protection against independent privileged network or mount administrators. The real-process lifecycle lock substitution probe remains a separate non-privileged check: `python tools/probe_lifecycle_lock_concurrency.py --run`.

### privileged lifecycle acceptance deterministic recovery interruption

The recovery acceptance probe now interrupts its child at a test-only callback checkpoint immediately after the durable creation intent has been persisted and before that callback can create kernel resources. The probe child wraps the restoration adapter without adding a production environment-variable hook. This tests recovery from a pending intent at a precisely defined boundary, not recovery from an arbitrary partially constructed kernel ecosystem. If recovery cannot establish verified ownership or convergence, evidence is retained and no unverified resource is deleted. Existing resources from earlier failed acceptance runs must be inspected and reconciled separately before further privileged tests.
