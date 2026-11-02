# Privileged mutation authority and threat boundary

## Supported authority model

Nord Tools coordinates cooperating restoration, cleanup and recovery processes using one journal-specific execution lock. The lock directory must belong to the effective execution identity and must not be writable by group or other users. A stable lock inode, descriptor-relative opening and directory continuity checks prevent accidental split-lock operation among cooperating processes using the same protected directory. A process with equivalent privileges that intentionally bypasses the lock is not a cooperating actor.

The kernel namespace descriptor and nsfs type attestation establish the identity of an observed network namespace. The owner-binding journal records the observed identity at creation. The cleanup executor also checks the observed host link name and index, then requests indexed rtnetlink deletion. These measures reject many stale, accidental or unprivileged substitutions. They are not atomic compare-and-delete operations.

## Excluded adversary and residual risk

An independent actor able to mount or replace network namespace entries with `CAP_SYS_ADMIN`, or delete, recreate and reuse interface indices with `CAP_NET_ADMIN`, can change kernel objects between verification and mutation. Neither `ip netns del NAME` nor `RTM_DELLINK` by index guarantees that the object deleted is the object previously verified. A filesystem lock cannot exclude a privileged actor who ignores it. Nord Tools must not describe these operations as safe against such actors or as having kernel-enforced exclusive ownership.

Consequently, privileged lifecycle execution is appropriate only within an administratively controlled host authority domain where competing privileged network/mount mutators are excluded by deployment policy and service isolation. This is an operational precondition, not a runtime proof: Nord Tools cannot discover every privileged actor or automatically certify that the condition holds. On shared or adversarially administered hosts, destructive operations must not be considered safe merely because preflight passes. Run privileged acceptance on a disposable-capable test system.

## Remaining work

Part 8.1.5 must exercise hostile pathname replacement, lock-directory substitution, concurrent cooperating operations, interface-index reuse and interruption boundaries. It must distinguish demonstrated refusal from scenarios requiring an external privilege boundary. Part 8.1.6 must verify the complete privileged matrix. Production claims and deployment instructions must remain qualified until these checks pass; Part 9 will perform the final cross-document consistency audit.

## Deterministic adversarial coverage

The Part 8.1.5 regression suite injects lock inode replacement, journal-directory replacement, symlink substitution and insecure directory or hard-link state at the acquisition boundary. These checks demonstrate refusal before entering a protected operation for those specific substitutions. They do not establish continuous kernel-enforced authority once an operation has begun. Privileged namespace and link replacement tests must be performed on disposable resources in an administratively controlled test environment; testing with unrestricted competing privileged actors cannot turn the operational exclusion into a kernel guarantee.
