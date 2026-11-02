# Nord Tools development plan

This document tracks the agreed sequence of work. It distinguishes completed foundations from work that has not yet been implemented or accepted. Update the status and acceptance notes as each increment is delivered. Do not mark live networking features complete on the strength of offline tests alone.

## Current position

The benchmarking, offline planning, read-only discovery, configured-state graph and Operation Kongroo foundations are complete. The operational VPN manager is in progress. Completed work is summarised below; this TODO retains outstanding requirements rather than repeating every accepted implementation task.

## Operational VPN manager: nine-part target

### Part 1: Disposable WireGuard integration harness (completed)

The opt-in disposable two-pair harness passed privileged connectivity and independent shutdown acceptance on Arch Linux. Crash and signal-interruption inspection remains an outstanding cross-cutting recovery check in Parts 6 and 8.

### Part 2: Resource ownership and lifecycle foundation (completed)

Offline lifecycle journalling, advisory locks, read-only identity correlation, operation intents and the privileged namespace smoke test are accepted. Part 7 has since delivered immutable creation-time owner records, verified reconciliation, boot restoration, confirmed cleanup and recovery, each with its own evidence rules; the remaining production ownership boundary is tracked below and in Parts 3, 6, 7 and 8.

### Part 3: Live tunnel provisioning

- [x] Extend the disposable two-pair experiment with read-only validation of a fresh peer handshake and bidirectional traffic counters. This is experimental connectivity evidence, not production provisioning or ownership verification.
- [x] Phase 1 foundation: validate disposable WireGuard tunnel specifications and produce credential-free offline plans. This is not privileged provisioning.
- [ ] Production Phase 1 ownership requirement: establish independently authorised, crash-persistent creation-time ownership. Durable intents and descriptor-based credential input exist, but neither authorises production mutation.
- [x] Introduce an internal experimental configuration step for WireGuard interfaces inside caller-owned disposable namespaces, without routes or production authority.
- [ ] Provision, verify, stop and reuse real WireGuard tunnels with securely handled provider credentials and server selection.
- [ ] Support shared profiles, explicitly isolated profiles and a default connection.
- [ ] Integrate platform/dependency preflight and conservative privilege boundaries.
- [x] Add experimental Phase 3 failure-injection coverage for process interruption, verifier errors, uncertain namespace retirement and failed uncertainty persistence. These tests do not establish crash-safe recovery or production ownership.
- [ ] Complete Part 3 privileged failure/recovery acceptance and resolve race-safe ownership before treating the executors as production-authoritative. Operator-confirmed cleanup and recovery exist; adversarial ownership testing under racing privileged actors remains.

### Part 4: Fail-closed routing, firewall and DNS (experimental programme completed)

The disposable namespace firewall, synthetic DNS drop, resolver visibility, simulated DNS route, IPv4/IPv6 endpoint exception and two-pair WireGuard host-integrity probes passed privileged acceptance on Arch Linux. These results do not establish production fail-closed behaviour.

- [ ] Verify real-tunnel IPv4/IPv6 DNS packet confinement and endpoint restrictions in privileged end-to-end tests.
- [ ] Demonstrate no unprotected fallback during real tunnel loss, restart or failed establishment.
- [ ] Complete firewall/DNS failure injection and production rollback verification, including host isolation.

### Part 5: Per-application routing (offline programme completed; operational integration outstanding)

Offline registered-application routing plans (Increment 5.1), logical binding/reference lifecycle planning (Increment 5.2), fail-closed launch request preparation (Increment 5.3), offline application session/namespace requirement modelling (Increment 5.4), and logical binding/session consistency auditing (Increment 5.5) are complete. These offline foundations do not authorise process launch, namespace mutation or kernel resource removal. The five-increment offline programme is complete, but Part 5 operational routing remains open pending production integration and privileged acceptance.

- [ ] Route assigned applications through their profiles, with unassigned applications inheriting the default.
- [ ] Reuse shared tunnels while maintaining isolation for dedicated profiles.
- [ ] Validate application launch/lifecycle, namespace behaviour and compatibility with common Linux desktop environments.

### Part 6: Live reconciliation and recovery (offline programme completed; operational integration outstanding)

Increment 6.1 adds an offline reconciliation evidence gate that rejects stale, conflicting or missing observations. Increment 6.2 adds ordered transaction checkpoint validation and conservative interruption-recovery assessments. Increment 6.3 adds offline staged-replacement planning that preserves existing allocations and refuses cut-over or retirement without privileged proof. Increment 6.4 adds conservative offline drift classification, including quarantine of unexpected resources and ownership-conflict blocking. Increment 6.5 adds a non-authorising cross-contract audit of reconciliation, drift, recovery and replacement reports. The five-increment offline Part 6 programme is complete; live reconciliation is not. None of these reports grants privileged mutation, resume, rollback or deletion authority. The three operational requirements below remain open and depend on the production ownership boundary.

- [ ] Implement idempotent apply/update/replace/remove against observed and owned state, without blind resource creation. Part 7.2 derives actual state from verified ownership evidence and classifies convergence idempotently, Part 7.3 performs idempotent creation of absent desired resources, and Part 7.4 performs removal of verified resources under the confirmed cleanup; live update and replacement authorities remain outstanding.
- [ ] Stage replacements, verify before cut-over, and preserve unaffected application tunnels.
- [ ] Implement rollback, drift repair and recovery after partial failure or interrupted live operations. Interrupted-creation and interrupted-cleanup recovery are the Part 7.5 recovery executors; live rollback and drift repair remain open.

### Part 7: Startup persistence and safe cleanup

- [x] Increment 7.1: durable creation-time ownership records, privileged verification and interrupted-creation recovery preflight, with batch-level rejection of foreign or uncertain resources. Offline tests and the privileged acceptance probe (`sudo python tools/probe_ownership_preflight.py --run-privileged`) passed on the user's Arch Linux test system. Boot-session continuity is a documented limit, not an unforgeable certificate.
- [x] Increment 7.2: read-only persistent desired-state reconciliation. Actual per-profile state is derived from verified ownership evidence, configuration drift is only detectable through recorded provisioned configuration, and every non-converged outcome is a plan — never an execution. Transient intent is structurally excluded.
- [x] Increment 7.3: systemd restoration of persistent desired state. `manage startup-plan` and `startup-install` render and install `nord-tools-restore.service` with `network-online.target` ordering and persistent-only path conditions; `manage restore-startup` runs an authorised, journal-gated boot executor which reconciles against a fresh ownership preflight, provisions only pinned profiles whose owned resources are absent in the current boot session, retires journal records for resources a reboot lost, records owner bindings at creation time and appends a bounded startup run record per boot. Transient intent is rejected outright. A failed attempt rolls back only its own namespace, records failed lifecycle evidence and leaves its intent uncertain. The restoration probe (`sudo python tools/probe_restore_startup.py --run-privileged`) passed creation-time binding and repeat-convergence checks on the user's Arch Linux test system after corrective iterations; the default profile's host-domain routing, provider server selection at boot, and real-tunnel DNS/IPv6 conformance remain open and are reported rather than restored.
- [x] Increment 7.4: ownership-aware cleanup and reset. `manage cleanup` plans and, on explicit confirmation, executes verified-resource removal with dry-run default, `--intents` required for execution, whole-profile refusal on any disputed ownership evidence, preserved desired profiles and unclaimed foreign observations, dependents-before-prerequisites deletion ordering, recorded owner identity re-verified at the moment of each deletion, observed-absence confirmation before retirement, and nothing ever flushed on the host outside owned namespaces and interfaces. `manage clear-ownership` performs the confirmed full reset and byte-verified archives of the four ownership stores before re-creating them empty. The cleanup probe (`sudo python tools/probe_cleanup.py --run-privileged`) still requires a successful privileged rerun against the corrected source; interrupted-cleanup resume belongs to Part 7.5.
- [x] Increment 7.5: crash, restart and interrupted-cleanup recovery. `manage recovery` plans and, on operator confirmation, resolves the interrupted evidence left by process death: the boot wall inside every `restore-startup` completes certified bookkeeping, rolls back a half-built creation recorded with a pending intent and resolves records for absent resources, while the operator's execution adds resume of confirmed retirements and evidence-gated resolution of uncertain intents. Lookalikes, unbound live resources and mixed evidence are reviewed, never touched, and profiles are classified whole around lookalikes so no executable item shares evidence with a lookalike. Recovery is idempotent and host-isolated in the same way as every other executor. Privileged acceptance with real process death is provided via `sudo python tools/probe_recovery.py --run-privileged`, which kills restore children at escalating delays until genuinely uncertain stores exist, converges through boot and operator recovery, and finishes with the confirmed cleanup.
- [x] Increment 7.6: integrated persistence and cleanup acceptance. `tools/probe_part7_acceptance.py --run-privileged` runs the whole workflow as one matrix: two pinned profiles restore while a different transient policy is configured and proven inert, restore children are killed mid-flight until real interrupted evidence exists and recovery converges both profiles, removing an application reference is pure bookkeeping, the authorised cleanup retires exactly the departed profile's resources while the shared profile's generation survives untouched, repeat runs converge without kernel changes, and host IPv4/IPv6 routes, nftables rules and resolver contents are compared across every stage boundary. The two evidence seams the matrix exposed are fixed: retired allocations without bindings classify as consistently retired, and the 7.2 configuration agreement counts the live generation only.
- [ ] Complete privileged acceptance of cleanup, recovery and the integrated Part 7 matrix against the corrected source, record the results, and design the host-domain default profile's protective routing. Ownership preflight and restoration have passed on the user's Arch Linux test system. The outstanding hand-off list for Part 8 is printed by the 7.6 matrix and recorded below under the production ownership boundary.

### Part 8: Production integration and security acceptance

Part 8.1 is planned as six increments: 8.1.1 authority preflight, 8.1.2 descriptor-anchored inspection, 8.1.3 shared lifecycle locking and state continuity, 8.1.4 kernel identity and mutation authority, 8.1.5 adversarial race hardening, and 8.1.6 privileged integration acceptance. The read-only inspector remains diagnostic and cannot authorise mutation. The restoration, cleanup and recovery executors now share a descriptor-relative single-flight lock with identity and directory-continuity checks. This serialises cooperating executors, but does not make multi-file state transitions atomic or defend against hostile directory replacement after verification. Independent kernel ownership, hostile-process races and privileged acceptance remain production blockers.

- [ ] Complete 8.1.4 kernel resource identity and mutation authority. Descriptor lifetime is corrected and verification now rejects invalid bound names and non-regular held descriptors; namespace pathname replacement and atomic host-interface mutation identity remain unproven and must be resolved before acceptance. The host-interface executor now refuses changed name/index mappings and uses a direct indexed rtnetlink deletion with kernel acknowledgement, but index reuse between observation and mutation remains possible and is not an atomic ownership compare-and-delete guarantee.

### Part 8 acceptance requirements

- [ ] Run unit, integration, failure-injection, repeatability and privilege-boundary tests, including two simultaneous real tunnels.
- [ ] Run Ruff check/format and full automated tests on the user's Arch Linux environment; record manual acceptance results.
- [ ] Review README, command help and design documentation for internal consistency and natural formal British English (formality 7–8/10).
- [ ] Confirm operational claims against evidence; leave unresolved safety issues open rather than declaring completion.

### Part 9: Final documentation reconciliation, hardening and consistency

- [ ] Audit documentation, command help, security claims, tests and implementation for consistency.
- [ ] Remove obsolete or redundant material without losing outstanding requirements or historical acceptance boundaries.
- [ ] Re-run all quality gates and privileged acceptance checks appropriate to the final release candidate.

The nine-part schedule is a planning limit, **not a waiver of safety requirements**. If privileged tests or leak-prevention checks fail, the manager remains incomplete until those issues are resolved. Do not start further discretionary features until the operational manager has met its acceptance criteria.

## Outstanding production ownership and recovery boundary

Part 2's offline lifecycle foundations and the Part 7 executors have automated coverage, with ownership preflight and restoration additionally accepted on the user's Arch Linux test system, but they do not satisfy adversarial race-safe ownership: bind continuity holds within one boot session, and a hostile process with store-directory access stays outside the evidence model. Before claiming production authority, require privileged adversarial tests and the live update and replacement authorities. Resource names, journal claims, inode fingerprints and completed intents remain insufficient deletion authority on their own.

- [ ] Bind durable intents and independent creation-time ownership evidence into an authorised privileged WireGuard executor with a transactional, crash-recoverable state model. The 7.1 owner-record preflight supplies the binding record and verification layer, Part 7.3's boot restoration executor consumes both for transactional provisioning of absent resources, Part 7.4 adds the confirmed verified cleanup, and Part 7.5 resolves interrupted evidence conservatively; the remaining executor authority (live update and replacement cut-over over verified resources) remains outstanding.
- [x] Connect the journal-gated creation adapter (durable intent before the privileged callback, verified completion afterwards) to the executors without granting mutation authority to offline plans: the 7.3 restoration path runs through it, and the 7.4 cleanup path applies the same gate to every retirement.
- [ ] Integrate namespace resolver installation into the authorised lifecycle: the saved policy carries no DNS data yet, so restoration installs no resolver file, and removal stays scope-limited to the exactly shaped `/etc/netns` directory of a verified namespace.
- [ ] Prove actual DNS packet confinement through WireGuard, including IPv6, application DNS bypass attempts, tunnel loss and failed establishment.
- [ ] Verify real WireGuard endpoint exceptions and production failure-injection recovery before claiming fail-closed behaviour.
