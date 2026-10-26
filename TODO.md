# Nord Tools development plan

This document tracks the agreed sequence of work. It distinguishes completed foundations from work that has not yet been implemented or accepted. Update the status and acceptance notes as each increment is delivered. Do not mark live networking features complete on the strength of offline tests alone.

## Current position

- [x] Benchmarking and unified `nord_tools.py` entry point.
- [x] Offline policy validation, persistent-by-default saved intent and `--transient` scope.
- [x] Offline topology, reconciliation, dependency, transaction and cleanup planning.
- [x] Read-only Linux discovery, allocation records and advisory ownership evidence.
- [x] Configured-state Unicode/ASCII connection graph.
- [x] Operation Kongroo terminal puzzle implemented, with encrypted scene data, cinematic ANSI/Unicode reveal, terminal restoration and accessibility fallbacks.
- [ ] **In progress:** Operational VPN manager, targeted for no more than eight parts, subject to safety and acceptance evidence.

## Bonus increment: Operation Kongroo

- [x] Add a hidden but discoverable, clue-driven command and encrypted transmission, themed around *El Psy Kongroo*.
- [x] Provide a terminal-only ANSI/Unicode reveal with ASCII, no-colour, non-interactive and reduced-motion fallbacks.
- [x] Keep the feature entirely separate from networking, credentials and privileged operations; restore terminal state on interruption.
- [x] Test puzzle decoding, output determinism/fallbacks, terminal cleanup and ordinary CLI behaviour; document the feature discreetly without publishing its solution.

## Operational VPN manager: eight-part target

### Part 1: Disposable WireGuard integration harness
- [x] Implement an opt-in disposable two-pair WireGuard harness without changing host default routing. Privileged two-pair connectivity acceptance passed on Arch Linux.
- [x] Validate bounded interface names and invocation-scoped cleanup in offline tests. Crash and signal-interruption acceptance remains pending.
- [x] Verify independent tunnel connectivity and tunnel-down isolation on Arch Linux. Explicit post-run namespace/interface inspection and crash/signal failure injection remain follow-up acceptance checks.

### Part 2: Resource ownership and lifecycle foundation
- [x] Establish process-bound identity evidence for newly created disposable namespaces; this is not durable ownership authority.
- [x] Introduce a strict, versioned offline lifecycle journal with allocation-bound event digests, transition validation, atomic fixture persistence and conservative simulated observation comparisons.
- [x] Add read-only live namespace/interface correlation for lifecycle claims, reporting missing, ambiguous and potentially stale names without granting ownership authority.
- [x] Add a stable advisory inter-process lock and serialised, atomic offline lifecycle transitions for cooperating writers.
- [x] Add offline interface-index fingerprint comparison against complete read-only discovery, reporting name reuse and scope drift without treating matches as ownership proof.
- [x] Record offline create/retire operation intents for recovery review, without treating them as privileged operation journals.
- [x] Keep offline lifecycle observations non-authoritative and prohibit any modification or deletion based on names, journal claims or matching simulated identifiers alone.
- [x] Pass the normal-operation privileged namespace smoke test on Arch Linux and verify that no named namespaces remain.
- [x] Move internal management and lifecycle modules into `nord_tools_internal/` without changing the public CLI.

### Part 3: Live tunnel provisioning
- [x] Extend the disposable two-pair experiment with read-only validation of a fresh peer handshake and bidirectional traffic counters. This is experimental connectivity evidence, not production provisioning or ownership verification.
- [x] Phase 1 foundation: validate disposable WireGuard tunnel specifications and produce credential-free offline plans. This is not privileged provisioning.
- [ ] Phase 1 completion: implement securely authorised creation-time ownership and durable intent recording before any privileged mutation. A single-use descriptor-based private-key input boundary is implemented, but no privileged executor exists yet.
- [ ] Provision, verify, stop and reuse real WireGuard tunnels with securely handled provider credentials and server selection.
- [ ] Support shared profiles, explicitly isolated profiles and a default connection.
- [ ] Integrate platform/dependency preflight and conservative privilege boundaries.

### Part 4: Fail-closed routing, firewall and DNS
- [ ] Enforce IPv4 and IPv6 traffic isolation, safe underlay exceptions and DNS confinement.
- [ ] Demonstrate no fallback to the unprotected route during tunnel loss, restart or failed establishment.
- [ ] Test firewall and DNS failure injection, and preserve unrelated host networking.

### Part 5: Per-application routing
- [ ] Route assigned applications through their profiles, with unassigned applications inheriting the default.
- [ ] Reuse shared tunnels while maintaining isolation for dedicated profiles.
- [ ] Validate application launch/lifecycle, namespace behaviour and compatibility with common Linux desktop environments.

### Part 6: Live reconciliation and recovery
- [ ] Implement idempotent apply/update/replace/remove against observed and owned state, without blind resource creation.
- [ ] Stage replacements, verify before cut-over, and preserve unaffected application tunnels.
- [ ] Implement rollback, drift repair and recovery after partial failure or interrupted operations.

### Part 7: Startup persistence and safe cleanup
- [ ] Restore persistent desired configuration using systemd with safe boot ordering; do not restore `--transient` intent.
- [ ] Provide dry-run and confirmed cleanup that removes only verified Nord Tools-owned resources and restores prior state where appropriate.
- [ ] Test restart, idempotency, interrupted cleanup and recovery without flushing host firewall or routing configuration.

### Part 8: Acceptance, security and documentation
- [ ] Run unit, integration, failure-injection, repeatability and privilege-boundary tests, including two simultaneous real tunnels.
- [ ] Run Ruff check/format and full automated tests on the user's Arch Linux environment; record manual acceptance results.
- [ ] Review README, command help and design documentation for internal consistency and natural formal British English (formality 7–8/10).
- [ ] Confirm operational claims against evidence; leave unresolved safety issues open rather than declaring completion.

## Acceptance and delivery rules

Each increment must include a complete source archive without Git metadata or Python cache artefacts, a revision-specific British English commit message, meaningful tests, documentation updates and explicit local acceptance instructions. Preserve the canonical working tree and existing behaviour. Keep README guidance concise, with architectural detail in `docs/VPN-ROUTING-DESIGN.md`.

The eight-part schedule is a planning limit, **not a waiver of safety requirements**. If privileged tests or leak-prevention checks fail, the manager remains incomplete until those issues are resolved. Do not start further discretionary features until the operational manager has met its acceptance criteria.

## Part 2 closure and operational safety boundary

Part 2 foundations and internal package organisation are complete. The normal-operation disposable namespace probe passed on Arch Linux, but does not establish persistent ownership or race-safe deletion. Before enabling any live mutation or automated cleanup that relies on ownership, implement and verify crash-persistent resource ownership and race-safe mutation authority, including interrupted-operation recovery and privileged adversarial integration tests. Do not infer deletion authority from resource names, journal records, inode fingerprints or completed operation intents alone. These requirements remain blockers for the relevant operational actions in subsequent parts.

- [ ] Bind durable intent recording and creation-time ownership evidence into a privileged WireGuard executor, with crash recovery and a transactional state model before any kernel mutation.
