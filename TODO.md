# Nord Tools development plan

This document tracks the agreed sequence of work. It distinguishes completed foundations from work that has not yet been implemented or accepted. Update the status and acceptance notes as each increment is delivered. Do not mark live networking features complete on the strength of offline tests alone.

## Current position

The benchmarking, offline planning, read-only discovery, configured-state graph and Operation Kongroo foundations are complete. The operational VPN manager is in progress. Completed work is summarised below; this TODO retains outstanding requirements rather than repeating every accepted implementation task.

## Operational VPN manager: eight-part target

### Part 1: Disposable WireGuard integration harness (completed)

The opt-in disposable two-pair harness passed privileged connectivity and independent shutdown acceptance on Arch Linux. Crash and signal-interruption inspection remains an outstanding cross-cutting recovery check in Parts 6 and 8.

### Part 2: Resource ownership and lifecycle foundation (completed)

Offline lifecycle journalling, advisory locks, read-only identity correlation, operation intents and the privileged namespace smoke test are accepted. These foundations do not grant crash-persistent ownership or production deletion authority. The remaining production ownership boundary is tracked below and in Parts 3, 6 and 7.

### Part 3: Live tunnel provisioning

- [x] Extend the disposable two-pair experiment with read-only validation of a fresh peer handshake and bidirectional traffic counters. This is experimental connectivity evidence, not production provisioning or ownership verification.
- [x] Phase 1 foundation: validate disposable WireGuard tunnel specifications and produce credential-free offline plans. This is not privileged provisioning.
- [ ] Production Phase 1 ownership requirement: establish independently authorised, crash-persistent creation-time ownership. Durable intents and descriptor-based credential input exist, but neither authorises production mutation.
- [x] Introduce an internal experimental configuration step for WireGuard interfaces inside caller-owned disposable namespaces, without routes or production authority.
- [ ] Provision, verify, stop and reuse real WireGuard tunnels with securely handled provider credentials and server selection.
- [ ] Support shared profiles, explicitly isolated profiles and a default connection.
- [ ] Integrate platform/dependency preflight and conservative privilege boundaries.
- [x] Add experimental Phase 3 failure-injection coverage for process interruption, verifier errors, uncertain namespace retirement and failed uncertainty persistence. These tests do not establish crash-safe recovery or production ownership.
- [ ] Complete Part 3 privileged failure/recovery acceptance and resolve race-safe ownership before enabling production resource deletion or automated cleanup.

### Part 4: Fail-closed routing, firewall and DNS (experimental programme completed)

The disposable namespace firewall, synthetic DNS drop, resolver visibility, simulated DNS route, IPv4/IPv6 endpoint exception and two-pair WireGuard host-integrity probes passed privileged acceptance on Arch Linux. These results do not establish production fail-closed behaviour.

- [ ] Verify real-tunnel IPv4/IPv6 DNS packet confinement and endpoint restrictions in privileged end-to-end tests.
- [ ] Demonstrate no unprotected fallback during real tunnel loss, restart or failed establishment.
- [ ] Complete firewall/DNS failure injection and production rollback verification, including host isolation.

### Part 5: Per-application routing

Offline registered-application routing plans (Increment 5.1), logical binding/reference lifecycle planning (Increment 5.2), fail-closed launch request preparation (Increment 5.3), and offline application session/namespace requirement modelling (Increment 5.4) are complete. These offline foundations do not authorise process launch, namespace mutation or kernel resource removal.

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

The eight-part schedule is a planning limit, **not a waiver of safety requirements**. If privileged tests or leak-prevention checks fail, the manager remains incomplete until those issues are resolved. Do not start further discretionary features until the operational manager has met its acceptance criteria.

## Outstanding production ownership and recovery boundary

Part 2's offline lifecycle foundations and the disposable privileged probes are accepted, but they do not establish persistent ownership or race-safe deletion. Before production mutation or automated cleanup, require independently authorised, crash-persistent creation-time ownership, atomic lifecycle coordination, interrupted-operation recovery and privileged adversarial tests. Resource names, journal claims, inode fingerprints and completed intents are not sufficient deletion authority.

- [ ] Bind durable intents and independent creation-time ownership evidence into an authorised privileged WireGuard executor with a transactional, crash-recoverable state model.
- [ ] Connect the journal-gated experimental adapter to that executor without granting mutation authority to offline plans or simulated observations.
- [ ] Integrate exclusive namespace resolver installation into the authorised lifecycle with verified ownership and cleanup semantics.
- [ ] Prove actual DNS packet confinement through WireGuard, including IPv6, application DNS bypass attempts, tunnel loss and failed establishment.
- [ ] Verify real WireGuard endpoint exceptions and production failure-injection recovery before claiming fail-closed behaviour.
