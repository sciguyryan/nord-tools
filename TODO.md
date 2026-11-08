# Nord Tools outstanding work

This is the canonical forward-looking work list. It contains requirements that are unfinished, incompletely verified or still require an explicit release decision. Completed implementation history belongs in Git, the changelog and the existing design and acceptance documents. A checked item was removed only when the source tree and available acceptance evidence supported its completion within the stated scope; an unproven remainder is retained below. Do not infer production security guarantees from offline or separate disposable component tests.

## Release authority boundary

The release target is the **cooperating-process authority model** described in `docs/PRIVILEGED-AUTHORITY-BOUNDARY.md`. Nord Tools executors share a protected lifecycle lock and verify ownership before privileged mutation. Independent privileged kernel/network/mount mutators, or actors deliberately bypassing that lock with equivalent authority, are outside the supported safety guarantee. Preserve fail-closed behaviour on uncertain evidence, document deployment isolation requirements and do not describe this boundary as atomic kernel-enforced ownership. Expanding the threat model requires a separate explicit decision, not an implicit release blocker.

## Current acceptance baseline and limits

The 7 November 2026 disposable Arch Linux guest run completed 1,135 pytest tests and 354 subtests, Ruff lint and formatting, Markdown lint and the privileged lifecycle, application, real WireGuard, dual-stack and DNS probe suites. The acceptance manager in `scripts/acceptance-manager.py` provisions the guest with passt userspace networking. This is evidence for the executed probe scopes, **not** for a combined production-installed tunnel/firewall/resolver application path, host-domain default protection, common desktop integration or every deployment environment. Maintain a current, source-linked evidence matrix in Phase A rather than repeating historical completion notes in this file.

## Phase A: Audit, documentation and acceptance reconciliation

- [ ] **A1: Verify the outstanding inventory against implementation and evidence.** Map each requirement to its implementation, deterministic tests, privileged probe and remaining gap. Where verification is not viable, retain the item and identify the missing evidence. Audit old checked items for partially completed promises rather than deleting their unresolved portions.
- [ ] **A2: Complete documentation, CLI help, diagnostics and test-name reconciliation.** The README implementation-status table and resolver descriptions now distinguish completed component acceptance from combined production verification. Audit remaining CLI help and diagnostic strings against actual execution paths, replace non-historical phase-based test identifiers and verify cross-references and Markdown anchors before closing this increment.
- [ ] **A3: Publish a release acceptance matrix.** Distinguish static checks, disposable privileged acceptance and platform-specific acceptance. Record the exact configuration and safety scope each test demonstrates, identify release blockers and keep failed or unverified guarantees visible.

## Phase B: Integrated production VPN confinement

- [ ] **B1: Exercise one production-installed, ownership-verified real WireGuard profile with its production nftables rules, IPv4/IPv6 routes and pinned namespace resolver active together.** Verify endpoint exceptions and live traffic, not merely separate component probes.
- [ ] **B2: Verify IPv4/IPv6 DNS packet confinement and application-level bypass resistance on that installed profile.** Test authorised resolver traffic, alternative DNS destinations, direct UDP/TCP attempts and the configured failure policy. Do not treat DNS-shaped disposable datagrams alone as complete application DNS acceptance.
- [ ] **B3: Prove fail-closed behaviour under failed establishment, tunnel shutdown/restart, malformed or uncertain firewall/resolver observations and interrupted provisioning.** Verify rollback, recovery and no host-route, host-firewall or host-resolver drift, including failure paths.
- [ ] **B4: Validate supported kernel and tooling combinations for production nftables readback, routing and resolver inspection.** Preserve conservative refusal where platform behaviour cannot be verified.

## Phase C: Registered application lifecycle and desktop behaviour

- [ ] **C1: Accept the actual production registered VPN-bound launch gate.** Verify namespace placement, generation and allocation selection, durable pre-execution lease reservation, non-root execution, refusal without authority and process-exit-verified release.
- [ ] **C2: Exercise concurrent launched applications.** Verify shared-tunnel reuse, independent isolated allocations, lease-protected retirement, explicit direct-network assignments and no direct fallback when VPN-bound launch fails.
- [ ] **C3: Run IPv4/IPv6 and application DNS/leak acceptance with real direct and VPN-bound processes running concurrently, including tunnel loss.** Distinguish the existing direct-child/packet-generator probe from a complete registered VPN-bound application path.
- [ ] **C4: Validate common Linux desktop launch environments and integration boundaries.** Cover environment propagation, child processes, identity/privilege transitions and desktop launch behaviour; identify any platform-specific limitations.

## Phase D: Host-domain default protection

- [ ] **D1: Accept the implemented host-domain protection lifecycle in a disposable guest with a supported static-egress configuration and no recognised competing manager.** Verify deny-first firewall activation, endpoint-specific underlay allowance, dual-stack policy routing and resolver state against live packet evidence.
- [ ] **D2: Prove failure and recovery guarantees.** Cover real tunnel loss, failed activation, interruption/process death, firewall and DNS readback uncertainty, barrier-last deactivation and preservation of host integrity.
- [ ] **D3: Exercise actual guest reboot and split early-barrier/network-online systemd restoration.** Check protected startup ordering, convergence and explicit recovery after interrupted transitions.
- [ ] **D4: Decide and document host-side deployment compatibility.** Do not silently claim support for hosts with competing VPN, firewall or network managers beyond the accepted static-egress boundary; test additional configurations only if support is explicitly selected.

## Phase E: Provider operations and live management

- [ ] **E1: Complete secure provider credential acquisition, validation and rotation, with no secrets in plans, logs, subprocess arguments or test artefacts.** Integrate provider endpoint/server selection, including fastest/country preferences where supported, and define deterministic failure behaviour at boot.
- [ ] **E2: Verify complete operational default, shared and isolated profile workflows with real provider configurations.** Distinguish the accepted named-profile and generation ownership foundations from unverified provider selection and live service behaviour.
- [ ] **E3: Define and implement general in-place live updates, if supported, using fresh owned-state inspection and evidence-gated apply/update semantics.** Existing create-only apply, generation-based replacement and verified removal are accepted; do not rebuild them or imply that disputed-resource drift is safe to repair automatically.
- [ ] **E4: Specify disputed-resource drift handling and operator recovery.** Preserve quarantine and refusal for uncertain ownership; implement repair only where independently verifiable evidence makes mutation safe within the cooperating-process model.
- [ ] **E5: Complete dependency, platform and privilege preflight for the supported operational configurations.** Keep unsupported environments explicit and non-mutating by default.

## Phase F: Final hardening and release readiness

- [ ] **F1: Audit cooperating-process races, lock continuity, creation-time ownership, interruption windows and uncertain-state handling across all production paths.** Add targeted tests for demonstrated gaps; do not promise resistance to independent privileged mutators.
- [ ] **F2: Reconcile all command help, security claims, design documents, README instructions and diagnostic output with observed behaviour.** Remove obsolete duplication while retaining security invariants and historical acceptance records in appropriate documents.
- [ ] **F3: Validate supported platform and desktop compatibility, including kernel, systemd, resolver, nftables and WireGuard dependencies, with a documented support matrix.**
- [ ] **F4: Run the complete release quality gates on the exact candidate tree:** `ruff check .`, `ruff format --check .`, pytest, Markdown lint and all relevant disposable privileged acceptance matrices. Record results, known limitations and any required platform-specific checks; do not label a candidate accepted before the necessary evidence exists.
- [ ] **F5: Produce a release-readiness assessment** identifying any unresolved security, operational or verification blockers, and verify release packaging excludes Git metadata and generated caches.

## Delivery rules

Complete one bounded increment at a time. Each change must preserve existing accepted behaviour, include appropriate regression coverage and a conventional-tagged Git commit message, and distinguish successful local/static checks from privileged guest results. Never mark a requirement complete merely because an earlier checkbox was ticked; require matching implementation and evidence, or retain the outstanding portion here.
