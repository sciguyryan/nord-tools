# Release acceptance evidence matrix

This matrix is the QA inventory for the outstanding requirements in [`TODO.md`](../TODO.md). It records where executable evidence exists and, separately, whether the complete release requirement has been accepted. A probe's existence, a successful dry run or a component-level pass is not evidence that the combined production configuration is safe. The project follows the [cooperating-process authority boundary](PRIVILEGED-AUTHORITY-BOUNDARY.md); independent hostile privileged mutators are not a release acceptance target.

## Evidence conventions

- **Static** means source inspection, automated tests, Ruff or Markdown lint. It cannot establish live kernel packet behaviour.
- **Guest** means privileged disposable Arch Linux acceptance using [`scripts/acceptance-manager.py`](../scripts/acceptance-manager.py), with passt networking. It does not imply acceptance on the operator's host.
- **Platform** means separately recorded acceptance on a supported deployment configuration, including relevant systemd, desktop, network-manager and kernel versions.
- **Partial** means relevant implementation or a narrower successful probe exists, but the complete requirement remains open. **Pending** means no qualifying acceptance evidence for the complete requirement is recorded here. Both are release blockers unless an explicit release-scope decision removes the requirement.

The 9 November 2026 guest run passed 1,224 pytest cases, 357 subtests, Ruff lint and formatting, Markdown lint and both privileged matrices. The guest runner executes [`probe_network_isolation_adversarial_acceptance.py`](../tools/probe_network_isolation_adversarial_acceptance.py) and [`probe_application_lifecycle_acceptance.py`](../tools/probe_application_lifecycle_acceptance.py). The network matrix ran the platform-contract probe, and both matrices reached the owned dual-stack profile whose real restoration path invokes the same preflight. The application matrix additionally ran the production registered gate against provisioned generations A and B. Its other component stages retain their narrower scopes and do not establish the concurrent registered packet or desktop requirements.

## Outstanding requirement matrix

| ID | Acceptance target and available evidence | Required level | State |
| --- | --- | --- | --- |
| B1 | [`Production profile confinement`](../tools/probe_production_wireguard_confinement.py) installs one owned dual-stack WireGuard profile through the restoration executor, verifies its production nftables policy, both live address families, routes, pinned resolver and endpoint-port refusal, then performs ownership-aware retirement and checks host integrity. | Guest | Accepted |
| B2 | Real IPv4/IPv6 application DNS exchanges, reachable dual-stack underlay TCP/UDP and alternative DNS bypass refusal, and tunnel-down fail-closed checks in the production-owned profile via [`production WireGuard confinement`](../tools/probe_production_wireguard_confinement.py). | Guest | Accepted |
| B3 | The production profile injects late establishment failure, closes its uncertain rolled-back generation through explicit recovery, refuses unavailable-peer and established-tunnel fallback, restarts live dual-stack traffic, rejects malformed firewall and unsafe resolver observations, and checks host integrity. [`Later recovery`](../tools/probe_later_recovery.py) separately kills provisioning after underlay, WireGuard and routing checkpoints inside the same enclosing matrix. | Guest | Accepted |
| B4 | The [supported network platform](SUPPORTED-NETWORK-PLATFORM.md) pins the accepted Arch kernel, iproute2, nftables and WireGuard-tools profile. A pre-mutation probe verifies versions, live `ip` and `nft` JSON shapes, safe WireGuard field output and trusted resolver storage; malformed and unsupported variants are refused. | Guest + Platform | Accepted for the documented Arch profile |
| C1 | The [`application lifecycle runner`](../tools/probe_application_lifecycle_acceptance.py) invokes the production registered VPN-bound launch gate against real provisioned A/B generations. It checks the executed child's namespace and non-root identity, exact durable generation lease, refusal without provisioned authority and lease removal after verified process exit. | Guest | Accepted |
| C2 | Concurrent shared, isolated and direct registered launches, lease-protected retirement and no VPN fallback; [`routing modes`](../tools/probe_application_routing_modes.py) and [`isolated retirement`](../tools/probe_isolated_consumer_retirement.py) are narrower evidence. | Guest | Partial; blocker |
| C3 | Concurrent real VPN-bound and direct applications with dual-stack DNS/leak checks through tunnel loss; [`application confinement`](../tools/probe_application_network_confinement.py) is narrower evidence. | Guest | Partial; blocker |
| C4 | Desktop launch environment, descendants and identity/privilege propagation on selected supported desktop stack. | Platform | Pending; blocker |
| D1 | Host-domain deny-first protection with live endpoint, route and resolver packet evidence on supported static-egress guest; [`host default lifecycle`](../tools/probe_host_default_lifecycle.py) is a starting probe, not this acceptance. | Guest | Partial; blocker |
| D2 | Host-domain failure, interruption, uncertain readback, barrier-last deactivation and integrity restoration. | Guest | Partial; blocker |
| D3 | Actual reboot and systemd early-barrier/network-online ordering, convergence and recovery; [`restore startup`](../tools/probe_restore_startup.py) and [`restoration lifecycle`](../tools/probe_startup_restoration_lifecycle.py) do not substitute for a real reboot. | Guest | Partial; blocker |
| D4 | Explicit supported host-network configuration and exclusions for competing managers; additional configurations only if selected. | Platform + QA decision | Pending; blocker |
| E1 | Provider credential acquisition, validation, rotation, secret redaction and fastest/country selection including boot failure behaviour. | Static + Guest | Pending; blocker |
| E2 | Default/shared/isolated live provider-profile operation; [`selected profile retirement`](../tools/probe_selected_profile_retirement.py) and [`generation replacement`](GENERATION-REPLACEMENT-ACCEPTANCE.md) are narrower evidence. | Guest + Platform | Partial; blocker |
| E3 | Decide whether general in-place updates are supported; if yes, implement and verify evidence-gated mutation. Existing generation replacement does not close this. | QA decision + Guest if implemented | Pending; decision/blocker |
| E4 | Disputed-resource drift refusal and operator recovery; any automated repair requires independently verified ownership. | Static + Guest | Partial; blocker |
| E5 | Supported dependency, platform and privilege preflight with non-mutating unsupported-environment refusal. | Static + Guest + Platform | Partial; blocker |
| F1 | End-to-end cooperating-process lock, ownership and interruption audit with targeted regressions for discovered gaps. | Static + Guest | Partial; blocker |
| F2 | Consistent CLI help, diagnostics, README and security statements against final observed behaviour. | Static + QA | Partial; blocker |
| F3 | Supported kernel, systemd, resolver, nftables, WireGuard and desktop support matrix with evidence. | Platform + QA | Pending; blocker |
| F4 | Complete exact-tree Ruff, formatting, pytest, Markdown and relevant privileged guest acceptance with retained run outputs. | Static + Guest | Pending for final candidate; blocker |
| F5 | Final release-readiness decision, limitations, packaging hygiene and unresolved-blocker disposition. | QA | Pending; blocker |

## Recording and closing evidence

For each requirement, QA should retain the candidate revision or archive digest, exact invocation, environment (guest image and relevant kernel/tool versions), test/probe identifiers, result and date, plus failure artefacts where relevant. A successful run of a component probe may update its **available evidence**, but does not change the requirement's state to accepted unless its stated target was actually exercised. A failure remains visible until corrected and rerun. No test should embed a hard-coded project-wide list of unfinished features; this document and `TODO.md` own that assessment.

The final release decision must separately address all blockers and any scope exclusions. A support limitation is not equivalent to a passing test, and a scope change must be explicit rather than silently deleting a requirement.

### B1 production-profile acceptance

On 8 November 2026, `tools/probe_production_wireguard_confinement.py --run-privileged` passed in the disposable Arch Linux guest. The production restoration executor installed one owned profile with canonical IPv4 and IPv6 tunnel addresses, the production firewall, both default routes and a pinned namespace resolver. Live traffic succeeded over both address families. The probe also verified endpoint-port refusal, ownership-aware retirement and unchanged host IPv4/IPv6 routes, nftables rules and resolver contents. B1 is accepted within that disposable guest scope.

### B2 and B3 production failure-confinement acceptance

On 9 November 2026, the production profile probe passed application-selected IPv4 and IPv6 DNS exchanges, reachable underlay TCP/UDP and alternative DNS bypass refusal. It then injected a routing-stage establishment failure after the real firewall, underlay and WireGuard device existed. Rollback removed the attempted generation without host drift; boot retained its conservative operator wall, and explicit recovery closed the freshly observed absent generation before a new profile was restored.

With the recovered production profile active, an unavailable peer remained fail closed, live traffic subsequently crossed both tunnel families, malformed nftables JSON and a multiply linked namespace resolver were refused, and established peer loss blocked DNS and underlay fallback. Restarting the peer restored IPv4, IPv6 and application DNS within a bounded handshake window. Verified retirement returned host routes, nftables configuration and resolver contents to their baseline. In the enclosing adversarial matrix, SIGKILL after underlay, WireGuard and routing checkpoints also converged through the existing recovery authority without host drift. B2 and B3 are accepted within this disposable guest and cooperating-process authority scope. B4 has the separate, narrower platform profile recorded below.

### B4 supported platform acceptance

On 9 November 2026, `tools/probe_platform_compatibility.py --run-privileged` accepted Linux `7.2.11-arch1-1`, iproute2 `7.3.0`, nftables `1.1.7` and wireguard-tools `1.0.20260223` before the complete production routing and failure-confinement stages passed on the same guest. The probe verified live loopback and dual-stack route JSON, nftables ruleset JSON, safe WireGuard interface readback and the `/etc/netns` ownership and mode contract without changing networking.

Automated refusal tests cover different or unrecognised versions, invalid link and route JSON, an unexpected nftables document, malformed WireGuard interface output and unsafe resolver storage. Real startup restoration invokes this preflight before creating state stores or constructing its production kernel surface. B4 is accepted only for the documented Arch profile. Other combinations remain unsupported until the same exact-tree quality and privileged matrices are recorded; the wider final platform and desktop matrix remains open.
