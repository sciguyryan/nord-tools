# Release acceptance evidence matrix

This matrix is the QA inventory for the outstanding requirements in [`TODO.md`](../TODO.md). It records where executable evidence exists and, separately, whether the complete release requirement has been accepted. A probe's existence, a successful dry run or a component-level pass is not evidence that the combined production configuration is safe. The project follows the [cooperating-process authority boundary](PRIVILEGED-AUTHORITY-BOUNDARY.md); independent hostile privileged mutators are not a release acceptance target.

## Evidence conventions

- **Static** means source inspection, automated tests, Ruff or Markdown lint. It cannot establish live kernel packet behaviour.
- **Guest** means privileged disposable Arch Linux acceptance using [`scripts/acceptance-manager.py`](../scripts/acceptance-manager.py), with passt networking. It does not imply acceptance on the operator's host.
- **Platform** means separately recorded acceptance on a supported deployment configuration, including relevant systemd, desktop, network-manager and kernel versions.
- **Partial** means relevant implementation or a narrower successful probe exists, but the complete requirement remains open. **Pending** means no qualifying acceptance evidence for the complete requirement is recorded here. Both are release blockers unless an explicit release-scope decision removes the requirement.

The 8 November 2026 guest run passed 1,160 pytest cases, 357 subtests, Ruff lint and formatting, Markdown lint and both privileged matrices. The guest runner executes [`probe_network_isolation_adversarial_acceptance.py`](../tools/probe_network_isolation_adversarial_acceptance.py) and [`probe_application_lifecycle_acceptance.py`](../tools/probe_application_lifecycle_acceptance.py). Both reached the production provisioning integration runner and its owned dual-stack profile stage. The remaining component stages retain their narrower scopes: passing the composed runners does not turn separate application, DNS, recovery or lock fixtures into one end-to-end registered application test.

## Outstanding requirement matrix

| ID | Acceptance target and available evidence | Required level | State |
| --- | --- | --- | --- |
| B1 | [`Production profile confinement`](../tools/probe_production_wireguard_confinement.py) installs one owned dual-stack WireGuard profile through the restoration executor, verifies its production nftables policy, both live address families, routes, pinned resolver and endpoint-port refusal, then performs ownership-aware retirement and checks host integrity. | Guest | Accepted |
| B2 | Authorised and unauthorised DNS/transport destinations and application bypass attempts on the installed profile; existing [`DNS route`](../tools/probe_dns_route_confinement.py) and [`application network`](../tools/probe_application_network_confinement.py) probes do not establish this full path. | Guest | Partial; blocker |
| B3 | Establishment failure, loss, restart, uncertain readback and interruption must fail closed without host drift; [`later recovery`](../tools/probe_later_recovery.py) and [`host integrity`](../tools/probe_wireguard_host_integrity.py) are narrower evidence. | Guest | Partial; blocker |
| B4 | Supported kernel/tool versions and conservative readback/refusal semantics for nftables, routes and resolver. | Guest + Platform | Pending; blocker |
| C1 | Registered VPN-bound launch with correct namespace, generation, durable lease, non-root execution and exit-verified release; [`application lifecycle runner`](../tools/probe_application_lifecycle_acceptance.py) covers narrower components. | Guest | Partial; blocker |
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

On 8 November 2026, `tools/probe_production_wireguard_confinement.py --run-privileged` passed in the disposable Arch Linux guest. The production restoration executor installed one owned profile with canonical IPv4 and IPv6 tunnel addresses, the production firewall, both default routes and a pinned namespace resolver. Live traffic succeeded over both address families. The probe also verified endpoint-port refusal, ownership-aware retirement and unchanged host IPv4/IPv6 routes, nftables rules and resolver contents. B1 is accepted within that disposable guest scope. Application-level DNS bypass and establishment, loss and restart failures remain under B2 and B3.
