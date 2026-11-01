# Default VPN optimisation and application routing

The Nord Tools benchmarker currently ranks OpenVPN endpoints using ICMP or TCP probes. Its existing `--auto-connect` path operates on the ordinary NordVPN Linux client. That is useful for a single connection, but it does not establish independent per-application tunnels. We should not pretend that adding an application list to the current connection command would solve that problem.

The intended extension is a system-wide default VPN profile, with applications optionally assigned to independent profiles. An unassigned application inherits the default. A named override remains on its assigned tunnel when the default is optimised. Applications deliberately sharing the default profile are *not* independent overrides, and may experience a default-server change.

A profile should support a country pool (ISO country code), a pinned server, or a preferred server with an explicitly authorised fallback pool. Applications sharing a profile normally share a tunnel; independently isolated profiles can use different servers in the same country. Country and server availability must be established from real provider data. The existing benchmark filter grammar should be reused rather than replaced with an almost-identical policy language.

## First increment: offline planning

`nordvpn_policy.py` reads a version 1 JSON policy and an existing version 1 benchmark report. It produces an advisory candidate for the **default profile only**, using the existing filter grammar and ranking fields. It cannot connect, disconnect or change routes. This boundary is deliberate: the benchmark measures endpoint latency, not throughput through a live VPN tunnel, and the current NordVPN CLI cannot safely manage the proposed independent tunnels.

Example `vpn-policy.json`:

```json
{
  "version": 1,
  "defaults": {"vpn": "primary"},
  "vpn_profiles": {
    "primary": {
      "selection": {
        "mode": "fastest",
        "filter": "country:ad&protocol:udp",
        "minimum_improvement_ms": 10,
        "minimum_improvement_percent": 15
      }
    },
    "discord": {"selection": {"mode": "country", "country": "gb"}}
  },
  "applications": {"discord": {"executable": "/usr/bin/discord", "vpn": "discord"}}
}
```

The example is also available at [`../examples/vpn-policy.json`](../examples/vpn-policy.json). Validate the policy independently of a benchmark report:

```bash
python nordvpn_policy.py --policy examples/vpn-policy.json --validate
```

The validator recognises `fastest`, `country` and `pinned` selection modes, requires an existing default profile, checks application executable paths and rejects unknown configuration fields. `sharing: shared` is the default; `sharing: isolated` describes future independent tunnel intent, but no namespace or tunnel is created by validation. A country code does not establish that NordVPN actually offers a compatible server there. There is no automatic country-pool connection implementation yet.

Given an existing JSON benchmark report with `ranking`, inspect the proposed default selection:

```bash
python nordvpn_policy.py --policy vpn-policy.json --report benchmark.json --current-server ad1234
```

The report's `ranking` must be from the benchmarker's versioned report format, not a plain JSON array export. `switch_candidate` is a *suggestion*, not permission to execute a switch. A current server absent from the eligible measurements produces `current_not_measured`, not a speculative comparison. No automatic switching or scheduling is implemented yet.

## Networking design still to validate

The host default route would be protected by a fail-closed VPN firewall. Independent application profiles would use separate namespaces and tunnels, with their own DNS and IPv4/IPv6 policy. Tunnel underlay routes must allow only the encrypted transport to reach the physical network; they must not create a general escape route. Desktop integration needs to account for Wayland, D-Bus activation and single-instance applications which might otherwise reuse a process outside the assigned namespace.

A disposable two-pair WireGuard experiment has demonstrated independent tunnel connectivity on Arch Linux; fail-closed routing and host integration still require validation. We also need to establish whether the official NordVPN client can coexist with manual tunnels; its routing, DNS and firewall ownership may conflict with a second manager. The future privileged component should manage networking, while the benchmark and policy engine remain unprivileged. Configuration should not grant arbitrary root command execution.

The eventual `optimise-default` operation should benchmark eligible servers, compare them with the current endpoint, respect minimum improvement and connection-age thresholds, and switch only the default profile. Failure must retain a healthy existing connection or fail closed. No override should be reconnected, reselected or moved to another profile as a side effect. Automatic re-evaluation should be opt-in, with rotation disabled by default.

The main unresolved measurement question is what *fastest* should mean. ICMP/TCP latency is a useful initial signal, but it cannot establish tunnel throughput. A later optional stage should measure actual tunnel performance without making a benchmark-induced route change look like a normal application connection.

## Next implementation boundary

The next networking step is production-oriented WireGuard provisioning, with ownership safeguards and fail-closed routing validated before touching the host's default route. The policy validator deliberately has no root operations or executable launch support. A later privileged manager will need an explicit authorisation model, safe underlay routing, IPv4/IPv6 and DNS enforcement, and a way to recover networking if the service fails. The official NordVPN client may conflict with that manager's firewall and routing ownership, so coexistence remains an open question.

The current JSON configuration does not yet encode fallback pools, server rotation, connection-age limits or scheduled optimisation. These should be introduced with versioned validation and tests once their runtime semantics are established, rather than silently accepting configuration that cannot be honoured.

## Routing topology inspection

The offline topology compiler provides a **design-only routing model**, not a network namespace implementation. It answers a question we need settled before any privileged networking code: which connection and isolation domain owns each configured application?

```bash
python nordvpn_topology.py --policy examples/vpn-policy.json
```

The JSON output lists a persistent host domain for the default profile and an on-demand namespace domain for each other named profile. Explicit applications assigned to the same named profile share that domain. An application absent from the policy inherits the host domain. A profile marked `isolated` does not create one connection per application: separate named profiles are required for separate connections. That distinction avoids promising isolation which this configuration cannot express.

Every domain carries the intended fail-closed, DNS, IPv4, IPv6 and tunnel underlay requirements. They are **requirements for the eventual runtime**, not claims that the running machine is protected. The output explicitly records `"runtime_enforcement": false` and `"status": "design_only"`. No network commands are executed, no provider credentials are read, and the official NordVPN client is left alone.

This also fixes the intended optimisation boundary: `default_optimisation_scope` contains only the default profile. Other profiles and their endpoints must not be reselected when the default changes. Applications deliberately assigned to the default profile do share its endpoint and can be interrupted by a switch.

A remaining feasibility step is a disposable two-tunnel integration harness. It needs to establish namespace underlay routing, DNS isolation, IPv6 handling and fail-closed firewall behaviour with deliberate link failures before we can claim that this design works on a real host. In particular, a namespace VPN cannot simply rely on the host's default route: doing so could nest the connection inside the host VPN or prevent the second tunnel from connecting.

## Disposable namespace firewall probe

The first executable networking feasibility tool is `tools/probe_namespace_isolation.py`. It is **not** a WireGuard or NordVPN integration. It creates a disposable network namespace with a veth underlay and a dummy interface standing in for a tunnel, installs an output-drop nftables rule inside that namespace, and checks that underlay traffic stays blocked both before and after the dummy interface goes down. It then removes the namespace. It does not modify host routes, host DNS or the host firewall.

The default invocation is a harmless description of the test:

```bash
python tools/probe_namespace_isolation.py
```

To execute the disposable namespace probe on a Linux host with `iproute2`, `nftables` and `ping` installed:

```bash
sudo python tools/probe_namespace_isolation.py --execute
```

This needs root privileges and network namespace support. It should first be run in a disposable VM. A failed cleanup reports the namespace name so it can be inspected and removed manually. The probe deliberately uses a non-routable benchmark address range and does not connect to the internet.

A passing result establishes only the narrow firewall property being tested. It does **not** prove real tunnel establishment, DNS isolation, IPv6 handling, underlay exception correctness, default-host protection or coexistence with NordVPN's own firewall. Those require later integration work, ideally in a disposable VM with controlled tunnel endpoints and failure injection. No production routing should depend on this probe alone.

### Probe evidence and limitations

The underlay probe now installs an explicit route to its disposable peer, so a failed ping cannot be explained merely by the dummy default route swallowing packets. The nftables underlay-drop rule includes a packet counter; the probe checks that the counter increases during each blocked ping, both with the simulated tunnel up and after it is brought down. An absent or unchanged counter fails the experiment. This is a narrower but more useful observation than treating any unsuccessful ping as proof of firewall enforcement.

The experiment still does not establish an actual VPN tunnel or demonstrate safe host-wide default routing. It is deliberately unsuitable as a production kill switch.

## Unified tool entry point

`nord_tools.py` dispatches to the existing benchmark, offline policy planner, topology inspector and experimental namespace probe. It does not add networking privileges or enable live routing. Keep each original CLI working independently as this interface evolves.

## Desired-state persistence and startup (planned)

The offline `nord_tools.py manage` interface now stores persistent configuration by default and selects transient session intent with `--transient`. Its atomic policy storage is not an active networking state registry and does not implement systemd startup, tunnel recovery or a kill switch. Future live management must track owned resources separately, reconcile drift and partial failures, preserve unaffected tunnels and avoid touching unrelated host networking. Startup should restore persistent desired configuration only after protective routing is established; transient intent must not be resurrected after reboot. Cleanup must remain separate from removal of saved policy intent.

## Offline reconciliation prototype

`manage reconcile --inventory FILE` compares the saved desired policy against an explicitly provided versioned simulation of observed profiles. It produces a deterministic, non-executable plan with create, replace, repair, retire, unchanged and blocked decisions. External ownership conflicts block planning for that profile, and external-only resources are left alone. This is not host discovery, an ownership registry, or a privileged executor. Before live execution is introduced, ownership must be independently verified against kernel resources, changes must be transactional and fail-closed, and startup restoration must distinguish persistent from transient intent.

## Offline resource-ownership audit

`python nord_tools.py manage audit --registry examples/managed-registry.json --inventory examples/managed-inventory.json` compares an explicitly supplied version 1 resource ledger with a simulated profile inventory. The ledger names claimed namespaces, interfaces, routes, firewall objects, DNS objects and services, with unique resource identities and profile associations. Invalid ownership, duplicate identities and malformed records are rejected.

This is a read-only schema and diagnostic exercise, not a live registry or kernel discovery. Even when a simulated profile is marked ready, the audit reports individual resources as unverified. Neither a ledger claim nor a simulated inventory grants authority to remove anything. A future privileged implementation must verify actual resource ownership, support crash recovery and enforce fail-closed replacement before applying changes. The existing persistent and transient desired-policy files remain separate from this illustrative ledger.

## Read-only Linux networking discovery

`python nord_tools.py manage discover` observes named Linux network namespaces, host and namespace interfaces, IPv4 and IPv6 routes, and nftables rulesets. It uses read-only `ip` and `nft` commands. A failed query, malformed result or duplicate identity causes discovery to fail instead of returning a partial inventory as though it were complete. Reading nftables rulesets may require elevated privileges.

Discovery does not inspect DNS configuration or service state, prove firewall effectiveness, or establish ownership of a resource. Matching a name in an allocation ledger is insufficient evidence to modify or remove that resource. See the evidence commands below for diagnostic correlation, not authorisation.

### Read-only evidence correlation

The `manage evidence` command correlates explicitly recorded resource names with live namespace and interface observations. Interface names are scoped to `host` or a named namespace, and unqualified names remain ambiguous. Missing resources and unsupported evidence kinds are reported rather than guessed. The result always declares ownership unverified and deletion unsafe, even when names match. Future resource creation must establish independent, durable ownership markers and validate them against actual kernel state before destructive reconciliation is permitted.

### Allocation identities and safe ownership

The version 2 allocation ledger adds a unique random `allocation_id` to each resource claim. It rejects duplicate identities, duplicate resource names within a kind and malformed claims. The offline `manage identities` command validates this structure but grants no permission to alter networking. A future provisioner must establish a verifiable binding between each allocation and the actual resource, including safeguards against resource-name reuse, stale records and interrupted creation. The legacy version 1 ledger remains supported by the separate diagnostic audit and evidence commands; it is not silently upgraded into an authoritative ledger.

### Allocation evidence and stale-state diagnostics

The `manage identity-evidence` command validates the version 2 allocation ledger and correlates its claimed resources with read-only discovery. It reports name matches as unverified because the operating system may reuse names. Missing names are classified as stale or unprovisioned, without claiming to distinguish those cases. Ambiguous interface scopes and unsupported kinds remain explicitly unverified. The result always forbids modification and deletion. This is diagnostic groundwork, not a kernel-bound ownership marker or recovery executor.

### Offline dependency ordering

The `manage dependency-plan` command accepts a version 1 graph whose `dependencies` object maps each profile to its prerequisite profiles. It combines that explicit graph with the saved desired policy and an independently supplied simulated inventory. It schedules desired profiles in prerequisite-first order and retirement in reverse, propagates externally owned prerequisite conflicts, and rejects cycles or missing dependencies. This is not a discovered resource graph and does not imply that a profile-level dependency proves ownership of its interfaces, routes, firewall rules or services. No operation can be executed from this output. A future live executor must separately verify per-resource ownership, leak protection, transactional cut-over and rollback.

### Offline transaction and recovery contract

`manage transaction-plan` expands the dependency-ordered simulation into descriptive stages for creation, repair, replacement and retirement. Replacement prepares and verifies a protected new connection before switching assignments, and retires the old connection only after a successful cut-over. Recovery requires a durable journal and fresh independent ownership verification; on uncertainty the future executor must preserve the existing connection or remain fail-closed. These are design obligations, not implemented operations. The current command neither writes a journal nor changes host networking, and its output always declares `safe_to_execute: false`.

## Configuration graph and cleanup preview

`manage graph` renders the saved configuration as a deterministic terminal tree. Unicode box-drawing is the default; `--ascii` provides a plain-text fallback. The root represents routing intent, not a verified host default route. Each named profile is a connection-sharing boundary, with assigned applications beneath it and unlisted applications inheriting the default. A profile marked isolated is distinct from a shared profile but does not imply a separate tunnel per application. The selection shown is a requested country, pinned endpoint or filter, never an observed destination. The output explicitly labels its configured persistent or transient scope and its lack of live networking verification.

`manage cleanup-plan --inventory FILE` describes candidate profile retirements from an explicit simulated inventory. It excludes externally owned profiles, rejects malformed records, and always reports that it is unsafe to execute. This is not a replacement for `cleanup`: safe live removal will require independently verified resource ownership, an ordered dependency graph, durable recovery records and fail-closed protections. No host state is changed by either command.

The README concentrates on commands and current capabilities; this design document retains the reasoning and safety boundaries. The five-increment offline management programme is complete, but privileged provisioning, real ownership binding, systemd restoration, rollback and cleanup execution are not implemented or certified.

### Read-only recovery triage (Part 2)

`nord_tools_internal.nordvpn_recovery.assess_recovery()` combines a validated lifecycle journal, recorded interface fingerprints and a complete read-only discovery snapshot. It classifies interrupted creation or retirement, missing or changed identities, retired-name reuse and insufficient evidence. All classifications require operator review. No classification establishes creation-time ownership, grants permission to modify or delete resources, or performs automatic recovery. A kernel interface index can be reused, so matching fingerprints are diagnostic only. Privileged creation-time ownership binding, recovery execution and integration tests remain outstanding.

## Operation intent boundary

`nord_tools_internal/nordvpn_operation_intent.py` records validated offline create and retire intents against a specific allocation identity and lifecycle transition sequence. Pending and uncertain intents require operator review, and duplicate unresolved operations are rejected. This is a planning and recovery input only: even an intent marked completed is not independent evidence that a kernel resource was created by Nord Tools. The future privileged provisioner must establish verifiable creation-time ownership, durable operation ordering and live identity checks before any resource may be modified or deleted.

### Process-bound disposable namespace ownership experiment

`nord_tools_internal/nordvpn_namespace_ownership.py` provides an explicit privileged experiment for disposable `nt-`-prefixed Linux network namespaces. Its context manager refuses pre-existing names, creates a namespace using `ip netns add`, retains a namespace file descriptor, checks the live namespace device/inode against that descriptor, refuses retirement while namespace processes remain and releases the descriptor when finished. If verification or cleanup is uncertain, it leaves the resource for operator investigation rather than deleting a resource based solely on its name. The caller must choose a collision-resistant name and invoke this only in a disposable, privileged test environment.

This is **ephemeral process-bound evidence**, not a persistent ownership certificate. Kernel identifiers may be reused, an attacker with namespace-management privileges can race the final name-based `ip netns del`, and a process crash loses the held descriptor. Therefore this experiment is not suitable for production resource removal, automatic recovery, or authorising changes to existing networking. The normal-operation privileged smoke test passed on Arch Linux, but a stronger race-resistant ownership mechanism remains required before production mutation or cleanup. No production networking code calls this experiment.

### Disposable namespace ownership acceptance probe

Run `sudo python tools/probe_namespace_ownership.py --run-privileged` only on a disposable Linux test host or a host where creation of a temporary network namespace has been explicitly approved. The probe creates one randomly named `nt-` namespace, verifies its process-held descriptor and attempts retirement through the existing ownership primitive. It does not alter host routing, DNS or firewall state. A successful probe establishes only that the basic privileged creation, descriptor inspection and retirement path worked in that environment. It does not establish race-free deletion, crash-safe ownership, or recovery after process death.

If the process is interrupted, or if verification or retirement fails, inspect `/run/netns` and `ip netns list` manually. Do not automatically delete an observed namespace merely because its name resembles a Nord Tools resource. The offline tests deliberately simulate missing privileges, missing dependencies and verification failures without modifying kernel resources. Process-death recovery and adversarial namespace replacement remain unverified safety requirements for later privileged operations.

## Part 3 provisioning input boundary

The internal `nord_tools_internal.nordvpn_wireguard_provision.TunnelSpecification` type validates a narrowly scoped, disposable WireGuard tunnel proposal before any privileged executor is introduced. Namespace and interface names are bounded, peer keys must have canonical WireGuard public-key encoding, endpoints must be numeric IP addresses, ports must be valid, and tunnel addresses and allowed networks must parse as IP prefixes. Its `public_plan()` result deliberately excludes private credentials and explicitly reports that no networking changes have been applied. This is an offline validation boundary, not a functioning tunnel provisioner, a secure credential-handling implementation or proof of resource ownership. Experimental disposable configuration and journal-gated integration probes have since been added and exercised, but production provisioning still requires independently authorised creation-time identity binding, crash-persistent ownership, safe recovery and controlled acceptance before live management can be enabled. No host routes, DNS settings or firewall rules are changed by this component.

## Experimental journal-gated creation adapter

The internal `nordvpn_provision_execution` adapter validates the supplied lifecycle snapshot, requires an existing durable operation store, and writes a pending creation intent before invoking an injected operation. Completion requires explicit verification and a durable outcome update. An exception, failed verification or failed outcome persistence must be treated as uncertain, with no automatic retry. This does not solve the cross-file lifecycle transaction, independent kernel ownership, crash recovery or race-safe deletion problems. The adapter is not wired to a production privileged entry point.

## Part 4 disposable acceptance and production boundary

The four experimental Part 4 increments have passed privileged acceptance on Arch Linux. The evidence covers namespace resolver visibility without host resolver changes, IPv4/IPv6 synthetic DNS route selection without simulated underlay fallback, narrowly scoped counter-verified UDP endpoint exceptions, and a two-pair real WireGuard experiment with unchanged observed host routes, nftables rules and resolver contents. Both WireGuard pairs exchanged tunnel packets, independent shutdown checks passed and the final named namespace listing was empty. The host-integrity comparison is a before-and-after observation, not proof against transient or concurrent changes. The synthetic routing and endpoint tests do not establish real DNS delivery over WireGuard. Production enforcement still requires independently authorised crash-persistent ownership, race-safe recovery, real-tunnel DNS packet confinement, and failure injection for tunnel loss, restart and rollback. The acceptance record and remaining requirements are maintained in `TODO.md`.

## Part 5 offline application-routing acceptance and production boundary

The five Part 5 offline increments cover registered-application routing and default-profile inheritance, shared versus isolated logical allocation planning, deterministic binding and reference release, immutable launch request preparation, logical application-session lifecycle and a read-only consistency audit. These are planning and consistency checks, not an operational per-application VPN launcher. In particular, a logical session is not a process handle, a binding is not proof of namespace ownership, and releasing a reference cannot authorise deletion of kernel resources. Application execution remains disabled pending independently authorised, crash-persistent ownership, verified namespace firewall and DNS confinement, transactional lifecycle coordination and privileged desktop/application integration testing. The remaining requirements are tracked in `TODO.md` under Parts 3 to 8 and the production ownership boundary.

## Part 6 offline reconciliation acceptance and production boundary

The five Part 6 increments implement separate, non-authorising contracts: an evidence gate for proposed operations, ordered checkpoint and interruption assessments, staged replacement obligations, drift classification, and a cross-contract consistency audit. They operate on supplied logical records, not independently authenticated kernel ownership. Even mutually consistent reports cannot authorise creation, cut-over, rollback, repair, retirement or deletion. The production executor must bind durable intents to independent crash-persistent creation-time ownership evidence, coordinate operations transactionally, re-observe kernel state before each sensitive transition and recover safely after interruption. Live idempotent apply/update/replace/remove, verified replacement without disturbing unaffected tunnels, drift repair, rollback and privileged failure-injection acceptance remain outstanding. See `TODO.md`; completion of the offline programme is not completion of Part 6 operational requirements.

## Part 7.1: ownership verification preflight

The reconciliation gate of Part 6 requires independently observed ownership before it will even consider execution, but until now nothing in the project could produce that evidence. Part 7.1 introduces that production step: `nord_tools_internal/nordvpn_ownership_verify.py` maintains a durable owner-record store and a preflight that classifies allocations against it.

### Owner records

An owner record binds an allocation identity to the kernel identity the creator observed while privileged authority was still live, at the moment of creation:

- A namespace binding records the device and inode of the `/run/netns` mount entry. `OwnedNamespace` already re-checks the held descriptor against that entry; a later process can repeat the check from the record without the descriptor.
- An interface binding records the creation-time scope (`host` or a namespace name) and interface index.

Records are appended through the same locked, atomic, symlink-refusing store pattern as the lifecycle and intent stores, and each binding is cross-checked against the validated allocation ledger. A binding is immutable once written. Retirement history is deliberately retained: if a name is reused after a recorded retirement, that appears as an identity conflict rather than renewed ownership. There is no binding shape for route, firewall, DNS or service kinds yet; those kinds are reported as unsupported rather than partially supported, and their bindings arrive with their consumers.

### Verification and its limit

The preflight re-derives each recorded identity from a complete read-only discovery snapshot: for a namespace it observes the live mount entry, for an interface the scope and current index. A finding of `verified_current` therefore means: the binding recorded at creation still matches the kernel, the lifecycle state is stable, no operation intent is unresolved, and the observation is fresh. Everything else fails closed: missing resources, changed identities, unbound claims, unresolved intents, interrupted lifecycle transitions, observed names after a recorded retirement, and resource kinds with no binding model. Observations that no allocation claims anywhere in the journal are listed separately as unclaimed; they may belong to other software or another ledger, and nothing in this layer makes a decision about them.

This is continuity evidence within a boot session, not an unforgeable certificate, and the report says so rather than implying otherwise. `/run/netns` is tmpfs, so mount identities cannot survive a reboot and must be re-established by an operator after one; a hostile process with write access to the store directory could forge a record, though it would also have to fabricate the matching journal, which makes that escape more demanding than forging names alone. The boundary the layer does draw is strict: a resource name, journal event or allocation token alone never verifies anything, and one unverified allocation fails verification for the whole batch, so no consumer can selectively adopt the convenient subset.

### Where this leaves Part 7

7.1 provides the verification and recovery-preflight layer; it does not authorise mutation, install a boot-time reconciler or delete anything. Later increments consume it: persistent reconciliation (7.2, 7.3) and cleanup (7.4) must gate on a fresh preflight result and re-verify ownership at the moment of execution. The privileged acceptance probe is `tools/probe_ownership_preflight.py`; it exercises exactly one disposable namespace and the rejection path, and leaves the host otherwise untouched.

## Part 7.2: persistent desired-state reconciliation

The saved persistent and transient intent files have always been separate documents, but nothing compared either against resources the tool can prove it owns. Part 7.2 closes that gap as far as is currently defensible: `nord_tools_internal/nordvpn_state_reconcile.py` derives an actual per-profile state from live evidence and classifies convergence, while continuing to perform no network change.

### Deriving actual state

`derive_actual_state` joins three inputs that must all be current and internally consistent: a validated lifecycle journal, the owner-record store of Part 7.1, and a fresh preflight report over exactly the same allocations. Resource names play no part in this: a profile has resources when the preflight classifies them `verified_current`, and `consistent_retired` allocations count as absent. Any other finding becomes a profile blocker with its exact finding carried forward. Observations unclaimed by any allocation remain a separate diagnostic list; they may belong to other software and are never folded into profile state.

Owner bindings now optionally record the provisioned configuration for the profile at binding time. A profile's configuration counts as recorded only when every binding of the profile agrees on an identical record, normalised through the same validation as desired intent; partial or conflicting records leave the configuration unverified. This asymmetry is deliberate. A binding is immutable, so a resource created before configuration recording cannot claim a configuration it does not possess, and the reconciliation must treat absence of evidence as non-convergence rather than as a suspected drift.

### Convergence classification and its limits

`reconcile_desired` compares persistent desired profiles with the derived state and produces one decision per profile: `converged`, `configuration_changed`, `configuration_unverified`, `blocked`, `create_pending` or `retire_pending`. Convergence requires verified resources and an identical recorded and desired configuration. Blocked profiles list their exact blockers; not-desired resources are never removed here and not-desired unverified resources are reported as left alone. Desired profiles without owned resources are `create_pending` and explicitly refuse blind creation: allocation happens only where a future provisioner establishes creation-time authority first. `configuration_changed` yields a replacement plan only; no cut-over is executed by this layer.

With an optional dependency graph, a blocked prerequisite blocks every desired dependent, including independently converged ones — matching the offline dependency planner's treatment of unsafe parents. Verified evidence of the dependent's own resources does not compensate for a prerequisite that cannot safely proceed.

Idempotence is a property of the pure classification: the same durable inputs produce a byte-identical report, and a run writes nothing. Interruption-state is deliberately not re-modelled here; pending or uncertain operation intents already surface through the preflight as blockers, and any run journal belongs with the boot wiring of 7.3 rather than with this layer. The plan/report split is unchanged from prior increments: `safe_to_execute` is always false, and 7.3's boot reconciliation must obtain a fresh preflight at startup and re-verify ownership at the moment of any privileged action.
