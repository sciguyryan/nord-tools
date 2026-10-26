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

I would prove two simultaneous VPN connections in disposable namespaces before changing host networking. We also need to establish whether the official NordVPN client can coexist with manual tunnels; its routing, DNS and firewall ownership may conflict with a second manager. The future privileged component should manage networking, while the benchmark and policy engine remain unprivileged. Configuration should not grant arbitrary root command execution.

The eventual `optimise-default` operation should benchmark eligible servers, compare them with the current endpoint, respect minimum improvement and connection-age thresholds, and switch only the default profile. Failure must retain a healthy existing connection or fail closed. No override should be reconnected, reselected or moved to another profile as a side effect. Automatic re-evaluation should be opt-in, with rotation disabled by default.

The main unresolved measurement question is what *fastest* should mean. ICMP/TCP latency is a useful initial signal, but it cannot establish tunnel throughput. A later optional stage should measure actual tunnel performance without making a benchmark-induced route change look like a normal application connection.

## Next implementation boundary

The next networking step should use disposable network namespaces to prove two independent encrypted tunnels and fail-closed routing before touching the host's default route. The policy validator deliberately has no root operations or executable launch support. A later privileged manager will need an explicit authorisation model, safe underlay routing, IPv4/IPv6 and DNS enforcement, and a way to recover networking if the service fails. The official NordVPN client may conflict with that manager's firewall and routing ownership, so coexistence remains an open question.

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

`nordvpn_recovery.assess_recovery()` combines a validated lifecycle journal, recorded interface fingerprints and a complete read-only discovery snapshot. It classifies interrupted creation or retirement, missing or changed identities, retired-name reuse and insufficient evidence. All classifications require operator review. No classification establishes creation-time ownership, grants permission to modify or delete resources, or performs automatic recovery. A kernel interface index can be reused, so matching fingerprints are diagnostic only. Privileged creation-time ownership binding, recovery execution and integration tests remain outstanding.

## Operation intent boundary

`nordvpn_operation_intent.py` records validated offline create and retire intents against a specific allocation identity and lifecycle transition sequence. Pending and uncertain intents require operator review, and duplicate unresolved operations are rejected. This is a planning and recovery input only: even an intent marked completed is not independent evidence that a kernel resource was created by Nord Tools. The future privileged provisioner must establish verifiable creation-time ownership, durable operation ordering and live identity checks before any resource may be modified or deleted.
