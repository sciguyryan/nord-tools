# Default VPN optimisation and application routing

This document describes the offline planning model and the production boundaries built around it. Sections labelled offline or experimental apply only to those components; they do not imply that the separate production executors are unimplemented. The current release scope is summarised in the [README](../README.md), the accepted authority model is defined in [Privileged mutation authority and threat boundary](PRIVILEGED-AUTHORITY-BOUNDARY.md), and current verification status is recorded in [Release status and verification](RELEASE-READINESS.md).

The Nord Tools benchmarker ranks OpenVPN endpoints using ICMP or TCP probes. Its `--auto-connect` path operates on the ordinary NordVPN Linux client. That is useful for a single connection, but it does not establish independent per-application tunnels. Application routing belongs to the separate WireGuard namespace lifecycle.

The routing model provides a system-wide default VPN profile, with applications optionally assigned to independent profiles. An unassigned application inherits the default. A named override remains on its assigned tunnel when the default is optimised. Applications deliberately sharing the default profile are *not* independent overrides, and may experience a default-server change.

A profile can select a country pool, expressed as an ISO country code, or a pinned server. Applications sharing a profile normally share a tunnel; isolated allocations can use different servers in the same country. Country and server availability must be established from imported provider data. The benchmark filter grammar is reused rather than duplicated in a second policy language.

## Offline planning

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

The validator recognises `fastest`, `country` and `pinned` selection modes, requires an existing default profile, checks application executable paths and rejects unknown configuration fields. `sharing: shared` is the default; `sharing: isolated` describes an independent allocation, but policy validation itself creates no namespace or tunnel. Production restoration can resolve country selection from an imported provider catalogue; automatic live reselection remains unsupported. A country code alone does not establish that NordVPN offers a compatible imported server there.

Given an existing JSON benchmark report with `ranking`, inspect the proposed default selection:

```bash
python nordvpn_policy.py --policy vpn-policy.json --report benchmark.json --current-server ad1234
```

The report's `ranking` must be from the benchmarker's versioned report format, not a plain JSON array export. `switch_candidate` is a *suggestion*, not permission to execute a switch. A current server absent from the eligible measurements produces `current_not_measured`, not a speculative comparison. No automatic switching or scheduling is implemented yet.

## Production networking boundary

The production namespace executor installs fail-closed per-allocation nftables, IPv4/IPv6 routes and a pinned resolver. Host-default protection uses a separate deny-first lifecycle and is accepted only for the documented static-egress deployment profile. Tunnel underlay routes allow only the pinned encrypted endpoint and must not create a general escape route. Registered desktop launch forwards a validated local Wayland, X11, Xauthority and user D-Bus environment; compositor portals, notifications, GPU rendering and desktop-specific activation remain outside the accepted evidence.

Disposable and production guest matrices have demonstrated independent WireGuard connectivity, fail-closed namespace routing, registered application confinement and the narrow host-default lifecycle on Arch Linux. Coexistence with the official NordVPN client is not supported: operational preflight refuses recognised competing VPN and firewall managers rather than attempting to share their routing, DNS or firewall state. Privileged execution remains confined to validated lifecycle operations; policy and benchmark processing stay unprivileged and configuration cannot supply arbitrary root commands.

The policy planner can benchmark eligible servers and recommend a default-profile candidate subject to improvement thresholds, but it does not execute a switch. Automatic live optimisation and in-place provider reselection are deliberately unsupported. A selected change must use explicit immutable generation replacement, which preserves existing application assignments and does not silently reselect independent overrides.

The `fastest` selection means the best eligible endpoint according to the saved benchmark report's packet loss and latency fields. It does not mean highest tunnel throughput. Nord Tools does not perform a throughput test through the selected VPN allocation.

## Lifecycle boundary

Production WireGuard provisioning is separate from policy validation. The validator has no root operations or executable launch support; privileged executors supply the authorisation model, restricted underlay routing, IPv4/IPv6 and DNS enforcement, and evidence-led recovery. Coexistence with the official NordVPN client is unsupported because operational preflight refuses recognised competing VPN and firewall managers.

The JSON configuration does not encode fallback pools, server rotation, connection-age limits or scheduled optimisation. Unknown fields are refused rather than accepted with semantics the runtime cannot honour.

## Routing topology inspection

The offline topology compiler provides a **design-only routing model**, not a network namespace observation. It shows which connection and isolation domain owns each configured application.

```bash
python nordvpn_topology.py --policy examples/vpn-policy.json
```

The JSON output lists a persistent host domain for the default profile and an on-demand namespace domain for each other named profile. Explicit applications assigned to the same named profile share that domain. An application absent from the policy inherits the host domain. A profile marked `isolated` does not create one connection per application: separate named profiles are required for separate connections. That distinction avoids promising isolation which this configuration cannot express.

Every domain carries its fail-closed, DNS, IPv4, IPv6 and tunnel underlay requirements. These are configuration requirements, not claims that the running machine is protected. The output explicitly records `"runtime_enforcement": false` and `"status": "design_only"`. No network commands are executed, no provider credentials are read, and the official NordVPN client is left alone.

This also fixes the intended optimisation boundary: `default_optimisation_scope` contains only the default profile. Other profiles and their endpoints must not be reselected when the default changes. Applications deliberately assigned to the default profile do share its endpoint and can be interrupted by a switch.

The production executor does not rely on the host default route as an unrestricted namespace underlay. It pins the encrypted endpoint path and installs namespace-local fail-closed firewall, DNS and dual-stack routing controls. This avoids silently nesting a namespace connection inside an unrelated host VPN.

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

A passing result establishes only the narrow firewall property being tested. It does **not** prove real tunnel establishment, DNS isolation, IPv6 handling, underlay exception correctness, default-host protection or coexistence with NordVPN's own firewall. Production behaviour has separate disposable-guest verification with controlled tunnel endpoints and failure injection. No production routing depends on this probe alone.

### Probe evidence and limitations

The underlay probe now installs an explicit route to its disposable peer, so a failed ping cannot be explained merely by the dummy default route swallowing packets. The nftables underlay-drop rule includes a packet counter; the probe checks that the counter increases during each blocked ping, both with the simulated tunnel up and after it is brought down. An absent or unchanged counter fails the experiment. This is a narrower but more useful observation than treating any unsuccessful ping as proof of firewall enforcement.

The experiment still does not establish an actual VPN tunnel or demonstrate safe host-wide default routing. It is deliberately unsuitable as a production kill switch.

## Unified tool entry point

`nord_tools.py` dispatches to the benchmark, offline policy planner, topology inspector, production management surface and disposable probes. Dispatch adds no authority: each management command retains its own validation, privilege and explicit-execution boundary, and each original CLI remains independently available.

## Desired-state persistence and startup

The offline `nord_tools.py manage` interface stores persistent configuration by default and selects transient session intent with `--transient`. Its atomic policy storage is not an active networking state registry. The separately installed `nord-tools-restore.service` unit reconciles and restores namespace-domain profiles whose owned resources are absent for this boot session, installing each profile's fail-closed firewall before any traffic configuration. Host-default protection is a separate deny-first lifecycle accepted only for the documented static IPv4 `systemd-networkd` and `systemd-resolved` profile. Transient intent must not be resurrected after reboot, and the boot command refuses it outright. Cleanup remains separate from removal of saved policy intent.

## Offline reconciliation model

`manage reconcile --inventory FILE` compares the saved desired policy against an explicitly provided versioned simulation of observed profiles. It produces a deterministic, non-executable plan with create, replace, repair, retire, unchanged and blocked decisions. External ownership conflicts block planning for that profile, and external-only resources are left alone. This is not host discovery, an ownership registry, or a privileged executor. The separate live executors independently verify kernel ownership, use durable operation evidence and distinguish persistent from transient intent.

## Offline resource-ownership audit

`python nord_tools.py manage audit --registry examples/managed-registry.json --inventory examples/managed-inventory.json` compares an explicitly supplied version 1 resource ledger with a simulated profile inventory. The ledger names claimed namespaces, interfaces, routes, firewall objects, DNS objects and services, with unique resource identities and profile associations. Invalid ownership, duplicate identities and malformed records are rejected.

This is a read-only schema and diagnostic exercise, not a live registry or kernel discovery. Even when a simulated profile is marked ready, the audit reports individual resources as unverified. Neither a ledger claim nor a simulated inventory grants authority to remove anything. Separate production executors establish creation-time bindings, re-observe ownership, retain durable operation evidence and fail closed on uncertainty. The persistent and transient desired-policy files remain separate from this illustrative ledger.

## Read-only Linux networking discovery

`python nord_tools.py manage discover` observes named Linux network namespaces, host and namespace interfaces, IPv4 and IPv6 routes, and nftables rulesets. It uses read-only `ip` and `nft` commands. A failed query, malformed result or duplicate identity causes discovery to fail instead of returning a partial inventory as though it were complete. Reading nftables rulesets may require elevated privileges.

Discovery does not inspect DNS configuration or service state, prove firewall effectiveness, or establish ownership of a resource. Matching a name in an allocation ledger is insufficient evidence to modify or remove that resource. See the evidence commands below for diagnostic correlation, not authorisation.

### Read-only evidence correlation

The `manage evidence` command correlates explicitly recorded resource names with live namespace and interface observations. Interface names are scoped to `host` or a named namespace, and unqualified names remain ambiguous. Missing resources and unsupported evidence kinds are reported rather than guessed. The result always declares ownership unverified and deletion unsafe, even when names match. Production creation uses a separate owner-binding store and destructive reconciliation requires fresh validation against actual kernel state.

### Allocation identities and safe ownership

The version 2 allocation ledger adds a unique random `allocation_id` to each resource claim. It rejects duplicate identities, duplicate resource names within a kind and malformed claims. The offline `manage identities` command validates this structure but grants no permission to alter networking. Production restoration establishes a separate verifiable binding between each allocation and its created resources, with checks for resource-name reuse, stale records and interrupted creation. The legacy version 1 ledger remains supported by the diagnostic audit and evidence commands; it is not silently upgraded into an authoritative ledger.

### Allocation evidence and stale-state diagnostics

The `manage identity-evidence` command validates the version 2 allocation ledger and correlates its claimed resources with read-only discovery. It reports name matches as unverified because the operating system may reuse names. Missing names are classified as stale or unprovisioned, without claiming to distinguish those cases. Ambiguous interface scopes and unsupported kinds remain explicitly unverified. The result always forbids modification and deletion. This is diagnostic groundwork, not a kernel-bound ownership marker or recovery executor.

### Offline dependency ordering

The `manage dependency-plan` command accepts a version 1 graph whose `dependencies` object maps each profile to its prerequisite profiles. It combines that explicit graph with the saved desired policy and an independently supplied simulated inventory. It schedules desired profiles in prerequisite-first order and retirement in reverse, propagates externally owned prerequisite conflicts, and rejects cycles or missing dependencies. This is not a discovered resource graph and does not imply that a profile-level dependency proves ownership of its interfaces, routes, firewall rules or services. No operation can be executed from this output; production executors separately verify per-resource ownership and their operation-specific fail-closed boundaries.

### Offline transaction and recovery contract

`manage transaction-plan` expands the dependency-ordered simulation into descriptive stages for creation, repair, replacement and retirement. Its output remains non-executable and always declares `safe_to_execute: false`. Separate production commands implement immutable generation replacement and evidence-certified recovery using durable journals and fresh ownership checks; the simulation is not authority for those operations.

## Configuration graph and cleanup preview

`manage graph` renders the saved configuration as a deterministic terminal tree. Unicode box-drawing is the default; `--ascii` provides a plain-text fallback. The root represents routing intent, not a verified host default route. Each named profile is a connection-sharing boundary, with assigned applications beneath it and unlisted applications inheriting the default. A profile marked isolated is distinct from a shared profile but does not imply a separate tunnel per application. The selection shown is a requested country, pinned endpoint or filter, never an observed destination. The output explicitly labels its configured persistent or transient scope and its lack of live networking verification.

`manage cleanup-plan --inventory FILE` describes candidate profile retirements from an explicit simulated inventory. It excludes externally owned profiles, rejects malformed records, and always reports that it is unsafe to execute. This is not a replacement for `cleanup`, which requires independently verified resource ownership, an ordered dependency graph, durable recovery records and fail-closed protections. No host state is changed by the preview.

### Read-only recovery triage (recovery triage)

`nord_tools_internal.nordvpn_recovery.assess_recovery()` combines a validated lifecycle journal, recorded interface fingerprints and a complete read-only discovery snapshot. It classifies interrupted creation or retirement, missing or changed identities, retired-name reuse and insufficient evidence. All classifications require operator review. No classification establishes creation-time ownership, grants permission to modify or delete resources, or performs automatic recovery. Production recovery is a separate evidence-certified executor backed by creation-time owner bindings; matching diagnostic fingerprints alone never authorise it.

## Operation intent boundary

`nord_tools_internal/nordvpn_operation_intent.py` records validated create and retire intents against a specific allocation identity and lifecycle transition sequence. Pending and uncertain intents require operator review, and duplicate unresolved operations are rejected. Even an intent marked completed is not independent evidence that a kernel resource was created by Nord Tools. Startup restoration, cleanup and recovery establish and recheck creation-time ownership for supported resource types; the intent module alone authorises no mutation.

### Process-bound disposable namespace ownership experiment

`nord_tools_internal/nordvpn_namespace_ownership.py` provides an explicit privileged experiment for disposable `nt-`-prefixed Linux network namespaces. Its context manager refuses pre-existing names, creates a namespace using `ip netns add`, retains a namespace file descriptor, checks the live namespace device/inode against that descriptor, refuses retirement while namespace processes remain and releases the descriptor when finished. If verification or cleanup is uncertain, it leaves the resource for operator investigation rather than deleting a resource based solely on its name. The caller must choose a collision-resistant name and invoke this only in a disposable, privileged test environment.

This is **ephemeral process-bound evidence**, not a persistent ownership certificate. Kernel identifiers may be reused, an attacker with namespace-management privileges can race the final name-based `ip netns del`, and a process crash loses the held descriptor. Therefore this experiment is not suitable for production resource removal, automatic recovery or authorising changes to existing networking. Production code does not call this experiment; it uses durable owner bindings, fresh verification and the cooperating-process authority model described separately.

### Disposable namespace ownership acceptance probe

Run `sudo python tools/probe_namespace_ownership.py --run-privileged` only on a disposable Linux test host or a host where creation of a temporary network namespace has been explicitly approved. The probe creates one randomly named `nt-` namespace, verifies its process-held descriptor and attempts retirement through the existing ownership primitive. It does not alter host routing, DNS or firewall state. A successful probe establishes only that the basic privileged creation, descriptor inspection and retirement path worked in that environment. It does not establish race-free deletion, crash-safe ownership, or recovery after process death.

If the process is interrupted, or if verification or retirement fails, inspect `/run/netns` and `ip netns list` manually. Do not automatically delete an observed namespace merely because its name resembles a Nord Tools resource. This experiment has no crash-persistent authority; production process-death recovery and replacement refusal use the separate durable lifecycle and ownership evidence.

## Provisioning input boundary

The internal `nord_tools_internal.nordvpn_wireguard_provision.TunnelSpecification` type validates a narrowly scoped, disposable WireGuard tunnel proposal. Namespace and interface names are bounded, peer keys must have canonical WireGuard public-key encoding, endpoints must be numeric IP addresses, ports must be valid, and tunnel addresses and allowed networks must parse as IP prefixes. Its `public_plan()` result deliberately excludes private credentials and explicitly reports that no networking changes have been applied. This component remains an offline validation boundary, not a provisioner, credential store or proof of ownership. Separate production restoration supplies credentials through file descriptors, records creation-time identity and performs the authorised kernel operations.

## Experimental journal-gated creation adapter

The internal `nordvpn_provision_execution` adapter validates the supplied lifecycle snapshot, requires an existing durable operation store, and writes a pending creation intent before invoking an injected operation. Completion requires explicit verification and a durable outcome update. An exception, failed verification or failed outcome persistence is uncertain, with no automatic retry. This adapter is not itself a production privileged entry point; startup restoration, cleanup and recovery use journal-gated lifecycle operations with separate ownership checks.

## Network confinement boundary

The experimental network confinement components passed privileged acceptance on Arch Linux. Their evidence covers namespace resolver visibility without host resolver changes, IPv4/IPv6 synthetic DNS route selection without simulated underlay fallback, narrowly scoped counter-verified UDP endpoint exceptions and a two-pair real WireGuard experiment with unchanged observed host routes, nftables rules and resolver contents. Both WireGuard pairs exchanged tunnel packets, independent shutdown checks passed and the final named namespace listing was empty. These historical component probes do not establish production behaviour by themselves. Production matrices separately accepted durable ownership, recovery, real-tunnel DNS confinement and failure injection for tunnel loss, restart and rollback within the documented guest and authority scope.

## Application routing boundary

The offline application-routing contracts cover registered-application routing and default-profile inheritance, shared versus isolated logical allocation planning, deterministic binding and reference release, immutable launch request preparation, logical application-session lifecycle and a read-only consistency audit. They remain planning and consistency checks, separate from the operational registered-application launcher. In particular, a logical session is not a process handle, a binding is not proof of namespace ownership, and releasing a reference cannot authorise deletion of kernel resources. A gated registered-application launcher and explicit direct host-routing mode are implemented. The completed privileged application lifecycle matrix demonstrates direct execution, VPN authority refusal, concurrent shared and isolated lifecycles, and registered dual-stack DNS and underlay refusal through peer loss and recovery. A separate guest-only stage demonstrates explicit desktop-session propagation. The desktop contract is deliberately narrower than a particular compositor: it accepts safe local Wayland, X11 and user D-Bus endpoints and refuses to infer or forward anything else.

## Live reconciliation boundary

The offline reconciliation layer implements separate, non-authorising contracts: an evidence gate for proposed operations, ordered checkpoint and interruption assessments, staged replacement obligations, drift classification and a cross-contract consistency audit. They operate on supplied logical records, not independently authenticated kernel ownership, so even mutually consistent reports cannot authorise creation, cut-over, rollback, repair, retirement or deletion. Separate production executors bind durable intents to creation-time ownership evidence, re-observe kernel state before sensitive transitions and provide create-only apply, immutable generation replacement, verified retirement and bounded recovery. General in-place repair and automatic provider reselection are unsupported; disputed resources quarantine their entire profile. Current acceptance is recorded in [Release status and verification](RELEASE-READINESS.md).

## Creation-time ownership verification

Live reconciliation requires independently observed ownership before it will consider execution. `nord_tools_internal/nordvpn_ownership_verify.py` provides that production step through a durable owner-record store and a preflight that classifies allocations against it.

### Owner records

An owner record binds an allocation identity to the kernel identity the creator observed while privileged authority was still live, at the moment of creation:

- A namespace binding records the device and inode of the `/run/netns` mount entry. `OwnedNamespace` already re-checks the held descriptor against that entry; a later process can repeat the check from the record without the descriptor.
- An interface binding records the creation-time scope (`host` or a namespace name) and interface index.

Records are appended through the same locked, atomic, symlink-refusing store pattern as the lifecycle and intent stores, and each binding is cross-checked against the validated allocation ledger. A binding is immutable once written. Retirement history is deliberately retained: if a name is reused after a recorded retirement, that appears as an identity conflict rather than renewed ownership. There is no binding shape for route, firewall, DNS or service kinds yet; those kinds are reported as unsupported rather than partially supported, and their bindings arrive with their consumers.

### Verification and its limit

The preflight re-derives each recorded identity from a complete read-only discovery snapshot: for a namespace it observes the live mount entry, for an interface the scope and current index. A finding of `verified_current` therefore means: the binding recorded at creation still matches the kernel, the lifecycle state is stable, no operation intent is unresolved, and the observation is fresh. Everything else fails closed: missing resources, changed identities, unbound claims, unresolved intents, interrupted lifecycle transitions, observed names after a recorded retirement, and resource kinds with no binding model. Observations that no allocation claims anywhere in the journal are listed separately as unclaimed; they may belong to other software or another ledger, and nothing in this layer makes a decision about them.

This is continuity evidence within a boot session, not an unforgeable certificate, and the report says so rather than implying otherwise. `/run/netns` is tmpfs, so mount identities cannot survive a reboot and must be re-established by an operator after one; a hostile process with write access to the store directory could forge a record, though it would also have to fabricate the matching journal, which makes that escape more demanding than forging names alone. The boundary the layer does draw is strict: a resource name, journal event or allocation token alone never verifies anything, and one unverified allocation fails verification for the whole batch, so no consumer can selectively adopt the convenient subset.

### Startup restoration and cleanup boundary

The verification and recovery-preflight layer does not itself authorise mutation, install a boot-time reconciler or delete anything. Restoration, cleanup and recovery gate on a fresh preflight result and re-verify ownership at the moment of execution. The privileged probe is `tools/probe_ownership_preflight.py`; it exercises exactly one disposable namespace and the rejection path, and leaves the host otherwise untouched.

## Persistent desired-state reconciliation

The saved persistent and transient intent files have always been separate documents, but nothing compared either against resources the tool can prove it owns. persistent-state reconciliation closes that gap as far as is currently defensible: `nord_tools_internal/nordvpn_state_reconcile.py` derives an actual per-profile state from live evidence and classifies convergence, while continuing to perform no network change.

### Deriving actual state

`derive_actual_state` joins three inputs that must all be current and internally consistent: a validated lifecycle journal, the owner-record store of creation-time ownership verification, and a fresh preflight report over exactly the same allocations. Resource names play no part in this: a profile has resources when the preflight classifies them `verified_current`, and `consistent_retired` allocations count as absent. Any other finding becomes a profile blocker with its exact finding carried forward. Observations unclaimed by any allocation remain a separate diagnostic list; they may belong to other software and are never folded into profile state.

Owner bindings now optionally record the provisioned configuration for the profile at binding time. A profile's configuration counts as recorded only when every binding of the profile agrees on an identical record, normalised through the same validation as desired intent; partial or conflicting records leave the configuration unverified. This asymmetry is deliberate. A binding is immutable, so a resource created before configuration recording cannot claim a configuration it does not possess, and the reconciliation must treat absence of evidence as non-convergence rather than as a suspected drift.

### Convergence classification and its limits

`reconcile_desired` compares persistent desired profiles with the derived state and produces one decision per profile: `converged`, `configuration_changed`, `configuration_unverified`, `blocked`, `create_pending` or `retire_pending`. Convergence requires verified resources and an identical recorded and desired configuration. Blocked profiles list their exact blockers; not-desired resources are never removed here and not-desired unverified resources are reported as left alone. Desired profiles without owned resources are `create_pending` and explicitly refuse blind creation: only the production provisioner can establish creation-time authority. `configuration_changed` yields a replacement plan only; no cut-over is executed by this layer.

With an optional dependency graph, a blocked prerequisite blocks every desired dependent, including independently converged ones, matching the offline dependency planner's treatment of unsafe parents. Verified evidence of the dependent's own resources does not compensate for a prerequisite that cannot safely proceed.

Idempotence is a property of the pure classification: the same durable inputs produce a byte-identical report, and a run writes nothing. Interruption state belongs to the recovery executor; the boot executor obtains a fresh preflight at startup and re-verifies ownership at the moment of any privileged action. The plan/report split remains explicit: `safe_to_execute` is always false here, while the executors carry their own execution evidence fields.

## Systemd startup restoration

The boot-scoped restoration executor (`nord_tools_internal/nordvpn_restore_executor.py`) consumes persistent-state reconciliation without treating its classification as mutation authority. Generated systemd wiring invokes it after the network has settled.

### The restoration transaction

`restore-startup` acquires one exclusive advisory lock so two restorations cannot interleave, then installs any absent store (journal, owner bindings, operation intents, run record) exclusively. Everything after that point happens against fresh evidence: complete read-only discovery, ownership preflight over exactly this journal, and reconciliation of the saved persistent policy. Only two situations fall inside the boot path's mutation authority:

- A desired profile with no owned resources at all is restored through its pinned provider tunnel plan.
- A desired profile whose every allocation is freshly observed as kernel-absent (with journal state `active`, a previous boot's `failed` evidence, or a scope that no longer exists) has those stale allocations retired in the journal first, because a namespace that a reboot destroyed possesses no kernel state to delete; bookkeeping alone never removes a live resource.
- Anything else stays untouched: verified-but-undesired resources belong to the confirmed cleanup command, configuration drift is a replacement plan, and present-but-unverifiable observations require review.

The pinned tunnel plan is the operator's authority: one numeric endpoint, peer public key, tunnel addresses, allowed networks and an underlay address pair per profile. Profiles without a plan are reported as not restored, never guessed. The private key arrives through a separate credential input, wired in the unit as `LoadCredential`, so the executor's descriptor boundary from provisioning is preserved end to end and no secret ever appears on a command line or in a store.

### Executor mechanics

The kernel surface is an injected structure (`RestoreKernel`) so offline tests can exercise the full transaction without networking; the production surface reuses the established primitives: descriptor-bound persistent namespace creation (a create-without-retire counterpart of `disposable_namespace`), one restricted underlay wire-up (a single veth pair created and removed only when nothing else exists, with two certified addresses), counter-instrumented firewall installation before any traffic configuration, underlay routing additions confined to the namespace, and the descriptor-validated disposable WireGuard configuration.

The transaction boundary is one pending creation intent on the namespace allocation. Inside the gated operation, allocations advance to `creating`, each resource's kernel identity is recorded in the immutable owner binding store while the descriptor is still held, the namespace end and the tunnel are configured and verified, and only then do lifecycle states reach `active`. Any failure rolls back exclusively what this attempt created (namespace retirement through its own held identity, host-end removal), advances the allocations to `failed`, and re-raises; `execute_recorded_creation` then leaves the intent uncertain for review. The run stops at the first failure: profiles not yet attempted and everything unrelated remain exactly as observed.

### Ordering and idempotency

The unit waits for `network-online.target`, conditions on the startup configuration and the persistent policy, and remains a oneshot with `RemainAfterExit`. There is no timer; the reboot repeat is the only automatic invocation and everything else is operator-initiated. Two properties follow from the evidence-first design: a converged profile is never provisioned twice, so a repeated run within one boot session performs no kernel change, and names are drawn fresh per boot, because reusing a retired name would re-create the very `possible_name_reuse` ambiguity the preflight exists to detect. Dependency graphs, when configured, order restoration and refuse dependents of unrestorable prerequisites, matching the offline dependency planner.

### Separate host and provider boundaries

The namespace restoration executor does not perform host-domain default routing. Host protection has a separate deny-first lifecycle, transaction store and recovery boundary because it changes the host firewall, routes and resolver state. Provider-backed restoration resolves only imported local catalogue entries and fresh saved benchmark data; it never fetches or measures provider data during boot. Nothing in either path grants read authority to a journal, binding or intent store owned by another actor, and a process with store-directory access remains outside the evidence model.

## Ownership-aware cleanup and reset

Cleanup has deletion authority, so it is deliberately the least trusting executor. Its classification derives entirely from fresh ownership preflight over the immutable bindings, and it refuses to act on anything the preflight cannot certify: a profile with any disputed finding is reviewed whole instead of being partly deleted, and `cleanup --execute` refuses to run while any review obligation, unresolved intent or unusable store makes the classification ambiguous.

### The classification

Every owned allocation is classified exactly once, from findings of three kinds: `verified_current` (the binding still matches the live kernel), kernel-absent (`resource_missing` or `scope_missing`: the resource does not exist and only records remain), and `consistent_retired` (recorded and observed absent with nothing to do). Verified resources of a profile retained in the saved policy are preserved; everything verified outside it is removable; kernel-absent records outside it retire with bookkeeping alone, because verification already established that no kernel state is left to delete. Unclaimed observations are listed and never touched.

Profiles mix generations because retirement history is deliberately retained in the journal. That history exists precisely to detect name reuse, so the classification evaluates it instead of deleting it: a single disputed finding anywhere in a profile puts the whole profile under review, and a prerequisite is never deleted while a dependent profile (as declared in the optional dependency graph) stays in place.

### The execution contract

One deletion means: a lifecycle transition to `retiring` and a durable retire intent recorded first; re-verification of the recorded owner identity against the live kernel at the moment of deletion (the namespace mount device/inode pair, or the freshly re-observed host ifindex, which additionally removes name-reuse ambiguity from the deletion window); a fresh observation confirming absence afterwards; then the journal records `retired` and the intent resolves as completed. Namespace deletion removes the namespace-local interfaces and firewall table together with it; the host underlay end deletes by its verified interface index, removing only the pair the project created, and the auto connected route goes with it. No host firewall, route table, DNS file or unrelated configuration is ever flushed, because the executor has no path to them.

Ordering removes dependents before prerequisites, the reverse of restoration order. On the first failure the pending intents become uncertain and the run stops, so a partial cleanup is always attributable and the next run refuses until review. Repeat runs converge: a fully retired ecosystem plans nothing, and the executed report carries a fresh reconciliation of the surviving state.

### Reset and its archive

`clear-ownership` is the confirmed full teardown: every verified owned resource is removed regardless of the saved policy, and only after a byte-verified archiving of the journal, bindings, intents and run record are the stores re-created empty under the exclusive creation semantics of the other stores. The archive retains the immutable retirement records, so name-reuse detection survives the reset through documented evidence instead of being silently erased. The saved policy is left alone, because clearing intent and deleting owned resources are separate decisions.

### The deliberate limits

Resolver directories under `/etc/netns` are the one kind of created namespace state whose identity was never recorded. Removal happens only with explicit `--resolvers` confirmation, only for a verified namespace, and only when the directory contains exactly the expected single `resolv.conf`; anything else requires review. Host-default routes, nftables objects and services use their separate transaction and readback model. Interrupted-cleanup recovery, including a reviewable resume of uncertain retire attempts, belongs to the recovery executor. The cleanup probe (`tools/probe_cleanup.py --run-privileged`) exercises one real pinned restoration and then cleans it on a disposable-capable Linux test host.

## Integrated persistence and cleanup verification

`tools/probe_startup_restoration_lifecycle.py` binds the lifecycle contracts into one workflow on a disposable-capable privileged host. Two pinned profiles restore together while a deliberately different transient policy sits in the runtime scope and is proven inert; a real process death mid-restore converges through the boot and operator authority walls; one authenticated profile is cleaned to its exact deletion set while the shared profile's namespace, bindings and convergence survive untouched; repeat operations leave every classification and the kernel unchanged; and the host's IPv4/IPv6 routes, nftables rules and resolver tables are compared across each stage boundary with any drift failing the run.

The matrix covers recorded retirement without a binding by classifying retired-unbound allocations as consistently retired with the same evidence used for the bound case. Configuration agreement counts only allocations that are not recorded retired, so cross-boot policy changes and partial rollbacks do not wedge a profile against convergence.

The matrix's historical final output identified provider credentials and fastest or country selection at boot, the host-domain default profile's protective routing, real-tunnel DNS and IPv6 acceptance, live replacement, adversarial ownership testing and application launch. Generation replacement, gated launch, the registered packet path and generic desktop-session integration now have scoped privileged acceptance.

## Interrupted-operation recovery

Recovery is the conservative answer to the question every executor here raises: what does the next run do when the previous one died between two durable writes? The seven possible crash points of the creation transaction and the three kernel states of an interrupted retirement are all finitely enumerable, so recovery plans from the stores and a fresh observation, classifying each unresolved intent and each interrupted record, and the boot wall plus the operator's explicit execution decide which classifications may act.

### Classification from evidence

A pending or uncertain intent makes the readiness gate report `uncertain_intent` for its allocation regardless of what is in the kernel, so recovery judges absence itself from the fresh observation: is the namespace mount still the recorded mount identity; is the interface still at its recorded index inside the recorded scope; does a recorded binding exist at all. Six dispositions result: `complete_creation` for a generation whose whole binding set was recorded and still matches, `rollback_creation` for a half-built one, `resolve_create_failed` and `complete_retirement_records` for resources the kernel does not hold, `resume_retirement` for a confirmed retirement still pending, and `review_required` for lookalikes, live-but-unbound resources and mixed evidence. The last category is treated profile-conservatively, so an executable item never touches a generation beside a lookalike.

### The two authority walls

Boot recovery runs as the first phase of every `restore-startup` and is deliberately weaker than the operator's. It finishes certified bookkeeping, rolls back a half-built creation recorded with a pending intent (deleting the identity-verified namespace and re-provisioning fresh), and resolves records for absent resources whose attempts failed. Anything else aborts the boot with the exact evidence; uncertain intents, operator-authority items and unresolved disputes stay put. Operator execution of the same command widens the authority deliberately: it also resumes confirmed retirements, rolls back anything the boot wall refused, and resolves uncertain outcomes to `completed` or `failed`, because a human invoked it. The extension to the operation intent schema is correspondingly narrow: uncertain intents are resolvable only through the recovered-resolution entry point, and no new fields were invented to record the consent; the recovery report itself is the decision record.

Options that make recovery correct rather than clever: names and bindings are never guessed for a missing record; active generations are never dragged down by a sibling's rollback; the host remains outside every path except the identity-verified delete of owned namespaces and interfaces; and the interrupted shutdown unit shows up on the next boot as the same evidence a manual crash leaves. Repeat runs converge and the host shows nothing left, which is what the privileged probe verifies under real process death.

The README concentrates on commands and current capabilities; this design document retains the reasoning and safety boundaries. Generation replacement now assigns a distinct kernel ownership profile to each allocation generation. B is provisioned through the production restoration machinery and must pass fresh creation-time ownership and packet-level readiness before a durable selection change. Launch selection, ownership verification and lease reservation occur under lifecycle-then-consumer authority; existing processes remain in A. Exact-generation leases block only A retirement, which delegates to the ownership-verified cleanup executor. The handover journal coordinates this flow but never substitutes for live kernel evidence. Scoped privileged generation replacement, interruption recovery, production VPN-bound launch-to-packet and generic desktop-session acceptance have passed. Compositor-specific services remain outside that claim.

## Startup restoration and cleanup verification

Startup restoration and cleanup include creation-time ownership verification, persistent-state reconciliation, journal-gated restoration, ownership-aware cleanup, interruption recovery and an integrated acceptance probe. The current verification scope and limitations are recorded in [Release status and verification](RELEASE-READINESS.md).

### Host-domain default protection

The original `assess_host_default_protection` helper remains a read-only compatibility boundary. It still returns a non-executable assessment and cannot be used as mutation authority. Executable plans use the separate, closed `HostProtectionPlan` schema: one IPv4 and one IPv6 tunnel address, both default AllowedIPs, dual-stack DNS, a pinned numeric endpoint, a name-and-index physical egress binding, dedicated route table and rule priorities, and the fixed `inet nord_tools_host` firewall identity.

The first executable host arrangement is intentionally restrictive. It requires a stable static IPv4 physical egress, an IPv4 WireGuard endpoint and `systemd-resolved`; it refuses NetworkManager, firewalld, UFW and other WireGuard interfaces. DHCP, IPv6 neighbour discovery and router-advertisement renewal over the physical underlay are not permitted by the host output policy, so an address or endpoint which depends on them is unsupported. The dedicated nftables table installs input, output and forwarding base chains at priority -200 with default-drop policies. At first it permits loopback and tunnel-interface output; established inbound traffic is restricted to the tunnel interface, while inbound WireGuard transport packets are restricted to the pinned physical interface, endpoint source address, local underlay destination and UDP source port. The endpoint output exception is a later, separate rule restricted to the pinned physical interface, source address, numeric destination, UDP destination port and WireGuard socket mark. This is mark-based confinement, not cryptographic socket identity: a process with sufficient privileges to set the same mark or change the firewall remains outside the cooperating-process security boundary. Existing non-VPN underlay sessions are deliberately not preserved by the input barrier.

Routing uses one destination-specific rule to retain the endpoint's main-table underlay path, followed by IPv4 and IPv6 rules for a dedicated table containing only tunnel defaults. Route retirement re-reads both families before each mutation and deletes rules with their exact priority, destination and table selectors, and routes with their interface, table and protocol selectors. Any mismatch stops retirement without removing the deny barrier. This does not make a sequence of kernel operations atomic against independent privileged mutators. Resolver configuration is attached to the WireGuard link through `systemd-resolved`; installation requires matching link readback, and retirement checks the original link index and expected assignment before reverting it. Existing resolver configuration is not overwritten, and the firewall prevents it becoming a direct-underlay fallback. These checks do not establish that applications use the resolved stub; real DNS and packet acceptance remains necessary. The interface is removed only after resolver and routing retirement. The endpoint exception is removed before the deny table, and removal of that final table requires an explicit traffic-exposure confirmation.

The host store records boot identity, generation, plan digest, operation state and intent/readback evidence for every mutation. A pending or uncertain step blocks ordinary retry. Recovery does not adopt a pending creation merely because a matching object is observed: without durable creation identity, that object could belong to another actor. It can certify absence for a safe creation retry; interrupted retirement can resume only when the original observed creation evidence still identifies the live resource. Ambiguous evidence remains uncertain, and recovery never removes the barrier automatically. Status compares every recorded identity with live state and distinguishes absent, preparing/protected-unavailable, active/verified, degraded and uncertain states.

Persistent startup uses a separate early systemd unit with `DefaultDependencies=no` and ordering before `network-pre.target`. It waits for the filesystems containing its inputs, installs and verifies only the deny barrier, and isolates `emergency.target` if that step fails. A second unit requires the barrier, waits for `network-online.target`, receives the private key through `LoadCredential` and continues endpoint, WireGuard, route and resolver activation. Prior-boot evidence is archived only when every recorded object is absent, and neither unit automatically deactivates protection. Disposable verification covers the ordinary packet, DNS and verified-retirement lifecycle; unavailable-peer activation; tunnel loss; uncertain readback refusal; interrupted retirement recovery; and real reboot ordering. Deployment remains limited to the accepted static-egress profile rather than treating those guest results as general host compatibility.

Host lifecycle status rechecks live tunnel readiness rather than treating the durable active outcome and matching resource identities as sufficient evidence of a usable tunnel. A missing handshake or resolver/route readiness downgrades status while the verified deny barrier remains in place. Activation cannot resume a retirement transaction, and ordinary deactivation refuses an incomplete activation: these states require explicit recovery review rather than an implicit reversal of the transaction. During a resumed retirement, even steps previously recorded absent are checked again before proceeding, so reappearing resources cannot be ignored on the way to removing the final barrier. These checks remain subject to the documented limits of non-atomic kernel observations and require privileged packet and interruption acceptance.
