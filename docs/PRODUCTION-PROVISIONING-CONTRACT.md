# Production provisioning contract

The read-only `validate_provisioning_contract` boundary correlates the configured VPN profiles with validated public WireGuard specifications and candidate namespace/interface allocations. Every configured profile must have exactly one tunnel specification and exactly one candidate namespace and interface. Additional profiles, missing resources, reused allocation tokens and mismatched identifiers are refused.

The result is deliberately credential-free and reports `ownership_verified: false`, `mutation_authorised: false` and `network_changes_applied: false`. An allocation token does not prove that Nord Tools created or still owns a kernel resource. The contract cannot replace creation-time owner bindings, fresh kernel observations, lifecycle locking, durable operation intents or mutation-time ownership verification. Those requirements remain the privileged executor's responsibility.

This boundary establishes a shared shape for subsequent production provisioning integration. It is not a new privileged entry point, and it does not change existing experimental provisioning or operational management behaviour.

The read-only `validate_provisioning_owner_bindings` check additionally requires the complete set of recorded creation-time owner bindings to match the allocation ledger by token, resource kind and identifier. Missing, additional, malformed or conflicting records are refused. A consistent recorded binding is historical evidence only: the result continues to report unverified ownership and no mutation authority. Production execution still requires fresh kernel identity checks, an authorised lifecycle lock and a durable operation intent at the actual mutation boundary.

## Production creation boundary

The boot restoration executor validates its actual four-resource creation batch before appending new allocations to the lifecycle journal. The batch consists of the namespace, WireGuard interface, namespace-side underlay and host-side underlay. Profile, kind, name and allocation-token collisions with existing journal entries are refused. A fresh kernel observation also refuses newly occupied candidate names before recording the creation intent. The executor then retains its existing lifecycle lock, durable intent, descriptor-bound namespace creation, progressive creation-time owner binding and verification sequence.

The offline two-resource contract remains a diagnostic contract for the tunnel and namespace pair. It does not require creation-time owner bindings for resources that have not yet been created. Neither the offline contract nor the four-resource validation is independent authority to mutate kernel state. Independent privileged actors can still race the observation and creation boundary; the accepted cooperative authority model and conservative failure behaviour remain in force.

## WireGuard interface creation identity

The disposable WireGuard creation path checks the namespace-local interface index immediately after creating the device and again after applying peer configuration. A missing, invalid or changed index stops subsequent address assignment and activation. This is a creation-time consistency check, not an ownership claim about an arbitrary pre-existing interface. The caller remains responsible for durable intent, descriptor-bound namespace ownership and rollback. Independent privileged mutation between checks remains outside the cooperating-process authority model.

## WireGuard peer configuration

The disposable configuration path accepts an optional persistent keepalive interval from 0 to 65535 seconds. Zero leaves the peer setting unset; a positive interval is passed explicitly to `wg set` alongside the validated endpoint and allowed IP networks. Booleans, strings and out-of-range values are refused before kernel mutation. The public plan records the interval but never carries the private key.

The private key is still supplied through an inherited descriptor, not an argument or a persistent configuration file. The subsequent restoration readback verifies live peer configuration; this configuration step alone does not provide persistent production credentials or establish fail-closed routing. Those require later integration and privileged acceptance.

## WireGuard live peer verification

The production restoration executor checks the derived local public key and the sole expected peer, then reads back the peer endpoint, allowed IPs and persistent keepalive through separate non-secret `wg show` fields. Any mismatch or failed command refuses activation and leaves the existing creation intent and rollback machinery responsible for recovery. The verifier never invokes `wg show ... dump`, whose output can contain private-key material. The checks establish the configured peer values at observation time, not successful connectivity or protection against a separate privileged mutator racing later operations. The ownership-aware cleanup path refuses ambiguous kernel observations and passed the existing five-stage privileged lifecycle matrix. A separate disposable WireGuard acceptance probe now checks non-secret endpoint, allowed-IP and keepalive readback, followed by namespace absence after retirement. The targeted probe has passed privileged execution on the accepted candidate. Neither probe establishes real-tunnel DNS confinement, IPv6 leak prevention or production provider connectivity.

## Named-profile resolution

`resolve_named_profiles` validates the complete version-one policy before returning an immutable ordered sequence of named entries with detached profile descriptions. An omitted selection resolves every profile in lexical name order; an explicit empty selection resolves none. Duplicate, unknown or malformed requested names are rejected. Each entry identifies whether it is the configured default.

This is an offline resolution contract only: it does not create resources, authorise privileged mutation or establish shared-tunnel ownership.

The disposable WireGuard peer-field and retirement probe passed privileged acceptance. The accepted scope excludes production DNS confinement, application routing and independent privileged kernel mutators.

## Independent named-profile provisioning

The production restoration executor already processes eligible named profiles under its lifecycle lock and records a separate four-resource allocation batch, ownership bindings and durable creation intent for each profile. Multi-profile regression coverage now exercises two distinct pinned profiles, verifies that namespace and interface identities do not overlap, and confirms that a repeated restoration does not create further resources. A desired profile without a pinned provider plan is reported as not restored while another eligible profile can proceed.

These tests use an injected kernel harness and do not establish real concurrent VPN connectivity, shared-tunnel ownership, application routing or independent profile retirement. Those boundaries remain separate acceptance work.

## Selected-profile retirement

The ownership-aware cleanup executor accepts an explicit tuple of profile names to constrain retirement. An empty tuple makes no changes, while an omitted selection retains the established desired-policy cleanup behaviour. Unknown and duplicate names are refused. Resources belonging to unselected profiles remain outside the deletion plan, even if their ownership evidence would otherwise require review. Explicitly selected profiles can be retired even when present in the desired policy, but only after the existing ownership checks and dependency constraints pass. This does not establish application routing or shared tunnel ownership.

## Selected-profile lifecycle reconciliation

Adversarial cleanup tests verify that a selected prerequisite cannot be retired while an unselected dependent remains, while a selected dependent can be retired without deleting its prerequisite. A selected-profile deletion failure leaves unselected profiles untouched, and repeated successful retirement produces no further deletion. These tests use an injected kernel harness; the dedicated two-profile retirement probe has passed privileged acceptance, including preservation of the unselected profile and final teardown. The existing ownership and dependency checks remain the authority for deletion.

## Logical shared and isolated ownership

`resolve_ownership_groups` groups registered application consumers by their validated allocation keys. Applications using a shared profile contribute to one logical group, while applications using an isolated profile retain separate groups even when their VPN selection is identical. The groups and their consumer lists are immutable, deterministic and detached from the input policy. An unused profile does not create a consumer group. These keys are planning identities only: they are not kernel resource identifiers, persistent reference counts or proof that a tunnel can safely be reused or retired. The production lifecycle uses these keys to derive kernel allocation identities, but the keys alone remain insufficient to authorise privileged operations.

## Consumer reference release planning

`plan_consumer_release` evaluates an explicit set of registered application consumers against the validated policy. Releasing one consumer of a shared profile leaves the logical allocation retained while another registered consumer remains. Isolated application allocations are evaluated independently. Invalid or repeated consumer names are rejected, and results are immutable and deterministic. A result with no retained consumers means only that retirement can be considered; it does not provide a persistent reference count, verify a live tunnel or authorise resource deletion. The ownership-aware executor remains the sole destructive path; durable consumer evidence is checked separately from this read-only release plan.

Consumer-aware cleanup can optionally require a validated policy and an explicit release set alongside selected profiles. It refuses a selected profile when any registered consumer remains, and also refuses profiles without a released consumer group. This conservative check applies before any ownership-aware deletion is planned. It is not a durable live reference registry: callers must not treat policy-derived release decisions as proof that runtime consumers have actually stopped. The production cleanup executor continues to require independent creation-time ownership verification before deleting resources.

## Persisted consumer reference evidence

A private, versioned consumer-reference snapshot records a complete mapping of registered applications to their profile and logical allocation key, together with a declared active flag. The writer validates the entire snapshot, writes a restricted temporary file, synchronises it and replaces the target atomically. The reader rejects missing, symlinked, malformed, incomplete and policy-inconsistent evidence. When explicitly supplied to selected-profile cleanup, an active reference prevents retirement inside the existing lifecycle lock.

The snapshot is not a runtime reference registry. Its active flags are declared rather than independently attested, and an inactive flag cannot establish that a process has exited or that a tunnel is no longer in use. This evidence is an additional refusal condition, never deletion authority. Process-bound leases and independently verified kernel allocations provide separate operational evidence.

## Consumer reference transitions

Declared consumer references can be updated under a private advisory lock with an expected-state check. The transition refuses absent snapshots, unknown applications and stale state. This prevents competing cooperating writers from silently overwriting each other, but does not establish that an application started, stopped or released its tunnel. These declared transitions cannot authorise retirement; process-bound leases and kernel ownership verification are separate requirements.

## Consumer reference coordination during retirement

The cleanup executor holds the consumer-reference store's advisory lock throughout a guarded retirement operation, including kernel mutation. Cooperating reference transitions use the same lock, preventing a new declared acquisition from racing between the retirement check and deletion. Unsafe or replaced lock files are refused. This protects the consistency of declared reference evidence but does not establish process identity or kernel ownership. Runtime leases use the same reference-lock boundary, and isolated consumer retirement requires that evidence explicitly.

## Process-bound consumer evidence

The runtime consumer lease store records a registered executable, process ID, boot identity and process start time, together with the logical allocation key. Acquisition checks the live Linux process identity and refuses mismatched executables or duplicate consumer leases. Release refuses a process that still has the original identity, and accepts a vanished process or a reused PID with a different start identity. The store is policy-fingerprinted, serialised and atomically persisted. A failed or inaccessible process inspection does not silently discard a lease. A missing lease is not proof that a process is no longer using a tunnel.

`acquire_provisioned_consumer` is the ownership-verified acquisition path. It takes the established lifecycle lock before the consumer-reference lock, reads the durable journal, owner bindings and operation intents, and performs a fresh kernel ownership preflight. It refuses acquisition unless the consumer's kernel allocation has exactly one namespace and three interfaces, all with active lifecycle states and independently verified current owner bindings. The process identity is checked again before committing the lease. This operation binds a cooperating process to existing resources; it does not launch the application, change its network namespace or grant access to arbitrary resources.

## Shared and isolated production allocations

Production restoration expands isolated application consumers into distinct, deterministic kernel profile identities. These identities are derived from each application's logical allocation key and are recorded in the existing lifecycle journal, owner bindings and durable creation intents. Shared consumers retain the same kernel profile identity and resources. An unused isolated profile remains available for explicit named-profile management, but once it has registered consumers its template is not provisioned as an additional shared resource. Restoration refuses to reinterpret an existing live template allocation as consumer-owned resources; it requires explicit review and retirement instead.

Each isolated allocation can have its own pinned provider tunnel plan under its generated kernel profile identity. Credentials may be inherited from the original provider profile or pinned per allocation. Because overlapping host underlay networks would make routing ambiguous, restoration refuses overlapping host underlay plans before changing the kernel. Operators provisioning multiple isolated consumers must supply non-overlapping underlay addressing. The allocation mapping does not select providers or invent network addresses, and it cannot guarantee that an operator-supplied network is conflict-free with unrelated host routing.

Selected retirement resolves consumer references against the kernel allocation identities rather than treating every isolated consumer as a reference to one profile-wide resource. A retained lease vetoes retirement of its own allocation. Consumer-specific isolated retirement requires the durable runtime lease store and the validated policy; missing evidence is a refusal, not permission to delete. The existing identity-verified cleanup executor remains the sole destructive authority, with its lifecycle and reference locks held through deletion. Shared allocations remain protected by their registered consumer references and active leases.

An interrupted acquisition cannot silently replace an existing lease. A crashed consumer leaves its durable lease until its process identity can be shown to have exited or changed. An unreadable process is not silently released, and uncertain kernel ownership remains subject to the existing recovery and operator-review path. These are conservative cooperating-process guarantees, not an atomic transaction spanning process execution and the kernel. The isolated consumer retirement probe has passed privileged end-to-end acceptance. Application launching and resistance to independent privileged kernel mutators remain outside this implementation's acceptance evidence.

## Isolated consumer retirement acceptance

The opt-in `tools/probe_isolated_consumer_retirement.py` exercises two independently provisioned isolated allocations with real kernel resources. Before retiring either allocation, it verifies that a durable outstanding lease refuses retirement and that release evidence for one application cannot authorise retirement of another application’s allocation. It then verifies selected retirement, preservation of the unrelated allocation, idempotent repeated retirement and final resource removal. Run with `sudo python tools/probe_isolated_consumer_retirement.py --run-privileged` on a disposable test host with the required networking capabilities. Failed probes retain diagnostic evidence for operator review.

The operator confirmed successful privileged execution of the expanded adversarial probe, including outstanding-lease and cross-allocation refusal checks, as well as passing Ruff, formatting and the full automated suite. This acceptance is limited to the tested cooperating-process ownership model and does not establish application routing or protection against independent privileged kernel mutators.

## Failed provisioning rollback identity

A failed restoration attempt retains an uncertain creation intent even when best-effort rollback appears to succeed. The host underlay interface rollback captures the interface index immediately after creation and uses the same identity-checked indexed deletion mechanism as confirmed cleanup. A replaced or missing host interface is not deleted by name alone. Rollback failures are reported on the original exception; subsequent recovery must use fresh ownership evidence rather than assuming the kernel is clean. This does not establish transaction-wide atomicity or safe deletion against independent privileged kernel mutators.

## Provisioning failure and rollback assessment

A failed creation retains an uncertain durable operation intent even when its best-effort rollback callbacks succeed. The restoration executor re-observes the namespace and host-interface scopes after rollback and records an exception note when a resource remains or observation is unavailable. This assessment is not deletion authority: unexpected resources and reused names remain subject to creation-time ownership verification and operator recovery. Deterministic fault injection covers each provisioning boundary. Privileged interruption recovery has passed after creation and durable binding of a live namespace, but interruption after subsequent interface and routing mutations remains outside the tested checkpoint coverage.

## Interrupted provisioning recovery acceptance

The privileged recovery probe supports two deliberate process-death boundaries. Its default mode kills a child after the creation intent is durable but before kernel creation. The `--after-binding` mode instead kills the child immediately after the namespace has been created and its creation-time mount identity has been durably recorded, before the underlay and WireGuard interfaces are configured. The latter mode verifies that the namespace is actually present at the checkpoint, then exercises the existing boot and operator recovery paths and confirmed cleanup. Neither mode treats a matching name as deletion authority; recovery continues to require the recorded identity and fresh kernel verification. A failed probe retains its disposable evidence for inspection. The operator confirmed successful privileged execution of the `--after-binding` checkpoint, including recovery convergence and confirmed teardown. These probes do not establish protection against independent hostile privileged mutators.

## Explicit production management commands

`python nord_tools.py manage provision --config /absolute/path/startup.json` validates the pinned startup configuration and reports its profile names without inspecting or changing kernel state. Adding `--execute` invokes the existing ownership-checked restoration and interrupted-operation recovery executor. It is persistent-only and does not select provider endpoints or credentials. The preview is not a safety preflight or a promise that execution will succeed.

`python nord_tools.py manage retire-consumers --config /absolute/path/startup.json --consumer application --runtime-consumers /absolute/path/leases.json` scopes cleanup to the allocations of explicitly registered applications. The default invocation plans retirement; `--execute` requests verified deletion. Shared allocations cannot be retired while another registered consumer remains. Isolated allocations require durable runtime evidence, and optional `--consumer-references` can add a separate declared-reference check. The command does not terminate processes or create release evidence. The cleanup executor independently checks the pinned ownership records and refuses uncertain or incomplete evidence.

These commands reuse the production executors and do not bypass their existing authority model. Neither command implements application launching, production DNS confinement or unrestricted live replacement.

## Runtime consumer lease management

The `manage consumer-leases --config STARTUP --runtime-consumers LEASES` command reads and validates the process-bound lease store against the pinned registered policy. It does not infer whether a process is alive, release leases or mutate kernel resources.

The `manage release-exited-consumer --config STARTUP --runtime-consumers LEASES --consumer NAME` command previews a registered consumer lease release without checking process exit or modifying the store. Adding `--execute` delegates to the existing process-identity-verified release operation. A live process, inaccessible process evidence, missing lease or inconsistent policy causes refusal. Releasing a lease does not retire its kernel allocation; resource retirement remains a separate, ownership-verified operation. Both commands reject transient scope.

The `manage acquire-consumer --config STARTUP --runtime-consumers LEASES --consumer NAME --pid PID` command previews a requested consumer lease without inspecting kernel resources. With `--execute`, it delegates to the existing process-bound acquisition executor, which independently verifies the process identity and complete, active, ownership-verified provisioned allocation before persisting the lease. This does not launch the process or move it into a network namespace. Acquisition requires the startup configuration to pin the journal, ownership bindings and operation intents.

## Production provisioning integration acceptance

The disposable production provisioning integration probe runs the existing authority, named-profile, isolated-consumer and post-binding interruption probes in a fixed, fail-fast order. Run `python tools/probe_provisioning_integration.py` to inspect the stages without changing the host. An operator may explicitly run `sudo python tools/probe_provisioning_integration.py --run-privileged` on a suitable Linux host with `ip` and `wg` installed. Each child probe retains its own diagnostic evidence on failure. The runner deliberately does not attempt cleanup after a failed stage, since that could discard the evidence needed for ownership-aware recovery.

The matrix exercises production resource creation, recorded ownership, selected retirement, isolation between consumer allocations, outstanding lease refusal, interrupted provisioning and confirmed recovery. Successful execution establishes these behaviours only under the documented cooperating-process authority model. It does not establish protection against an independent privileged kernel mutator, production application launching, or DNS and firewall confinement. Later mutation-boundary interruption and adversarial recovery acceptance remain outstanding.

## Later provisioning interruption acceptance

The opt-in `tools/probe_later_recovery.py` runner exercises three additional production checkpoints using disposable, independently created ecosystems: after the host underlay has a durable creation-time interface binding, after WireGuard configuration returns, and after tunnel routing installation returns. Each checkpoint pauses the child after the real kernel operation, terminates it with SIGKILL, checks retained intent and creation-time ownership evidence, and attempts recovery through the existing operator and boot recovery paths. The runner stops on the first failure and retains diagnostic evidence rather than deleting resources whose ownership is uncertain.

Run `sudo python tools/probe_later_recovery.py --run-privileged` on a disposable-capable Linux host with `ip` and `wg` installed. Without `--run-privileged`, the runner only describes the planned checks. A successful result demonstrates the tested cooperating-process interruption boundaries, not protection against independent hostile root-level mutation. These later checkpoints require local privileged acceptance before they can be marked complete.

## Complete provisioning acceptance

The `tools/probe_provisioning_final_acceptance.py` runner combines the production integration matrix with the later interruption-recovery matrix. Its default invocation only previews the stages. Privileged execution requires `--run-privileged` and root authority. Each delegated probe owns its disposable resources and retained diagnostic evidence; the runner stops on the first failure and does not attempt cross-probe cleanup. The acceptance matrix exercises cooperating-process ownership guarantees and does not establish protection against hostile privileged kernel mutation, DNS confinement or fail-closed application routing.

Automated tests verify runtime behaviour and structured security contracts rather than matching the wording of Markdown documents or the checked state of roadmap entries. Markdown formatting remains a documentation linting concern, not a runtime correctness invariant.

The consolidated provisioning acceptance increment has been accepted by the operator. This acceptance does not extend the documented authority model to independent privileged kernel mutation or establish production DNS confinement and fail-closed application routing. Documentation prose and roadmap checklist wording are not runtime acceptance criteria.

## Production firewall readback hardening

The production restoration path installs a dedicated namespace-local nftables table before creating or activating the WireGuard device. Installation now verifies both the three default-drop base chains and the exact allow-rule expressions for loopback, established replies, tunnel output and the pinned numeric UDP endpoint. Unexpected or altered rules cause provisioning to fail with uncertain evidence rather than treating chain-only readback as sufficient. This readback is not proof of packet confinement, tunnel-loss behaviour or DNS leak prevention. The JSON expression contract must be verified against the installed nftables version during privileged acceptance.

## Firewall readback object restrictions

The production isolation readback rejects unrecognised nftables objects in its dedicated table, including flowtables, in addition to verifying the default-drop chains and exact allow rules. This check does not prove packet-level confinement or compatibility with every nftables JSON version; privileged kernel acceptance remains required.

## Disposable dual-stack packet acceptance

Run `sudo python tools/probe_dual_stack_packet_policy.py --run-privileged` to exercise the production isolation policy's narrowly pinned UDP endpoint exception and unrelated underlay drops using kernel counters, followed by IPv4 and IPv6 route selection and tunnel-loss fallback checks in separate disposable namespaces. Run without `--run-privileged` to preview the checks without creating resources. The runner stops on the first failure and leaves each underlying probe responsible for its own cleanup and diagnostic output.

These checks deliberately do not establish real WireGuard packet delivery, application DNS confinement, or production fail-closed behaviour. The routing probe uses a dummy tunnel, and full real-tunnel and resolver acceptance remains outstanding.

## Dual-stack namespace default routes

The production routing installer adds both IPv4 and IPv6 default routes through the WireGuard interface after installing the endpoint-specific underlay route. It refuses a failure in either default-route installation, leaving the surrounding provisioning transaction to handle rollback. A tunnel configured for one address family does not thereby gain working connectivity for the other family; the additional route prevents an implicit underlay fallback rather than guaranteeing service. Namespace firewall enforcement is a separate boundary. Real-tunnel packet and tunnel-loss acceptance remains outstanding.

Production route activation now requires live readback of both namespace default routes and the peer endpoint's longest-prefix route. The readback refuses missing, duplicated, gateway-bearing or underlay-directed defaults and an endpoint route that does not select the pinned namespace underlay. This check is a point-in-time activation condition and does not protect against independent privileged route mutation after verification. Real WireGuard packet confinement, DNS and tunnel-loss acceptance remain outstanding.

### Integrated privileged routing acceptance

Run `sudo python tools/probe_production_routing_acceptance.py --run-privileged` to execute the production provisioning integration, real WireGuard encrypted exchange and shutdown with host-integrity observations, and disposable dual-stack endpoint/firewall/route policy checks in one fail-fast sequence. Run `ruff check .`, `ruff format --check .` and `python -m pytest -q` separately for the source quality gate. Each stage reports its own evidence and retains its own failure handling.

The real WireGuard experiment is independent of the production provisioning executor and does not install its firewall policy. The dual-stack policy probe uses a simulated tunnel. Consequently, even passing the integrated runner does not prove production real-WireGuard packet confinement, DNS leak prevention or production tunnel restart safety. Those claims remain blocked pending a probe that combines production firewall/routing installation with a real tunnel and observed packets.

The real-WireGuard host-integrity probe compares nftables JSON structurally, ignoring only live packet and byte measurements inside counter expressions. Counter statements, rule handles, verdicts, policies and other firewall configuration remain part of the comparison. This prevents unrelated UFW traffic from causing a false host-configuration failure while continuing to reject firewall modifications.

### DNS confinement acceptance

A pinned `dns_servers` list causes authorised provisioning to install an exclusive namespace-local resolver only after the namespace firewall, dual-stack default routes and WireGuard peer have been configured. Before activation, DNS destination-specific routes, live peer AllowedIPs and exact resolver contents are checked. A DNS address outside the peer's AllowedIPs is rejected even when the kernel route points at WireGuard. Cleanup of namespace resolver files remains an explicit `--resolvers` operation, guarded by the existing namespace ownership checks. Existing deployments without a DNS list retain their previous behaviour.

`sudo python tools/probe_wireguard_dns_acceptance.py --run-privileged` tests a disposable real WireGuard pair, dual-stack DNS-shaped UDP exchange, namespace resolver visibility, tunnel-loss route behaviour and host-network integrity. It requires a trusted `/etc/netns` directory and does not install a host resolver or change the host firewall. This probe does not certify the production-installed firewall and real WireGuard tunnel together, or guarantee that applications cannot select external DNS mechanisms such as DNS-over-HTTPS. Production DNS confinement remains conditional on those separate application and packet-policy boundaries.

### Consolidated adversarial routing and DNS acceptance

`sudo python tools/probe_network_isolation_adversarial_acceptance.py --run-privileged` runs the accepted production provisioning and dual-stack routing probes, disposable real-WireGuard DNS confinement, late-stage interrupted provisioning recovery and cooperating-process lock substitution refusal. It takes an additional counter-aware snapshot of host IPv4/IPv6 routes, nftables configuration and resolver contents before and after the entire matrix, including when a child fails. A failed child stops later stages; the runner never assumes authority to clean up another probe's resources.

Resolver readback also rejects multiply linked files and verifies the opened descriptor against the originally inspected inode, so replacement between pathname inspection and opening is refused. These are bounded readback checks, not protection against independent privileged mount or kernel mutators.

The acceptance matrix does not send DNS packets through the firewall installed by the production provisioning executor on the same live tunnel, does not test application-level DNS bypass and does not prove automatic fail-closed protection of the host's default profile. The privileged evidence must be reported with these limits. Do not describe the production system as universally leak-proof or production-ready on the basis of this matrix alone.
