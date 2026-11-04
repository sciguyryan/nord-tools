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

An interrupted acquisition cannot silently replace an existing lease. A crashed consumer leaves its durable lease until its process identity can be shown to have exited or changed. An unreadable process is not silently released, and uncertain kernel ownership remains subject to the existing recovery and operator-review path. These are conservative cooperating-process guarantees, not an atomic transaction spanning process execution and the kernel. Privileged end-to-end testing, application launching and independent privileged mutator resistance remain outside this implementation's acceptance evidence.
