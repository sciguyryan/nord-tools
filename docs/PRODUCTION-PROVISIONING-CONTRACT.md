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

The private key is still supplied through an inherited descriptor, not an argument or a persistent configuration file. This phase does not verify live peer state, provide persistent production credentials or establish fail-closed routing. Those require later integration and privileged acceptance.

## WireGuard live peer verification

The production restoration executor checks the derived local public key and the sole expected peer, then reads back the peer endpoint, allowed IPs and persistent keepalive through separate non-secret `wg show` fields. Any mismatch or failed command refuses activation and leaves the existing creation intent and rollback machinery responsible for recovery. The verifier never invokes `wg show ... dump`, whose output can contain private-key material. The checks establish the configured peer values at observation time, not successful connectivity or protection against a separate privileged mutator racing later operations. Controlled retirement and privileged end-to-end acceptance remain open in 8.2.2.
