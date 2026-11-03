# Production provisioning contract

The read-only `validate_provisioning_contract` boundary correlates the configured VPN profiles with validated public WireGuard specifications and candidate namespace/interface allocations. Every configured profile must have exactly one tunnel specification and exactly one candidate namespace and interface. Additional profiles, missing resources, reused allocation tokens and mismatched identifiers are refused.

The result is deliberately credential-free and reports `ownership_verified: false`, `mutation_authorised: false` and `network_changes_applied: false`. An allocation token does not prove that Nord Tools created or still owns a kernel resource. The contract cannot replace creation-time owner bindings, fresh kernel observations, lifecycle locking, durable operation intents or mutation-time ownership verification. Those requirements remain the privileged executor's responsibility.

This boundary establishes a shared shape for subsequent production provisioning integration. It is not a new privileged entry point, and it does not change existing experimental provisioning or operational management behaviour.
