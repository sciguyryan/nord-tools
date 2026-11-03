# Provisioning lifecycle inspection

`inspect_provisioning_lifecycle` correlates the complete profile-to-tunnel contract with creation-time ownership bindings, the lifecycle allocation ledger and read-only Linux discovery evidence. A missing or additional allocation, inconsistent binding, malformed discovery snapshot or unresolved operation intent is not silently accepted as proof of ownership.

The result is diagnostic. The `lifecycle_continuity_verified` field reports the ownership preflight classification of supplied evidence; it is not a capability or authorisation token. The returned `ownership_verified`, `mutation_authorised` and `network_changes_applied` fields remain false. The inspection does not hold an executor lock, obtain fresh kernel descriptors or write durable mutation intents.

Privileged provisioning must independently establish the accepted 8.1 lifecycle authority boundary at the point of mutation. In particular, previously collected discovery snapshots and recorded creation identities must not be reused as permission to create, modify or remove an interface. Integration of that privileged execution path and its Linux acceptance tests remains outstanding within 8.2.1.
