# Live update policy

Nord Tools does not support general in-place updates of a live VPN allocation. This is a deliberate release boundary, not an unfinished executor.

A production allocation combines a WireGuard interface and client identity, endpoint route, two default routes, namespace firewall, resolver file, lifecycle records, creation-time ownership bindings and application leases. Updating those objects one at a time would expose a mixed generation that no single durable record described. Fresh ownership evidence can show that the current objects belong to Nord Tools; it cannot make a partial rewrite atomic or prove that a changed object still matches the other recorded objects.

`manage apply-live --config PATH` therefore remains create-only. Its fresh reconciliation report now includes `update_policy`, which always reports `in_place_updates_supported: false` and maps each allocation to an existing explicit lifecycle:

| Reconciliation result | Required strategy |
| --- | --- |
| `converged` | No action. |
| `create_pending` | Create the independently verified-absent allocation with `apply-live --execute`. |
| `configuration_changed` | Use generation replacement when the logical profile and allocation key are known. |
| `retire_pending` | Use the ownership-verified retirement commands. |
| `configuration_unverified` or `blocked` | Stop for operator review; no mutation is authorised. |

For replacement-eligible shared and isolated allocations, the report supplies the logical profile and allocation key. The operator must still choose distinct old and replacement generation identifiers and provide the runtime lease store. Read-only reconciliation never invents those durable identities or starts a replacement automatically.

Edits to startup tunnel plans, imported catalogues or benchmark reports do not rewrite a converged live allocation. Automatic provider reselection is unsupported. To adopt new public tunnel data or a new provider identity, prepare an explicit independent generation, verify it through the existing replacement path, cut new launches over through the durable handover and retire the old generation only after its leases are gone. Where the replacement path cannot represent the proposed allocation, retain the current generation and use an explicit verified retirement followed by creation during an operator-approved interruption.

This policy does not repair disputed drift. A missing configuration record, uncertain owner binding, unresolved operation intent, foreign object or inconsistent observation remains quarantined for operator recovery. Generation replacement is authority only for independently owned A and B allocations; it is not permission to edit or delete a disputed object.

Because the release supports no in-place mutation design, this boundary is verified through the scope decision and static refusal coverage rather than a separate privileged mutation probe. Generation replacement and cleanup retain their own guest evidence and acceptance boundaries.
