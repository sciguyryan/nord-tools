# Disputed drift recovery

Nord Tools does not repair a live resource merely because its name or configuration resembles a recorded allocation. Recovery starts from the durable lifecycle journal, creation-time ownership bindings, operation intents and a fresh kernel observation. The recovery executor remains the only component that may act on that evidence.

Preview recovery before requesting execution:

```bash
python nord_tools.py manage recovery --journal path/to/lifecycle.json --bindings path/to/owner-bindings.json --intents path/to/operation-intents.json
sudo python nord_tools.py manage recovery --journal path/to/lifecycle.json --bindings path/to/owner-bindings.json --intents path/to/operation-intents.json --execute
```

The report's `drift_policy` groups each profile into one of three states:

- `record_only_recovery` means fresh observation proves that the relevant resource is absent, or that complete recorded bindings allow lifecycle bookkeeping to finish. This state does not permit a kernel mutation.
- `identity_bound_recovery` means an interrupted creation or retirement can be resumed only after the executor rechecks its exact creation-time identity. Kernel mutation is possible only through explicit recovery execution.
- `quarantined` means some evidence is disputed. The executor performs no action for that profile, including otherwise recoverable work in the same profile.

Missing bindings, identity mismatches, live unbound host resources, conflicting operation evidence and same-name lookalikes cause quarantine. Recovery never adopts, deletes or reconfigures such a resource by name or configuration match. An operator must preserve the evidence and determine the resource's owner outside Nord Tools before changing it.

One profile's quarantine does not prevent independently evidenced recovery for another profile. Both still run under the common lifecycle execution lock. An absent, never-bound dependent left by a half-built creation is not independent disputed evidence: the executor may close its records only as part of an exact, identity-bound namespace rollback. An unbound interface observed solely inside that verified namespace is removed only as a consequence of deleting the namespace, never by claiming its name. A live unbound host interface, or a same-name interface in any other namespace, quarantines the whole profile.

Generation handover recovery has the same boundary. It may explicitly reprovision a verified-absent, unselected replacement generation, but it does not repair an unhealthy selected generation or a partial, disputed replacement. Those cases remain fail-closed and require operator review.

These guarantees cover cooperating Nord Tools processes using the recorded locks and evidence stores. They do not protect against an independent privileged process changing kernel resources between verification and mutation. A recovery preview is a classification, not a reusable authority token.
