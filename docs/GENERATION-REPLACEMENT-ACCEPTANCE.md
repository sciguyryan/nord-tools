# Generation replacement and recovery acceptance

This document describes the production generation handover acceptance boundary. It does not grant authority to create or retire kernel resources, and a successful test does not establish safety against independent hostile privileged kernel mutators.

## Implementation and evidence

The production replacement executor provisions a distinct generation, verifies its owned resources and packet readiness, durably selects it for new launches, preserves old-generation consumer leases during draining, and retires the old generation only after verified lease release and fresh replacement verification. The generation recovery command classifies interrupted and inconsistent states without treating saved intent as kernel ownership proof. It can promote a verified prepared record or explicitly reprovision a verified-absent, unselected replacement under production authority; it does not silently switch a selected generation or repair disputed resources.

The disposable real-peer acceptance runner is `tools/probe_live_tunnel_replacement.py`. Its ordinary mode is read-only and does not exercise privileged behaviour. The opt-in mode provisions a local WireGuard peer, executes generation A and B through the production paths, launches two lease-gated consumers, verifies that old-generation retirement is refused while A is in use, and checks exact retirement and host integrity. The interruption option terminates workers after replacement provisioning, after durable activation and after verified retirement, then checks recovery against the resulting durable state. The runner additionally checks repeatable read-only recovery, wrong-profile and wrong-allocation refusal, and non-mutating fail-closed classification of a deliberately failed selected-generation packet verifier. This last injection simulates failed verification; it does not physically disconnect a peer or prove packet loss containment.

## Automated and privileged gates

From the source root, run:

```bash
ruff check .
ruff format --check .
python -m pytest -q
python tools/probe_live_tunnel_replacement.py
sudo python tools/probe_live_tunnel_replacement.py --run-privileged --uid 1000 --gid 1000
sudo python tools/probe_live_tunnel_replacement.py --run-privileged --inject-replacement-interruption --uid 1000 --gid 1000
```

Use the actual non-root UID and GID of the disposable test account. Privileged runs modify networking resources and must be performed only on an appropriate disposable Linux test host with the documented prerequisites. Inspect retained evidence and ownership before authorising cleanup after a failed run. A probe's suggested cleanup command is not an instruction to execute it blindly.

The interruption option covers three specific process-death checkpoints. It does not inject death after every individual namespace, interface, route, firewall, resolver or lease mutation. The existing broader recovery and isolation probes remain separate evidence. Passing this matrix does not establish safe general in-place live updates, default-host routing protection, official client coexistence, or comprehensive real-application DNS leak prevention. Those requirements remain open in `TODO.md`.

## Acceptance decision

The generation replacement acceptance local quality gates and privileged real-peer scenarios, including interruption-enabled replacement, all passed. This closes the generation replacement acceptance scope, not the broader production routing and independent privileged mutator boundaries. Any future unexpected ownership observation, failed health verification, inconsistent lease or host-network change remains a failure requiring investigation. Do not infer broader privileged safety from passing mocked tests or this bounded acceptance.
