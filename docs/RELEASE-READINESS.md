# Release readiness assessment

## Decision

The candidate at commit `1f9d8b47f021be9f6f61f7913c776da83ea446da` is not ready for a general provider-backed production release. Its complete F4 quality and disposable-guest matrix passed on 12 November 2026, and the source-package audit found no packaging-hygiene defect. The remaining release blocker is the unrecorded credential-bearing provider workflow required by E1 and E2.

This decision does not reopen the accepted namespace, application, host-default, recovery or platform work. Those capabilities remain accepted only within their documented Arch Linux guest profiles and cooperating-process authority model.

## Final candidate evidence

The exact candidate passed `ruff check .`, `ruff format --check .`, the standalone `pytest` gate with 1,402 tests, and Markdown lint over 19 files. The acceptance manager then completed `python scripts/acceptance-manager.py test --mode final` on a clean disposable guest. Final mode disables result reuse and runs the complete quality, network, application, desktop, D1, D2 and D3 scenario set.

The guest evidence therefore closes the exact-tree rerun requirements attached to E4, E5 and F1-F4. It does not include the live-provider probe, which is deliberately excluded from unattended final mode because it requires private operator configurations and contacts the provider service.

## Remaining release blocker

E1 and E2 still require the opt-in [provider workflow acceptance](PROVIDER-WORKFLOW-ACCEPTANCE.md) on this exact candidate. That run must use four distinct current provider configurations and a fresh benchmark report, then demonstrate four live handshakes, namespace DNS, registered non-root launches, idempotent restoration, complete retirement and host restoration. Static tests and the synthetic real-WireGuard guest fixture do not establish provider reachability or validate current provider material.

Until that evidence is recorded, documentation and release material must continue to say that provider-backed production use is not accepted. The blocker is evidential rather than an observed implementation failure.

## Accepted limitations

The following limits are deliberate release scope, not unfinished F5 work:

- Production networking is accepted only on the [documented Arch Linux profile](SUPPORTED-NETWORK-PLATFORM.md), including its exact network-tool gates.
- Privileged mutation assumes an administratively controlled [cooperating-process authority domain](PRIVILEGED-AUTHORITY-BOUNDARY.md). Independent privileged kernel, network or mount mutators are outside the safety guarantee.
- Host-default protection supports only the documented static IPv4 `systemd-networkd` and `systemd-resolved` arrangement.
- Desktop acceptance covers the local Wayland, X11 and D-Bus protocol boundary on the recorded nested stack, not complete desktop environments or their ancillary services.
- General in-place updates and automatic provider reselection remain unsupported; live changes use immutable generation replacement.
- Automatic recovery of an incomplete host transaction inherited from an earlier boot remains outside the D3 evidence.

## Source-package hygiene

A source archive produced with `git archive --format=tar` from the candidate contained 328 entries and no Git internals, dependency installations, Python bytecode, test or lint caches, virtual environments, coverage output, build directories, nested archives or private-key files. The archive contained the source, tests, documentation, examples, licence, dependency manifests and required acceptance tooling. Its uncompressed audit size was 2,785,280 bytes.

The working tree may contain ignored `node_modules`, `__pycache__`, `.pytest_cache` and `.ruff_cache` directories. They are local development state and were absent from the archive. Build release archives from a committed candidate with `git archive`; do not package the working directory recursively. Repeat the content-list inspection after the F5 documentation commit so the recorded release identifier and archive digest can refer to the final commit rather than this pre-decision candidate.
