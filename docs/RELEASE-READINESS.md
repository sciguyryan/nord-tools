# Release status and verification

## Current decision

Version 0.9.0 is the current release candidate. The benchmarker, offline planning tools and scoped production lifecycle pass the complete local and disposable-guest verification suites. The source-package audit also found no Git metadata, dependency installations, generated caches, build output, nested archives or private-key files.

The repository is not yet approved for a general provider-backed production release. The remaining check is the credential-bearing [provider workflow](PROVIDER-WORKFLOW-ACCEPTANCE.md), which is excluded from unattended verification because it needs private operator configurations and contacts the live provider service. This is an evidence gap, not a failure observed in the implementation.

## Verified scope

The release tree passed:

- Ruff lint and formatting;
- 1,403 pytest cases;
- Markdown lint;
- production namespace confinement and failure recovery with real WireGuard traffic;
- registered direct, shared and isolated application lifecycles;
- dual-stack packet and DNS confinement through tunnel loss and recovery;
- validated local Wayland, X11 and D-Bus forwarding to non-root children;
- deny-first host protection, unavailable-peer handling and interrupted retirement recovery; and
- real reboot ordering with barrier-last retirement and restored host state.

The disposable acceptance manager ran the complete final scenario set without reusing development results. Its platform preflight accepted the exact network-tool contract recorded in [Supported platform and desktop scope](SUPPORTED-NETWORK-PLATFORM.md).

## Remaining provider verification

The provider workflow must run on the release tree with four distinct, current WireGuard configurations and a fresh benchmark report. Acceptance requires four live handshakes, namespace DNS, registered non-root launches, converged repeat restoration, complete retirement and restored host state.

Static provider tests and the local real-WireGuard fixture cannot establish current provider reachability or validate private provider material. Until this run is recorded, release material must not claim that provider-backed default, shared and isolated production routing is fully accepted.

A passing provider run permits the release owner to update the version and [changelog](../CHANGELOG.md) for 1.0.0. After committing the exact release tree, create an annotated `v1.0.0` tag and build the source archive from that tag. Do not tag a working tree whose contents differ from the reviewed candidate.

## Accepted limitations

These limits define the supported release scope:

- Production networking is accepted only on the documented Arch Linux profile and exact network-tool versions.
- Privileged mutation assumes an administratively controlled cooperating-process authority domain. Independent privileged kernel, network or mount mutators are outside the safety guarantee.
- Host-default protection supports only the documented static IPv4 `systemd-networkd` and `systemd-resolved` arrangement.
- Desktop acceptance covers the local Wayland, X11 and D-Bus protocol boundary on the recorded nested stack, not complete desktop environments or their ancillary services.
- General in-place updates and automatic provider reselection are unsupported; live changes use immutable generation replacement.
- Automatic recovery of an incomplete host transaction inherited from an earlier boot is outside the reboot evidence.

## Source-package hygiene

The audited source archive was produced with `git archive`. It contained the source, tests, documentation, examples, licence, dependency manifests and required acceptance tooling, while excluding local dependency trees, caches and other generated state.

Build release archives from a committed candidate rather than recursively packaging the working directory. Inspect the final archive contents and record its digest after the release documentation commit so the identifier describes the actual distributed tree.
