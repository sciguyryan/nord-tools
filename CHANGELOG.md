# Changelog

This file records user-visible changes to Nord Tools. The project uses semantic version numbers while it prepares its first provider-backed production release.

## Unreleased

### Release gate

- Record a passing live-provider workflow with four current, distinct WireGuard configurations before declaring provider-backed production routing fully accepted or publishing version 1.0.0.

## 0.9.0 - 2026-11-12

### Added

- A unified `nord_tools.py` command for endpoint benchmarking, diagnostics, policy inspection and explicitly authorised lifecycle operations.
- Secure provider configuration import with deterministic pinned, country and fresh-benchmark selection.
- Shared and isolated WireGuard namespace allocations, registered application launch, immutable generation replacement and conservative recovery.
- Deny-first host-default protection for the documented static IPv4 Arch Linux profile.
- Disposable guest acceptance for network confinement, application lifecycle, desktop protocol forwarding, host failure recovery and reboot restoration.
- Read-only operational preflight for the exact supported network platform.

### Changed

- Replaced the development-oriented project overview with an operator-focused guide and consolidated release status.
- Made immutable replacement, administrative authority and supported-platform boundaries explicit in the public documentation.

### Removed

- Internal planning and acceptance-tracking documents that no longer form part of the release documentation.

### Known limitations

- Live-provider acceptance has not yet been recorded for this release candidate.
- Privileged networking is supported only on the exact platform and host arrangement documented in `docs/SUPPORTED-NETWORK-PLATFORM.md`.
- General in-place updates, automatic provider reselection and independent privileged network mutators remain outside the supported authority model.
