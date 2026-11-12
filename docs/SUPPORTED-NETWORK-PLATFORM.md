# Supported platform and desktop matrix

Nord Tools production networking is accepted on one deliberately narrow Arch Linux guest profile. The table separates runtime gates from acceptance evidence: a runtime check can refuse a known mismatch, but passing it does not extend the tested scope or authorise mutation. Anything not listed as accepted is unsupported until it receives an explicit support decision and equivalent evidence.

## Support summary

| Area | Accepted profile | Runtime enforcement | Acceptance evidence | Status outside this profile |
| --- | --- | --- | --- | --- |
| Operating system | Arch Linux cloud image used by the acceptance manager | Linux is required; production mutation also requires root and Python 3.10 or newer | Complete disposable guest matrices, 9-11 November 2026 | Other distributions, kernels and Python versions below 3.10 are unsupported |
| Kernel | `7.2.x-arch1`; accepted run used `linux 7.2.11.arch1-1` | Full release pattern is checked before production namespace admission | Platform-contract probe followed by production confinement and recovery | Other kernel series and non-Arch release forms are refused |
| iproute2 | `7.3.0`; package evidence `iproute2 7.3.0-1` | Exact version plus loopback-link and dual-stack main-route JSON schemas | Platform-contract and production lifecycle probes | Other versions or output shapes are refused |
| nftables | `1.1.7`; package evidence `nftables 1:1.1.7-3` | Exact version plus recognised ruleset JSON; each executor also verifies its own tables, chains and rules | Platform-contract, namespace confinement and host-domain probes | Other versions or output shapes are refused |
| WireGuard tools | `1.0.20260223`; package evidence `wireguard-tools 1.0.20260223-1` | Exact version plus safe interface-name readback; production paths verify peer and interface fields again | Platform-contract, real-tunnel, failure and host-domain probes | Other versions or malformed readback are refused |
| Namespace resolver | Root-owned, non-symlinked `/etc/netns`, not writable by group or others; per-namespace `resolv.conf` | Resolver-root ownership, type and mode are checked before mutation; individual resolver files receive stricter lifecycle checks | Production namespace DNS, bypass-refusal and recovery probes | Alternate namespace resolver roots and unsafe storage are unsupported |
| systemd startup | Generated namespace restoration unit; host-default uses the generated early-barrier and network-online units | Required executables must exist; generated units pin ordering and service entry points; D3 verifies the live ordering | Startup restoration matrices and D3 real reboot | Other init systems and hand-written unit arrangements are unsupported |
| Host network manager | Static IPv4 egress managed by `systemd-networkd` | Live service state, interface identity, source address and endpoint path must match the plan | D1-D4 host-domain acceptance | DHCP, changing egress, multiple uplinks and other network managers are unsupported |
| Host resolver | `systemd-resolved` with resolver state attached to the owned WireGuard link | `resolvectl` and determinate active service state are required; assignment and retirement are read back | D1-D3 direct DNS, resolved query, failure and reboot probes | Other host resolver managers and indeterminate service state are unsupported |
| Desktop protocol contract | Local Wayland or X11 session, target-owned runtime endpoints, standard user D-Bus address and safe Xauthority | Launch validates session type, runtime directory, socket ownership, D-Bus address, display syntax and Xauthority before dropping privileges | C4 nested Weston `15.0.1`, Xvfb `21.1.25` and D-Bus `1.16.2` | Remote displays, non-standard bus addresses and unvalidated desktop services are unsupported |

The systemd and `systemd-resolved` rows are capability and arrangement contracts rather than standalone version promises. Their accepted behaviour is tied to the recorded Arch guest run: D3 exercised real unit ordering across reboot, while D1-D2 exercised live resolver assignment, packet delivery, uncertain readback and retirement. A different systemd build or Arch image does not inherit support merely because its service names match; it must pass the exact-candidate matrices required by F4.

## Network runtime capability contract

`verify_supported_network_platform()` performs read-only inspection. It requires the accepted kernel and network-tool versions, the live iproute2 and nftables JSON shapes consumed by production readback, safe WireGuard interface-field output and trusted `/etc/netns` storage. Patch releases within the stated Arch kernel pattern are admitted only when all live capability checks pass. Invalid JSON, unexpected document shapes, unrecognised versions, missing commands, timeouts and unsafe resolver storage cause refusal before restoration creates durable state or invokes a mutation primitive.

Production namespace restoration, cleanup and recovery also run the combined [operational preflight](OPERATIONAL-PREFLIGHT.md). It requires Linux root, Python 3.10 or newer and `ip`, `nft` and `wg`. Host-default mode additionally requires `systemctl` and `resolvectl`, then composes the D4 inventory described below. A successful preflight is a current observation with `mutation_authorised: false`; each executor still performs its operation-specific ownership and resource checks.

The namespace resolver does not depend on the host's `systemd-resolved` service. Host resolver support applies only to host-default protection.

## Host-default deployment profile

Host-default protection supports a statically addressed IPv4 physical egress managed by `systemd-networkd`, `systemd-resolved`, one pinned numeric IPv4 WireGuard endpoint and dual-stack tunnel addresses. The physical interface name and ifindex, source address and endpoint route must continue to match the validated plan.

The production inventory refuses activation when either required service is unavailable, service inspection is indeterminate, the endpoint path differs, a recognised competing manager is active, another tunnel link exists, or host-protection objects already exist without matching durable evidence. Recognised competing services include NetworkManager, firewalld, UFW, Tailscale, OpenVPN and strongSwan. WireGuard, TUN/TAP, XFRM, IP-in-IP, SIT, GRE and VTI links other than the planned Nord Tools interface are also refused.

DHCP or otherwise changing egress, IPv6 physical endpoints, multiple uplinks, competing VPN or firewall managers and other network-management arrangements are unsupported. They are not necessarily incompatible, but they require a new support decision and the same platform, D1-D3 and restoration evidence before admission.

Run the combined read-only host check before any lifecycle store or network object exists:

```bash
sudo python nord_tools.py manage operational-preflight \
  --mode host-default \
  --host-plan /etc/nord-tools/host-protection.json
```

The narrower host inventory probe remains available when only D4 arrangement compatibility is needed:

```bash
sudo python tools/probe_host_platform_compatibility.py \
  --plan /etc/nord-tools/host-protection.json --run-privileged
```

## Desktop launch profile

Desktop support is a protocol boundary, not a claim that a complete desktop environment is certified. Without `--desktop-session`, registered applications receive a minimal environment. With the flag, the launcher accepts only `XDG_SESSION_TYPE=wayland` or `x11`, the target user's safe `/run/user/UID` and the standard `unix:path=/run/user/UID/bus` D-Bus address. A Wayland session requires a target-owned runtime socket name; an X11 session requires a local target-owned socket and an absolute target-owned Xauthority file that is not writable by group or others. When both display endpoints are supplied, both are validated. Environment values outside the fixed allowlist are not forwarded.

The C4 guest stage used headless Weston `15.0.1`, Xvfb `21.1.25` and D-Bus `1.16.2`. Registered direct and VPN-gated children and their descendants completed real Wayland, authenticated X11 and D-Bus requests after transition to the non-root identity. This accepts the launcher's local protocol contract on that nested stack. It does not certify GNOME, KDE Plasma, wlroots compositors or other full desktops as products, and it does not cover portals, notifications, audio, GPU rendering, tray integration, file pickers, keyrings or desktop-specific single-instance activation.

Remote X11, root-owned or non-socket display endpoints, absolute Wayland socket paths, non-standard D-Bus addresses and unsafe runtime or Xauthority paths are intentionally refused. Additional desktop protocols or services require explicit allowlisting, adversarial path tests and a disposable guest acceptance case before they can be called supported.

## Evidence and expansion rules

The accepted evidence consists of the platform-contract probe, production namespace confinement and recovery matrices, C4 desktop launch probe, D1-D2 host lifecycle matrices and D3 real-reboot matrix recorded in the [release acceptance matrix](RELEASE-ACCEPTANCE-MATRIX.md). These runs establish behaviour only within the disposable guest and [cooperating-process authority model](PRIVILEGED-AUTHORITY-BOUNDARY.md). They do not establish compatibility on the operator's host or safety against independent privileged network or mount mutators.

A new kernel, network-tool version, distribution, init system, host network arrangement, resolver manager or desktop integration must not be admitted from version numbering or a dry run alone. Update the runtime contract where a deterministic gate exists, add refusal and positive tests, pass the relevant privileged matrices on the exact candidate tree, and record the date, package evidence and scope decision here and in the release acceptance matrix.
