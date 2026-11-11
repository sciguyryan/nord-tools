# Supported production network platform

Production network provisioning is accepted on one deliberately narrow Linux profile. Version checks are paired with read-only capability checks because a recognised version string does not prove that command output still has the shape required by the ownership and fail-closed readback code.

## Accepted profile

The following profile passed the complete disposable Arch Linux guest matrix on 9 November 2026:

| Component | Accepted value | Package evidence |
| --- | --- | --- |
| Distribution | Arch Linux cloud image | Rolling image used by the acceptance manager |
| Kernel | `7.2.x-arch1` | `linux 7.2.11.arch1-1` |
| iproute2 | `7.3.0` | `iproute2 7.3.0-1` |
| nftables | `1.1.7` | `nftables 1:1.1.7-3` |
| WireGuard tools | `1.0.20260223` | `wireguard-tools 1.0.20260223-1` |

Patch releases within the stated Arch kernel profile are admitted only when the live capability checks below pass. Different kernel series or tool versions are refused before restoration creates its state stores or calls a network mutation primitive. This is a conservative support boundary, not a claim that other Linux combinations are known to be incompatible.

## Runtime capability contract

`verify_supported_network_platform()` performs only read-only inspection. It requires:

- the loopback link and both main route tables to use the accepted iproute2
  JSON shapes;
- `nft -j list ruleset` to return the recognised top-level nftables document;
- safe WireGuard interface-field readback without requesting private-key dump
  output; and
- a root-owned, non-symlinked `/etc/netns` directory that is not writable by
  group or other users.

Production startup restoration runs this check before it creates the journal, binding, intent or run-record stores. Invalid JSON, unexpected document shapes, unrecognised versions, missing commands, timeouts and unsafe resolver storage all cause refusal without network changes. The later production profile checks still validate the exact nftables chains and rules, dual-stack routes, WireGuard peer fields and resolver file. The preflight does not replace those resource-specific checks.

The namespace resolver uses `/etc/netns/<namespace>/resolv.conf`; it does not depend on a particular host `systemd-resolved` version. Host-domain resolver integration remains a separate Phase D requirement.

## Expanding support

A new kernel or tool version must not be added from version numbering alone. Its candidate tree must pass the platform probe, the complete local quality gates and both privileged disposable-guest matrices. The accepted values in the compatibility module and this table should then be updated together with the date and package evidence.

## Host-default deployment profile

Host-default protection has a separate, narrower compatibility boundary. D1-D3 passed with a statically addressed IPv4 physical egress managed by `systemd-networkd`, `systemd-resolved`, one pinned numeric IPv4 WireGuard endpoint and dual-stack tunnel addresses. The physical interface name and ifindex, source address and endpoint route must continue to match the validated plan.

The production inventory refuses activation when `systemd-networkd` or `systemd-resolved` is unavailable, service inspection is indeterminate, the endpoint path differs, a recognised competing manager is active, another tunnel link exists, or host-protection objects already exist without matching durable evidence. Recognised competing services include NetworkManager, firewalld, UFW, Tailscale, OpenVPN and strongSwan. WireGuard, TUN/TAP, XFRM, IP-in-IP, SIT, GRE and VTI links other than the planned Nord Tools interface are also refused.

This is the complete D4 support decision. DHCP or otherwise changing egress, IPv6 physical endpoints, multiple uplinks, competing VPN and firewall managers, and other network-management arrangements are unsupported. They are not necessarily incompatible, but they require an explicit support decision and the same capability, D1-D3 and restoration evidence before admission.

The read-only host check can be run before any lifecycle store or network object exists:

```bash
sudo python tools/probe_host_platform_compatibility.py \
  --plan /etc/nord-tools/host-protection.json --run-privileged
```

This profile closes the Phase B namespace-platform and Phase D host-deployment requirements for their documented Arch guest scopes. It does not close the broader final platform matrix, desktop integration or support for independently privileged network mutators.
