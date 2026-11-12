# Nord Tools

Nord Tools is a Linux-focused toolkit for benchmarking NordVPN endpoints and running policy-driven WireGuard routing. It can rank provider endpoints, maintain persistent routing intent, provision owned VPN namespaces, launch registered applications inside them and protect the host default route with a deny-first lifecycle.

The supported entry point is `python nord_tools.py`. Individual scripts remain available for compatibility, but new usage should start with the unified command.

The current release candidate is **0.9.0**. See the [changelog](CHANGELOG.md) for its scope and remaining release gate.

## Release status

The benchmarker, offline planning tools and scoped production executors pass the project's local and disposable-guest verification suites. Production networking has a deliberately narrow support boundary: the documented Arch Linux profile, exact network-tool versions and an administratively controlled host where other privileged network and mount mutators do not bypass Nord Tools' locks.

One release check remains unrecorded. The complete provider-backed workflow requires four current private WireGuard configurations and contacts the live provider service; it is intentionally excluded from unattended verification. Until that [provider workflow](docs/PROVIDER-WORKFLOW-ACCEPTANCE.md) passes, do not describe provider-backed default, shared and isolated production routing as fully accepted. The complete decision and limitations are in [Release status and verification](docs/RELEASE-READINESS.md).

## Requirements

- Linux and Python 3.10 or newer.
- The exact production platform described in [Supported platform and desktop scope](docs/SUPPORTED-NETWORK-PLATFORM.md) for privileged routing.
- `iproute2`, nftables and WireGuard tools for network operations.
- systemd and `systemd-resolved` for host-default protection.
- Root privileges only for commands that inspect protected state or change networking.
- The NordVPN Linux client only when using benchmark `--auto-connect`.

The runtime tools use the Python standard library. Run directly from a source checkout:

```bash
python nord_tools.py --help
python nord_tools.py --version
python nord_tools.py doctor
```

`doctor` reports feature dependencies without changing the system. Before a privileged lifecycle operation, run the stricter read-only preflight as the same root identity that will execute it:

```bash
sudo python nord_tools.py manage operational-preflight --mode namespace
sudo python nord_tools.py manage operational-preflight \
  --mode host-default \
  --host-plan /etc/nord-tools/host-protection.json
```

A successful preflight is a current observation, not reusable mutation authority. Every executor repeats its own ownership and resource checks.

## Benchmarking endpoints

Benchmark downloaded NordVPN profiles:

```bash
python nord_tools.py benchmark --download --accuracy balanced --top 10
```

Or use an existing OpenVPN configuration directory:

```bash
python nord_tools.py benchmark \
  --config-dir ~/nordvpn \
  --protocol both \
  --accuracy thorough \
  --top 20
```

The benchmark measures endpoint reachability and latency, not VPN throughput. ICMP-unresponsive servers are not necessarily offline. Use `--probe tcp` when TCP connection timing better matches the intended transport, and keep the selected probe method consistent when comparing runs.

### Filtering

`--filter` supports `!` for NOT, `&` for AND, `|` for OR and parentheses. A bare two-letter code selects a country; named fields include `country`, `server`, `host`, `protocol` and `port`. Repeated filters are combined with AND.

```bash
python nord_tools.py benchmark --download --filter='!(uk|us)'
python nord_tools.py benchmark \
  --download \
  --filter='(uk|nl)&protocol:udp&!server:uk2108'
```

Bundled region lists provide named country groups:

```bash
python nord_tools.py benchmark --list-region-lists
python nord_tools.py benchmark --download --region-list low-ads
```

Custom lists use the same JSON shape as `region-lists.json`. A custom group replaces a built-in group of the same name rather than merging with it. See [Maintaining the low-ads catalogue](docs/LOW-ADS-MAINTENANCE.md) for its evidence boundary.

### Reports and offline reuse

Write a versioned benchmark report for later policy selection:

```bash
python nord_tools.py benchmark \
  --download \
  --report benchmark-report.json \
  --output results.csv \
  --format csv
```

The derived endpoint cache supports bounded offline reuse:

```bash
python nord_tools.py benchmark --download
python nord_tools.py benchmark --offline
python nord_tools.py benchmark --refresh-cache --download
```

Use `--no-cache` when no persistent endpoint data should be written. Exported files never contain terminal colour sequences.

### Optional NordVPN client connection

`--auto-connect` asks the installed NordVPN Linux client to connect to a ranked server after benchmarking. It controls that client's single connection; it does not create an independent application tunnel.

```bash
python nord_tools.py benchmark \
  --download \
  --top 20 \
  --auto-connect \
  --connect-rank 2
```

Add `--dry-run` to preview the client command. Nord Tools refuses to benchmark through a confirmed active NordVPN connection unless `--allow-active-vpn` is supplied. Other VPN clients and routes cannot be detected reliably, so verify the network path separately.

## Routing policy and lifecycle management

Inspect the available management commands:

```bash
python nord_tools.py manage --help
```

The command surface contains three distinct classes:

| Class | Examples | Behaviour |
| --- | --- | --- |
| Offline planning | `plan`, `reconcile`, `dependency-plan`, `transaction-plan`, `graph` | Validates supplied records and prints plans without inspecting or changing networking |
| Live inspection | `discover`, `ownership-preflight`, `operational-preflight`, `reconcile-live`, status commands | Reads the current system but does not authorise later mutation |
| Explicit execution | `provision`, `apply-live`, `replace-profile`, `cleanup`, `recovery`, application launch and host lifecycle commands | Requires the command-specific execution flag or is a generated service entry point |

Saving a policy does not create a tunnel or change routes:

```bash
python nord_tools.py manage plan --policy examples/vpn-policy.json
python nord_tools.py manage configure --policy examples/vpn-policy.json
python nord_tools.py manage status
python nord_tools.py manage graph
```

Persistent and transient intent are separate. Transient state requires a valid user runtime directory and is never restored at boot.

### Provider credentials

Nord Tools imports official WireGuard configurations supplied by the operator. It does not scrape undocumented APIs or place private keys in the public catalogue.

```bash
python nord_tools.py manage provider-import \
  --configuration /secure/downloads/gb123.conf \
  --server gb123.nordvpn.com \
  --catalogue /etc/nord-tools/provider-catalogue.json \
  --credential /etc/nord-tools/provider/gb123.key
```

The default is a preview. Add `--execute` to import, and `--rotate` as well when deliberately replacing existing material. Read [Provider credential operations](docs/PROVIDER-CREDENTIAL-OPERATIONS.md) before using provider-backed startup.

### Startup restoration

The namespace lifecycle uses durable intents, creation-time owner bindings and a generated systemd unit:

```bash
python nord_tools.py manage startup-plan --config /etc/nord-tools/startup.json
sudo python nord_tools.py manage startup-install \
  --config /etc/nord-tools/startup.json \
  --execute
```

The generated service receives private keys through systemd credentials. A converged profile is left untouched; uncertain or disputed evidence stops restoration. General in-place updates and automatic provider reselection are unsupported. Use immutable generation replacement for an accepted live change.

The [Production provisioning contract](docs/PRODUCTION-PROVISIONING-CONTRACT.md) defines creation, cleanup, recovery, application leases and generation handover in detail.

### Applications and desktop sessions

Registered applications can use the default VPN allocation, a shared named allocation, an isolated allocation or explicit direct host routing. The launcher binds process identity to a durable allocation lease and never falls back from a failed VPN allocation to direct routing.

Desktop forwarding is opt-in. It validates local Wayland or X11 endpoints, Xauthority and the target user's standard D-Bus address before dropping privileges. The accepted evidence covers the documented protocol stack, not an entire GNOME, KDE Plasma or wlroots desktop.

### Host-default protection

Host-default protection is separate from namespace routing. It installs a deny barrier before the endpoint exception, WireGuard interface, policy routes and per-link resolver state. Retirement removes the barrier last.

Only the documented static IPv4 `systemd-networkd` and `systemd-resolved` arrangement is supported. DHCP, changing egress, multiple uplinks, competing VPN or firewall managers and additional tunnel links are refused. Read [Supported platform and desktop scope](docs/SUPPORTED-NETWORK-PLATFORM.md) and [Privileged mutation authority](docs/PRIVILEGED-AUTHORITY-BOUNDARY.md) before enabling it.

### Cleanup and recovery

Cleanup and recovery act only on fresh, independently verified ownership evidence:

```bash
python nord_tools.py manage cleanup \
  --journal /var/lib/nord-tools/lifecycle.json \
  --bindings /var/lib/nord-tools/owner-bindings.json

python nord_tools.py manage recovery \
  --journal /var/lib/nord-tools/lifecycle.json \
  --bindings /var/lib/nord-tools/owner-bindings.json \
  --intents /var/lib/nord-tools/operation-intents.json
```

Preview is the default. Execution refuses same-name lookalikes, identity conflicts, unresolved intents and disputed profile state. Do not delete state stores or flush networking merely to recover connectivity; preserve evidence and follow [Disputed drift recovery](docs/DISPUTED-DRIFT-RECOVERY.md).

## Safety boundary

Nord Tools coordinates its own cooperating processes with protected filesystem locks and rechecks creation-time identities before mutation. Linux does not provide an atomic compare-and-delete operation for every namespace and interface action used here. A separate privileged process can bypass those locks and replace a kernel object between verification and mutation.

Run privileged lifecycle operations only on an administratively controlled host where other privileged network and mount mutators are excluded by policy. Passing preflight or a disposable test does not prove otherwise. Unsupported environments fail closed rather than inheriting support from similar version numbers or service names.

## Verification

Run the local quality gates from the repository root:

```bash
ruff check .
ruff format --check .
pytest
npm ci
npm run lint:markdown
```

The disposable Arch Linux acceptance manager exercises real WireGuard traffic, namespace confinement, registered applications, desktop protocol forwarding, host-default failure recovery and real reboot ordering. It can interrupt the guest's networking and must not target a workstation:

```bash
python scripts/acceptance-manager.py rebuild --force
python scripts/acceptance-manager.py test --mode final
```

See [Acceptance VM manager](scripts/README.md) for host dependencies, evidence handling and recovery precautions. The private live-provider workflow remains a separate manual verification because it requires operator credentials.

## Documentation

- [Release status and verification](docs/RELEASE-READINESS.md)
- [Supported platform and desktop scope](docs/SUPPORTED-NETWORK-PLATFORM.md)
- [VPN routing design](docs/VPN-ROUTING-DESIGN.md)
- [Production provisioning contract](docs/PRODUCTION-PROVISIONING-CONTRACT.md)
- [Provider credential operations](docs/PROVIDER-CREDENTIAL-OPERATIONS.md)
- [Live update policy](docs/LIVE-UPDATE-POLICY.md)
- [Disputed drift recovery](docs/DISPUTED-DRIFT-RECOVERY.md)
- [Privileged mutation authority](docs/PRIVILEGED-AUTHORITY-BOUNDARY.md)

## Licence

Nord Tools is distributed under the [MIT Licence](LICENSE).
