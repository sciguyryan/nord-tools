# Nord Tools

Nord Tools is a collection of Linux-focused utilities for benchmarking NordVPN servers and exploring policy-driven VPN routing. The working benchmarker discovers and ranks NordVPN endpoints; the newer policy tools validate a default VPN profile, describe application-specific overrides and inspect proposed routing domains. **Generation-based multi-tunnel replacement and registered application launch are implemented for pinned production configurations; automatic default-server switching remains unimplemented.**

The [development plan](TODO.md) tracks the operational VPN manager programme and its outstanding safety requirements.

## Unified command-line entry point

`nord_tools.py` provides one place to access the project's existing tools. It delegates to the original commands, which remain available independently and retain their options.

```bash
python nord_tools.py --help
python nord_tools.py doctor
python nord_tools.py benchmark --help
python nord_tools.py policy --policy examples/vpn-policy.json --validate
python nord_tools.py topology --policy examples/vpn-policy.json
python nord_tools.py manage plan --policy examples/vpn-policy.json
python nord_tools.py namespace-probe
```

The `policy` and `topology` commands are offline only. The namespace probe is experimental: its default invocation is a dry run, and `--execute` performs privileged network changes. The entry point includes explicitly authorised provisioning, generation replacement, recovery and registered-application launch commands. General in-place live updates and automatic default-server switching remain unimplemented. Host-domain default protection has a narrowly scoped executable lifecycle, but its complete privileged acceptance remains outstanding.

## What works today

The benchmarker reads local OpenVPN `.ovpn` files or downloads NordVPN's official configuration archive, probes endpoints concurrently and ranks them by packet loss, latency and stability. These are endpoint measurements, not throughput measurements through an established VPN tunnel. ICMP-unresponsive servers are not necessarily offline.

The existing `--auto-connect` option can request a connection through the installed NordVPN Linux CLI after benchmarking. It manages that client's single connection, **not** independent per-application tunnels. See [Connecting to a ranked server on Linux](#connecting-to-a-ranked-server-on-linux).

### Offline resource lifecycle journal

recovery triage introduces a strict offline lifecycle journal for future Nord Tools-owned resources. It validates allocation-bound event histories, rejects illegal state transitions and detects mismatched simulated identities. A matching identifier is **not** independent kernel ownership evidence. No lifecycle command creates, modifies or removes networking resources.

```bash
python nord_tools.py manage lifecycle --journal path/to/lifecycle.json
python nord_tools.py manage lifecycle --journal path/to/lifecycle.json --observed path/to/simulated-observations.json
```

The internal lifecycle modules provide permission-restricted atomic journal persistence and advisory locking for cooperating writers. They reject invalid histories and unsafe journal paths, but do not establish kernel ownership or defend against hostile writers with directory access. See the [routing design](docs/VPN-ROUTING-DESIGN.md) for the safety boundary.

## Tunnel management implementation status

The ownership, restoration, cleanup and recovery executors for pinned provider plans have automated and scoped privileged acceptance, but **the manager is not yet ready for unrestricted general production use**. The table distinguishes implemented capabilities from the remaining integrated or platform-specific evidence:

| Area | Current state | Required before live use |
| --- | --- | --- |
| Tunnel provisioning | Pinned-provider boot provisioning through durable creation intents, creation-time owner records and the privileged namespace, isolation, routing and WireGuard primitives | Provider credentials acquisition, fastest and country selection at boot, and real-tunnel endpoint handling |
| Network isolation | One production-installed dual-stack WireGuard profile passed scoped guest acceptance with its nftables policy, routes, pinned resolver, application DNS and underlay bypass refusal, establishment rollback and recovery, tunnel loss/restart, uncertain readback refusal and ownership-aware retirement | Validate the supported kernel and tooling combinations; independently privileged mutation remains outside the authority model |
| Per-application routing | Offline routing plans, binding and session lifecycle models, launch preparation and consistency audit | Accept the actual registered VPN-bound launch-to-packet path and common desktop integration; direct-mode launch and separate application lifecycle probes have privileged evidence |
| Ownership and reconciliation | Immutable creation-time owner bindings, fresh preflight verification, read-only convergence classification, restoration and cleanup executors | Hostile privileged mutation remains outside the authority model; general in-place live updates are not authorised |
| Replacement and recovery | Generation-scoped provisioning, verified durable cut-over, launch selection, leases and old-generation retirement; conservative operation-intent recovery remains the kernel mutation foundation | Maintain generation replacement regression evidence; combined VPN-bound application and packet acceptance remains outstanding |
| Startup and persistence | `manage startup-install` renders the systemd unit, and `restore-startup` runs the boot executor with recovery; privileged restoration acceptance passed | Integrated host-domain protection, packet confinement and real-reboot acceptance; the narrowly scoped host executor exists |
| Cleanup | Ownership-aware `cleanup` and `clear-ownership` executors with dry-run plans, verified deletion and store-reset archives; privileged cleanup acceptance passed | Production integration with live update and replacement authorities |
| Integration and acceptance | Automated tests and the privileged lifecycle, application, production tunnel, failure-recovery and cooperating-process matrices pass in the disposable Arch Linux guest | Supported-platform compatibility, registered VPN-bound application acceptance and host-domain protection; independently privileged hostile mutators are outside the release boundary |

`manage graph` depicts **configured intent**, not live connectivity. Likewise, `manage cleanup-plan` and `manage transaction-plan` are advisory; they do not execute network changes. These boundaries apply even if a saved policy is persistent.

## VPN routing work in progress

The intended manager will route ordinary traffic through a default VPN country or server, while explicitly assigned applications can use other VPN profiles. Default-server optimisation will eventually select a better eligible endpoint without reconnecting or reselecting independent application overrides. Applications sharing the default profile will still be affected by default changes.

The policy and topology commands remain advisory, but separate explicitly authorised management commands can provision pinned WireGuard allocations and launch registered applications. Configuring a policy alone does not establish tunnels, change routes or DNS, or enforce a host-domain kill switch.

A working example is in [`examples/vpn-policy.json`](examples/vpn-policy.json), with the detailed design and known limitations in [`docs/VPN-ROUTING-DESIGN.md`](docs/VPN-ROUTING-DESIGN.md).

Validate a policy:

```bash
python nordvpn_policy.py --policy examples/vpn-policy.json --validate
```

Inspect its proposed routing domains:

```bash
python nordvpn_topology.py --policy examples/vpn-policy.json
```

Plan a default-server change from an existing version 1 benchmark report (advisory only):

```bash
python nordvpn_policy.py --policy examples/vpn-policy.json --report benchmark.json --current-server ad1234
```

### Saved routing intent and restart behaviour

The experimental `manage` command validates and stores **desired routing intent only**. It does not create tunnels, change host networking or install a VPN on boot by itself. Its default scope is persistent and stores the policy under `XDG_CONFIG_HOME/nord-tools/` (or `~/.config/nord-tools/`); pass `--transient` to use session-only storage under `XDG_RUNTIME_DIR` instead. Own networking resources appear only through the separately owned startup configuration and its systemd restoration unit (see [Startup restoration with systemd (startup restoration)](#startup-restoration-with-systemd-startup-restoration)); configuring a policy alone still activates nothing.

```bash
python nord_tools.py manage plan --policy examples/vpn-policy.json
python nord_tools.py manage configure --policy examples/vpn-policy.json
python nord_tools.py manage status
python nord_tools.py manage clear
python nord_tools.py manage configure --policy examples/vpn-policy.json --transient
python nord_tools.py manage status --transient
python nord_tools.py manage clear --transient
```

The experimental `manage reconcile` command compares saved intent with an explicitly supplied **simulated** inventory and prints a deterministic, read-only plan. It distinguishes create, replace, repair, retire, unchanged and blocked external-ownership conflicts. The inventory is not discovered from the host and its ownership claims are not sufficient authority to modify or remove actual networking resources. No live changes occur.

```bash
python nord_tools.py manage reconcile --inventory examples/managed-inventory.json
python nord_tools.py manage reconcile --inventory examples/managed-inventory.json --transient
```

`plan` previews whether intent would be created, replaced or left unchanged; `configure` stores it atomically. `clear` removes only the saved intent for the selected scope, **not** networking resources. Transient and persistent settings are independent. The transient scope requires a valid session runtime directory and does not silently fall back to durable storage. Ownership-aware reconciliation and boot restoration are separate commands that consume this saved policy; neither is activated by configuring intent alone.

### Disposable namespace firewall probe

`tools/probe_namespace_isolation.py` is an opt-in Linux networking experiment. It uses two disposable namespaces, a simulated tunnel interface and family-specific nftables packet counters to test a narrow IPv4/IPv6 fail-closed property before and after simulated tunnel loss. A direct route to each underlay test endpoint ensures that a blocked packet is attributable to the firewall rather than to a missing route. **It does not create a real WireGuard/NordVPN tunnel or protect the host's traffic.**

Inspect the proposed test without changing networking:

```bash
python tools/probe_namespace_isolation.py
```

Execute it only in a disposable VM initially, with `iproute2`, `nftables`, `ping` and root privileges:

```bash
sudo python tools/probe_namespace_isolation.py --execute
```

The experiment checks that underlay packets are dropped and that the relevant nftables counter increases, including after the simulated tunnel goes down. Passing does not establish DNS or IPv6 confinement, real tunnel behaviour, or safety of host-wide routing. See [the probe design and limitations](docs/VPN-ROUTING-DESIGN.md#disposable-namespace-firewall-probe).

## Requirements and platform support

**Linux is the only supported platform.** Windows, macOS and other operating systems are not currently supported. Some historical benchmark probing code contains platform-specific branches, but these do not constitute tested or supported platforms. Python 3.10 or later is required. No third-party Python packages are required for the current offline tooling.

Run the read-only preflight check before using a feature:

```bash
python nord_tools.py doctor
python nord_tools.py doctor --json
python nord_tools.py doctor --strict
```

The check reports the platform and Python version, and whether `ping`, `nordvpn`, `ip`, `nft`, `wg` and `systemctl` are available. Only the platform and Python version are universal requirements. Other executables are feature-specific: `ping` is needed for ICMP benchmarks, `nordvpn` for CLI connection support, `ip`/`nft` for the privileged namespace and underlay work, and `systemctl` for installing and verifying the systemd restoration unit. The `wg` check still describes future tunnel paths. `--strict` fails if any listed tool is missing. This is a local executable-availability check, not a guarantee of kernel support, privileges, VPN credentials or working network connectivity.

## Quick start

To download NordVPN's [official OpenVPN configuration archive](https://downloads.nordcdn.com/configs/archives/servers/ovpn.zip), extract it temporarily and benchmark UDP endpoints:

```bash
python nordvpn_benchmark.py --download --accuracy balanced --top 10
```

To use files already on disk:

```bash
python nordvpn_benchmark.py --config-dir ~/nordvpn --protocol both --accuracy thorough --top 20
```

To save the complete result set, including preliminary measurements and failures:

```bash
python nordvpn_benchmark.py --download --output results.csv --format csv
```

JSON and plain-text tables are also available with `--format json` and `--format table`. File export is optional. The `--top` option limits only the displayed table, not the exported records.

## Command-line options

| Option | Purpose |
| --- | --- |
| `--config-dir PATH` | Recursively discover local `.ovpn` files. |
| `--download` | Download and temporarily extract the official archive. |
| `--protocol udp\|tcp\|both` | Filter configuration transport; defaults to UDP. |
| `--accuracy fast\|balanced\|thorough` | Choose the measurement depth; defaults to balanced. |
| `--top N` | Display the first N ranked endpoint records; defaults to 10. |
| `--workers N` | Maximum concurrent ping subprocesses; defaults to 24. |
| `--timeout SECONDS` | Per-request timeout used for ping; defaults to 1. |
| `--output FILE` | Optionally write all results to a file. |
| `--format csv\|json\|table` | Export format; defaults to CSV. |
| `--ascii` | Use ASCII rather than Unicode table borders. |
| `--colourblind`, `--colorblind` | Use the alternative blue-to-orange latency palette. |
| `--no-colour`, `--no-color` | Disable terminal colour. |
| `--quiet` | Suppress progress messages. |
| `--verbose` | Report malformed or unsupported configurations. |

The two input options are mutually exclusive. Run `python nordvpn_benchmark.py --help` for the current CLI.

## Measurements and ranking

The initial survey sends 2, 3 or 5 ICMP requests per unique destination for fast, balanced and thorough modes respectively. A shortlist then receives 6, 12 or 25 additional requests. Survey measurements are retained. The shortlist is at least 20 destinations or three times the requested top count, whichever is larger, capped at the number discovered. These are provisional heuristics, not empirically optimised defaults.

A result records successful reply times, attempted and received probes, loss percentage, median latency and median absolute deviation (MAD) from the median. The ordering prefers lower packet loss, then lower median latency, then lower MAD. This deliberately favours reliability, although packet loss estimated from a handful of requests is uncertain. Survey-only results remain marked as such, so they are not mistaken for fully refined measurements.

ICMP probes are deduplicated by destination address, not by configuration filename or port. Multiple OpenVPN profiles using the same destination can therefore share a measurement. This is correct for ICMP but says nothing about whether their individual VPN ports work.

## Filtering configurations

Use `--filter EXPR` to select endpoints before probing. The language supports `!` (NOT), `&` (AND), `|` (OR), and parentheses, with precedence in that order. A bare two-letter code means `country:CODE`; a server identifier such as `uk2108` means `server:uk2108`. Named fields are `country`, `server`, `host`, `protocol`, and `port`. The `server` and `host` fields support `*` wildcards. Filters are case-insensitive, and repeated `--filter` options are combined using AND.

To exclude both UK and US servers:

```bash
python nordvpn_benchmark.py --download --filter='!(uk|us)'
```

To benchmark only UK or Netherlands UDP endpoints, excluding one server:

```bash
python nordvpn_benchmark.py --download --filter='(uk|nl)&protocol:udp&!server:uk2108'
```

The expression `!uk|!us` does **not** exclude both countries: by ordinary Boolean OR semantics, it matches both UK and US servers. Use `!(uk|us)` or `!uk&!us` instead. Quote expressions in the shell because `|`, `&`, `!`, and parentheses may have special meaning.

Filters are applied after configuration parsing and before any network probes. Download mode currently extracts the selected transport profiles before applying expression filters; this reduces probing work but does not yet reduce extraction work for country or server filters. Invalid expressions fail before downloading or probing. If no endpoints match, the program reports the empty selection rather than probing anything.

The table shows canonical server hostnames such as `uk2108.nordvpn.com`, not archive filenames such as `09150-uk2108.nordvpn.com.udp_2.6.ovpn`. CSV and JSON exports retain the original configuration filename as `config_file` for traceability. Auto-connect uses the same canonical identity.

## Latency colours

The terminal table includes mean and median ICMP latency. Mean values use a continuous green-to-red colour scale by default, with fixed reference points from 0 to 250 ms. A fixed scale matters because a relatively quick server in a slow batch should not automatically appear green. The alternative `--colourblind` or `--colorblind` option uses a blue-to-orange palette. It is intended to be easier to distinguish for some forms of colour-vision deficiency, although no palette is universally accessible.

Colours are presentation only. Ranking still uses packet loss, median latency and MAD, and the numeric values remain visible without colour. ANSI true-colour sequences are emitted only when stdout is an interactive terminal that supports conventional terminal controls; `NO_COLOR`, `TERM=dumb`, `--no-colour` and `--no-color` disable them. `--ascii` affects table borders independently. Exported files never contain ANSI colour sequences. Some terminals may render true colour differently or not at all.

## TCP refinement fairness

TCP surveying retains measurements for each distinct address and advertised port, but refinement now selects at most one representative port for each canonical server/address pair. The representative is the best survey result for that server, with deterministic port selection when survey measurements tie. The refinement shortlist therefore contains distinct servers rather than multiple ports for the same server, reducing unnecessary repeat connections and preventing heavily represented servers from consuming disproportionate refinement capacity.

This is a **refinement-only** reduction: the initial TCP survey still probes all eligible address/port pairs to choose the representative. CSV and JSON exports continue to include survey measurements for every eligible port, with additional refinement samples only on the selected representatives. A port's relative performance can vary over time, so the chosen representative is not guaranteed to remain the fastest port. ICMP sampling and the single-probe-method contract are unchanged.

## Progress and output

During each stage, stderr shows completed addresses, responding addresses, elapsed time and an approximate ETA. Interactive terminals refresh a single status line; redirected output receives periodic status lines. Standard output contains the final table. `--quiet` suppresses routine progress, not the final table.

The CSV export includes endpoint identity, transport, port, stage, probe counts, loss, median mean and median latency, MAD and error text. JSON additionally includes the raw successful reply times. The table export is a human-readable summary, not a lossless sample record.

## Automatic downloads

`--download` streams the archive over HTTPS, filters for the selected transport before applying bounded extraction limits, extracts `.ovpn` files into a temporary directory and removes the temporary files when the run finishes. It does not cache downloads. It also does not require or read VPN credentials. The download may be substantially larger than the files needed for a single protocol.

## Limitations and next steps

This is an initial prototype. It has not yet been calibrated against real NordVPN endpoints, and the current ping output parser is primarily aimed at conventional English-language `ping` output. The Linux implementation uses one `ping` process per destination per stage, which is simple and bounded but not necessarily the fastest possible probing strategy. Progress estimates are approximate, and pressing Ctrl+C during a batch does not yet produce a partial export.

Potential follow-up work includes empirical concurrency tuning, better handling of unresponsive survey candidates, cross-platform ping validation, a more efficient probe engine and optional genuine OpenVPN endpoint validation. None of those should be presented as implemented until tested.

## Tests

```bash
python -m unittest discover -s tests -v
```

## Connecting to a ranked server on Linux

The optional `--auto-connect` flag asks the installed NordVPN Linux CLI to connect to the first ranked server after the benchmark. It is not the NordVPN client's persistent auto-connect setting. `--connect-rank N` chooses a different rank among the displayed top results. For example:

```bash
python nordvpn_benchmark.py --download --top 20 --auto-connect --connect-rank 2
```

Use `--auto-connect --dry-run` to benchmark normally and preview the selected NordVPN connection command without connecting or disconnecting. The preview reads the NordVPN client status, reports when the selected server is already connected, and identifies when an existing connection would require confirmation or `--replace-connection`. It does not prompt, authenticate, or change the connection. `--dry-run` requires `--auto-connect`; it does not bypass the active-VPN benchmark preflight. The preview describes the intended command, not proof that the eventual connection would succeed or select the requested server.

The benchmarker checks for `nordvpn`, reads its connection status, and derives a server identifier from the canonical server hostname. It will not attempt a connection when that identifier is unavailable or the selected server returned no ICMP responses. An existing connection is left alone unless you confirm replacement interactively, or supply `--replace-connection` explicitly. Non-interactive runs cannot prompt, so they require that flag to replace an existing connection.

After issuing `nordvpn connect SERVER`, the script checks `nordvpn status` and requires the reported server to match the requested server. A failed connection returns a non-zero exit status without discarding an export already written. The client must already be installed, configured and logged in. No credentials are handled by this script, and it does not change NordVPN's configured VPN technology. Consequently, the resulting VPN transport may differ from the OpenVPN profile used for ICMP discovery. The client may also refuse a server identifier that is no longer available.

The status parser recognises English `Status:`, `Current server:`, `Hostname:` and `Server hostname:` output. Other client versions and localisations need testing; an unrecognised response causes the connection operation to stop rather than guessing. Actual client integration has not yet been verified on a live NordVPN session.

## Continuous integration and formatting

GitHub Actions runs the unit tests and checks Python source formatting on pushes and pull requests. Ruff is pinned to version 0.14.2 for consistent CI behaviour. To apply its formatting locally before committing, run:

```bash
python -m pip install 'ruff==0.14.2'
ruff format .
ruff format --check --diff .
python -m unittest discover -s tests -v
```

The CI formatting check is deliberately read-only and fails if source files need formatting. It does not automatically rewrite committed code.

## Country names and named region lists

The Country column is derived from NordVPN's server identifier. Country names come from the bundled `country-names.json` snapshot, generated from `pycountry`'s ISO 3166 data during development. The runtime does not need `pycountry` or a geolocation service. NordVPN's `uk` prefix is mapped to the United Kingdom; the prefix represents NordVPN's advertised location, not independent evidence of physical server placement.

The bundled `region-lists.json` provides an experimental `low-ads` group of 17 NordVPN OpenVPN country locations. The catalogue is manually curated against Google's published YouTube monetised-market list, independent reports and NordVPN-specific community observations. Each included code was also found in the NordVPN OpenVPN directory listing supplied for the October 2026 review. This is a shortlist of locations to *test*, not proof of advert-free playback, a general advertising classification or a guarantee. NordVPN server availability, IP geolocation and YouTube advertising behaviour can change.

See [Low-ads catalogue maintenance](docs/LOW-ADS-MAINTENANCE.md) for the current codes, evidence hierarchy, official source links, archive-verification commands, review procedure and reasons for excluding some plausible countries. The `low-ads` catalogue is deliberately hand-maintained; the generated ISO country-name snapshot is a separate dataset.

```bash
python nordvpn_benchmark.py --download --region-list low-ads
python nordvpn_benchmark.py --download --filter='list:low-ads|country:nl'
python nordvpn_benchmark.py --list-region-lists
python nordvpn_benchmark.py --download --region-lists-file ~/.config/nordvpn-benchmark/regions.json --region-list low-ads
```

Custom JSON files have the same shape as the bundled catalogue: an object mapping group names to objects with a `description` string and a `countries` array of lowercase two-letter codes. Custom groups override built-in groups of the same name rather than merging them. Invalid codes, duplicate countries and malformed definitions are rejected before probing. Multiple `--region-list` options are combined using AND, like repeated `--filter` options.

## Distinct-server results

The terminal table displays one rank per canonical hostname and destination IP, rather than repeating the same ICMP measurement for each OpenVPN port. Where a hostname resolves to different measured IP addresses, those endpoints remain distinct. `--top` and `--connect-rank` refer to the displayed ranking. CSV and JSON exports continue to include every configuration and port, since ICMP does not test whether a particular OpenVPN port is available.

## Development checks

The GitHub Actions workflow runs the unit tests, `ruff check .` and `ruff format --check --diff .`, with Ruff pinned to version 0.14.2. Run the same commands locally before committing; the entry-point script must retain its executable bit in Git.

### Country-code aliases and ISO data

NordVPN server hostnames are preserved exactly, but country matching uses canonical ISO 3166-1 alpha-2 codes. For example, NordVPN's `uk` prefix maps to `gb`. Both `--filter uk` and `--filter gb` match UK servers; `country:uk` and `country:gb` are equivalent. Named region lists accept either spelling and normalise entries when loaded. Duplicate aliases such as `uk` and `gb` in the same list are rejected.

The country-name snapshot is generated, not hand-maintained. To update it, install the development-only dependency `pycountry==24.6.1` and run `python tools/generate_country_names.py`. CI checks the snapshot with `python tools/generate_country_names.py --check`. The runtime requires neither `pycountry` nor an internet connection for names. Provider-specific aliases remain deliberately explicit in `nordvpn_regions.py`. The curated `low-ads` list remains hand-maintained because ISO country data cannot establish advertising behaviour or NordVPN OpenVPN availability.

## Early country filtering

Country-only restrictions, including named region lists and Boolean expressions composed entirely of country and list selectors, are evaluated against recognised NordVPN configuration filenames before extraction and profile parsing. This reduces disk I/O and parsing work when a small subset of locations is selected. The full filter expression is still evaluated against parsed endpoints before DNS or ICMP measurements.

Filters that depend on server, host, transport or port metadata are evaluated after parsing. Mixed expressions are not used to exclude profiles early, because doing so could change the result of an OR expression. Filenames that do not match NordVPN's recognised naming convention also fall back to normal parsing. Country aliases such as `uk` and `gb` remain equivalent.

The OpenVPN ZIP is still downloaded in full; this optimisation does not reduce archive download bandwidth. It also does not change the ranking or export format.

## Test strategy

The GitHub Actions workflow runs Ruff linting, Ruff formatting and generated ISO country-data verification as a separate quality job. An independent offline test matrix runs on Python 3.11, 3.12 and 3.13 on every push and pull request. The tests use synthetic OpenVPN profiles, in-memory ZIP archives and mocked ICMP/client calls; they do not need NordVPN credentials, real network access or a working VPN connection.

The test jobs also report branch coverage, with an XML report uploaded from Python 3.13. Coverage is diagnostic rather than a release threshold at present. Run the suite locally using `python -m unittest discover -s tests -v`. Live NordVPN downloads and real VPN connection tests are intentionally excluded from routine CI.

## VPN connection preflight

Before downloading profiles or probing servers, the benchmarker checks the NordVPN Linux CLI when available. If it confirms an active NordVPN connection, the run stops without disconnecting or replacing that connection. Disconnect manually using `nordvpn disconnect` before benchmarking to avoid measuring through the tunnel. Use `--allow-active-vpn` to deliberately continue through an active connection; a warning remains visible. If the NordVPN client is absent or its status cannot be read, the check reports uncertainty and continues. Other VPN clients and routes are not reliably detected by this check, so verify your network path separately. The preflight also applies when `--auto-connect` is requested; automatic connection occurs only after measurements finish.

### Country flags in terminal results

The Unicode terminal table prefixes recognised countries with their flag emoji (for example, `🇬🇧 United Kingdom`). Flags are derived from canonical ISO country codes, including NordVPN's `uk` to `gb` alias, and require no additional dependency. Unrecognised locations retain their text label without a flag. Use `--ascii` for a plain-text table without emoji; CSV and JSON exports continue to contain country names rather than presentation-only emoji. Flag appearance depends on the terminal's font and emoji support.

## Probe methods

The default `--probe icmp` retains the original ICMP benchmark. Some functioning VPN servers do not answer ICMP, so zero replies mean *ICMP unresponsive*, not offline.

Use `--probe tcp --protocol tcp` to time TCP connection establishment to the port advertised in each TCP OpenVPN profile. A successful TCP handshake does not prove OpenVPN authentication or throughput. The result table includes a **Probe** column, and TCP measurements are port-specific. TCP mode requires matching TCP profiles; the default `--protocol udp` must be changed to `tcp` or `both`.

Each benchmark run uses **exactly one** probe method. There is no automatic fallback or mixed-method ranking: TCP handshake times and ICMP round-trip times measure different operations and must not be compared as equivalent latency. With `--probe tcp --protocol both`, only the matching TCP profiles are benchmarked; UDP profiles are not silently assigned TCP results. Use `--protocol tcp` to make this selection explicit. The default `--protocol udp` is incompatible with `--probe tcp` and produces a clear argument error.

```bash
python nordvpn_benchmark.py --download --region-list low-ads --protocol tcp --probe tcp --top 20
python nordvpn_benchmark.py --download --region-list low-ads --protocol udp --probe icmp --top 20
```

UDP `connect()` is not a network handshake. Protocol-aware UDP probing and optional authenticated tunnel validation remain future investigations. Automatic connection is refused if the selected rank has no successful probe.

### Console phase headings

Interactive benchmark runs identify Configuration, Server discovery, Initial benchmarking, Refinement and Results as they execute. Headings and progress diagnostics are written to stderr, while the ranking table remains on stdout. Terminal headings use Unicode rules; `--ascii` and redirected diagnostics use plain ASCII without terminal control sequences. `--quiet` suppresses headings and progress, but not the requested results.

## Console phase spacing and connection verification

The diagnostic console separates completed phases with a single blank line. Phase headings and progress remain on standard error, while the results table remains on standard output. Quiet mode suppresses phase headings and their spacing.

Automatic connection distinguishes a failed NordVPN command or disconnected status from a connected status without a reported server identity. When the CLI reports `Status: Connected` but omits `Current server`, the tool reports that the VPN connection is established but the requested server identity is **unverified**. It does not claim to have connected to the selected server, and it does not disconnect or retry automatically. A reported server identity that differs from the requested one remains a verification error.

## Derived endpoint cache

`--download` now maintains a versioned JSON catalogue of parsed OpenVPN endpoints at `$XDG_CACHE_HOME/nord-bench/endpoints.json` (or `~/.cache/nord-bench/endpoints.json`). It caches the full endpoint inventory, independent of the selected region, transport or filter, but never caches latency measurements or VPN credentials. The first run still downloads and parses the complete archive. Later runs reuse the catalogue within the default 24-hour freshness interval. After that, the benchmarker attempts an HTTP conditional request when supported and otherwise downloads the archive and compares its SHA-256 digest. An unchanged digest avoids reparsing. The digest is a local change detector, not an independently authenticated checksum published by NordVPN.

Use `--cache-ttl 6` to check for updates after six hours, `--refresh-cache` to force a remote check, `--offline` to use an existing validated catalogue without network access, `--no-cache` to retain the previous download-and-extract workflow, and `--cache-file PATH` to choose a different catalogue location. These options apply to `--download`; `--config-dir` continues reading local profiles directly. Updates are written atomically after parsing and validation. A failed update does not overwrite an existing valid catalogue. Offline mode refuses missing or invalid caches instead of silently downloading anything.

## Exploratory ranking stability

Use `--stability` to display an additional advisory assessment of the ranked servers without changing their order or the CSV/JSON export schema. The assessment computes deterministic 90% percentile-bootstrap intervals for the sample median of each displayed responsive endpoint. It requires at least eight successful timing samples per endpoint; otherwise the interval is marked unavailable. The calculation uses the actual samples collected during the run and does not generate additional network traffic.

```bash
python nordvpn_benchmark.py --download --protocol tcp --probe tcp --stability --top 20
```

The report indicates whether a candidate's interval overlaps the ranked leader's interval. Overlap does not establish equivalent performance, and non-overlap is not a formal pairwise significance test. Bootstrap intervals assume sufficiently independent, stable samples, which sequential network measurements may violate. Results are exploratory and should not be interpreted as probabilities that a server is fastest, or as evidence of actual VPN throughput. The existing loss-first, median-based ranking and auto-connect selection remain unchanged.

### NordVPN status identity recognition

For automatic connection verification, the Linux CLI status parser recognises the English `Current server:`, `Hostname:` and `Server hostname:` fields. Values must be canonical NordVPN server hostnames (for example `uk715.nordvpn.com`) or exact short server identifiers (`uk715`). It does not infer an identity from the country, city, endpoint IP address or connection-success message. Missing identity remains unverified, while conflicting or malformed identity fields cause verification to fail closed. NordVPN CLI output can change between versions; live compatibility should be checked against the installed client.

### Reproducible benchmark reports

Use `--report benchmark-report.json` to write a separate, versioned JSON report alongside the existing `--output` CSV, JSON or table export. The report contains UTC start and completion timestamps, the selected probe method and benchmark settings, source catalogue provenance where available, sampling methodology, every per-endpoint measurement (including failed probes and individual samples), the distinct-server ranking and optional stability diagnostics. The report is written atomically so an interrupted write cannot replace a previous complete report. The report describes a completed measurement run, not a promise that later network measurements will be identical. For cached downloads, the source SHA-256 identifies the downloaded archive; it is not an independently authenticated publisher checksum. When using a local configuration directory or bypassing the derived cache, an archive digest is not available and is not invented. Reports do not include VPN credentials or OpenVPN profile contents.

Example: `python nordvpn_benchmark.py --download --protocol tcp --probe tcp --accuracy balanced --stability --report benchmark-report.json`

### Optional adaptive refinement

Use `--adaptive` to divide the existing refinement budget into two rounds. The first round samples every shortlisted server or address; the second retains the leading `--top` responsive targets, additional candidates whose median and median absolute deviation ranges overlap the leader's conservative range, and unresponsive targets for another attempt. The method uses a minimum 1 ms tolerance and does not claim statistical significance. The overall per-target sample cap remains the selected accuracy preset, and skipped second-round probes reduce network load. Results record actual attempts and samples, so adaptive and fixed-refinement results should not be treated as equally sampled. The default remains fixed refinement, and `--adaptive` works with either ICMP or TCP without mixing probe methods. This heuristic can exclude a genuinely competitive server because of noisy early measurements; use fixed refinement for more uniform comparisons.

### Comparing fixed and adaptive sampling

To evaluate adaptive refinement against fixed refinement, run matched benchmarks with identical filters, probe method, accuracy and other settings. Save separate versioned reports using `--report`, alternating the run order where practical to reduce systematic time-of-day bias. For example, run the usual benchmark once with `--report fixed-1.json` and once with `--adaptive --report adaptive-1.json`, then repeat the pair on several occasions. Avoid `--auto-connect` during these comparisons because changing VPN state would alter the network conditions.

Compare the reports offline with `python tools/compare_sampling.py --fixed fixed-1.json fixed-2.json --adaptive adaptive-1.json adaptive-2.json --top 10`. The tool checks that paired reports use matching benchmark settings, source provenance and sampling budgets, then shows total probe-attempt savings, top-ranked server-set overlap and winner agreement. It refuses mismatched inputs rather than silently comparing different methods or catalogues. Results are descriptive: sequential runs can disagree because of changing network conditions, and agreement does not prove statistical equivalence. The comparator performs no network operations and does not modify the reports.

## Routing policy and management diagnostics

The proposed default-VPN and per-application routing architecture is documented in [docs/VPN-ROUTING-DESIGN.md](docs/VPN-ROUTING-DESIGN.md). An offline default-optimisation preview is available through `nordvpn_policy.py`; it reads an existing versioned benchmark report and **does not** connect, disconnect or modify networking. Pinned independent application tunnels and explicit registered launch operations exist; integrated VPN-bound launch-to-packet acceptance and automatic switching remain outstanding.

### Offline ownership audit

Use `python nord_tools.py manage audit --registry examples/managed-registry.json --inventory examples/managed-inventory.json` to compare an illustrative resource ledger against a simulated profile inventory. The audit rejects ambiguous resource identities and reports conflicts, missing profiles and unverified claims. It never discovers, creates or removes live networking resources. In particular, a saved ownership claim is not proof that a kernel resource belongs to Nord Tools. See [the routing design](docs/VPN-ROUTING-DESIGN.md#offline-resource-ownership-audit).

### Disposable routing feasibility probe

An opt-in namespace firewall experiment is documented in [the routing design](docs/VPN-ROUTING-DESIGN.md#disposable-namespace-firewall-probe). Run `python tools/probe_namespace_isolation.py` for a no-change preview. The privileged `--execute` mode should be used in a disposable VM; it does not establish a real VPN.

### Read-only Linux networking discovery

Run `python nord_tools.py manage discover` on Linux to inspect host and namespace interfaces, IPv4 and IPv6 routes, and nftables rulesets through read-only `ip` and `nft` commands. Output is structured JSON and does not require saved policy or root privileges where the host permits ordinary namespace listing. Discovery fails rather than silently reporting partial results if a command fails or returns invalid data.

The discovery output is **not an ownership registry**. It does not verify firewall effectiveness, DNS, service state or ownership, and it cannot authorise networking changes. Windows and macOS are unsupported. The `nft` executable and sufficient privileges to read rulesets are required; an inaccessible ruleset fails discovery rather than silently omitting firewall state.

### Read-only ownership evidence correlation

`manage evidence` compares an explicit offline ownership ledger with current Linux namespace and interface observations. It reports name matches, missing names, ambiguous interface scopes and unsupported resource kinds. An interface claim must use `host:interface-name` or `namespace-name:interface-name` to avoid confusing identical names in different namespaces. This is diagnostic correlation, **not independently verified ownership**: matching names never authorise replacement or deletion. The command does not change networking, and incomplete discovery fails closed.

```bash
python nord_tools.py manage evidence --registry examples/managed-registry.json
```

Routes, nftables rules, DNS and services still require stronger evidence models before any privileged management is enabled.

### Resource allocation identities

`python nord_tools.py manage identities --registry examples/managed-allocations.json` validates a version 2 allocation ledger containing a random, per-resource `allocation_id`. Allocation identities are distinct from interface and namespace names, which can be reused. This command is read-only and does not establish that a kernel resource belongs to Nord Tools. The creation-time ownership verification owner-record store and the startup restoration and cleanup executors now provide that binding for namespaces and interfaces; route, firewall, DNS and service kinds still have no binding model and wait for their consumers.

### Allocation evidence and stale-state diagnostics

`python nord_tools.py manage identity-evidence --registry examples/managed-allocations.json` correlates version 2 allocation claims with live, read-only Linux discovery. It distinguishes absent names, ambiguous scopes, unsupported resource kinds and observed names that may have been reused. No classification verifies the allocation token or authorises modification or deletion. A missing name may indicate an interrupted provisioning attempt or a resource that was never created; the command does not guess which.

### Offline dependency-aware reconciliation

`python nord_tools.py manage dependency-plan --inventory examples/managed-inventory.json --graph examples/profile-dependencies.json` orders proposed profile operations against an explicit, versioned dependency graph and the saved policy (persistent by default; add `--transient` for session intent). The graph must enumerate every desired or simulated observed profile, and dependencies must remain in the desired configuration. Creation and repair are ordered after prerequisites, while retirement is ordered in reverse. Cycles, unknown dependencies and attempts to retain a profile whose prerequisite is retired are rejected. An external ownership conflict blocks dependent profiles. The result is a deterministic, read-only simulation, not a privileged execution plan or ownership authorisation.

### Offline transaction and recovery contract

`python nord_tools.py manage transaction-plan --inventory examples/managed-inventory.json --graph examples/profile-dependencies.json` describes gated preparation, cut-over, retirement and recovery obligations for the dependency-ordered simulated changes. It explicitly requires independently verified ownership, live preflight, a durable operation journal and firewall/DNS protection before execution could be considered. The command only prints JSON; it does not create a journal, perform rollback or modify networking. Persistent saved intent is selected by default, with `--transient` selecting session intent.

### Configuration graph and cleanup preview

The final offline management commands show configured routing relationships and preview possible cleanup candidates. Neither command inspects verified tunnel status or changes networking:

```bash
python nord_tools.py manage graph
python nord_tools.py manage graph --ascii
python nord_tools.py manage graph --transient
python nord_tools.py manage cleanup-plan --inventory examples/managed-inventory.json
```

`graph` uses the saved policy (persistent by default), groups applications by their assigned shared or isolated profile, and labels all connections as **configured intent, not live networking**. The ASCII option works without box-drawing characters. `cleanup-plan` accepts a simulated inventory, excludes externally owned profiles, and lists possible retirements only. Its output explicitly states that execution is unsafe without independently verified ownership, dependency-aware teardown and recovery protections. It does not remove resources or clear saved policy. See the [routing design](docs/VPN-ROUTING-DESIGN.md) for the safety contract.

The optional hidden terminal puzzle supports a cinematic ANSI/Unicode reveal in interactive UTF-8 terminals. Its roughly eight-second sequence uses deliberately uneven progress, alternating rapid acquisition with slower verification intervals; the percentage is theatrical rather than a measure of actual work. Use `--no-animation` or `NORD_TOOLS_REDUCED_MOTION=1` for a static display, `--ascii` for plain text, and `--no-colour` or `NO_COLOR` to suppress colour. Its animated display combines converging Unicode worldline trajectories, distinct ANSI colours and a fictional numerical search with hexadecimal probe addresses and shrinking search intervals. The animation is theatrical and does not perform a real numerical search. Its compressed scene is stored as an authenticated, password-derived cipher payload; as with any puzzle shipped in source code, this is not a security boundary.

### Rebuilding the Operation Kongroo launcher

The hidden `divergence` command loads the generated `nordvpn_kongroo_packed.py` module. Its canonical, readable implementation remains in `nordvpn_kongroo.py`, with the deterministic generator at `tools/generate_kongroo_launcher.py`. After editing the canonical source, run `python tools/generate_kongroo_launcher.py` and verify it with `python tools/generate_kongroo_launcher.py --check`. The generated module contains compressed, base85-encoded Python source and an integrity checksum; it is deliberately harder to read at a glance but is **not encrypted**. No key exists, and the readable original is included in the repository. Do not use this mechanism for sensitive code or credentials. The generated module executes only its bundled, locally generated source and does not fetch external code.

### Regenerating the Operation Kongroo transmission

The optional `tools/generate_kongroo_blob.py` utility regenerates the encrypted scene when its text or decoding phrase changes. To re-encrypt the existing scene with a new phrase, run `python tools/generate_kongroo_blob.py --current --update-module`. The utility prompts for the existing and replacement phrases without placing them in shell history. To change the scene, prepare a JSON file outside the repository and run `python tools/generate_kongroo_blob.py --scene /path/to/scene.json --update-module`. The scene must contain `message` (a list of strings), `phases` (a list of strings), `signature` (a decimal value with six fractional digits), `glyphs` (`0123456789ABCDEF`) and `footer` (a string). Without `--update-module`, the tool prints the replacement `CIPHERTEXT` and `TAG` assignments for review instead of editing the module. Test the new phrase using `python nord_tools.py divergence --decode 'your phrase' --no-animation`, and review the resulting diff before committing. Avoid passing real secrets as command-line arguments or committing plaintext scene files. This is a recreational puzzle cipher, not a secure secrets-storage mechanism.

## Disposable WireGuard integration experiment

`python nord_tools.py wireguard-probe` prints the planned experiment without changing networking. On a disposable Linux VM, `sudo python nord_tools.py wireguard-probe --execute` creates two separate client/server WireGuard pairs inside four temporary namespaces, verifies tunnel traffic, a fresh bidirectional WireGuard peer exchange and shutdown, then attempts cleanup. The experiment requires `ip`, `wg`, `ping`, root privileges and kernel WireGuard support. It does not install NordVPN credentials, modify host default routes, configure DNS or establish production leak protection. **Do not run it on a critical host until you have reviewed the implementation.** The two-pair connectivity experiment passed a privileged test on Arch Linux; crash and interruption handling remain unverified.

### Read-only lifecycle correlation

An experimental lifecycle journal can be compared with a complete live Linux discovery snapshot without changing networking:

```bash
python nord_tools.py manage lifecycle --journal path/to/lifecycle.json --live
```

The output identifies missing names, ambiguous interface scopes and possible lifecycle drift. A name match, allocation token or journal entry does **not** establish kernel resource ownership. The command cannot authorise modification or deletion; the sanctioned resolution of interrupted evidence is the interrupted-operation recovery recovery executor through the same immutable stores. Cooperating journal writers already use advisory locking. Use `--observed` instead for an explicitly simulated fixture; the two options cannot be combined.

### Ownership and recovery diagnostics

Internal fingerprint, lifecycle, recovery and operation-intent modules support read-only assessment of resource drift and interrupted work. They do not prove kernel ownership or execute recovery. The experimental disposable namespace primitive retains a process-bound descriptor for identity checks, but is not a production cleanup mechanism. The privileged smoke probe (`sudo python tools/probe_namespace_ownership.py --run-privileged`) passed on Arch Linux with no named namespaces left behind. See the [routing design](docs/VPN-ROUTING-DESIGN.md#process-bound-disposable-namespace-ownership-experiment) for limitations and safe test instructions.

### Ownership verification preflight (creation-time ownership verification)

`python nord_tools.py manage ownership-preflight --journal path/to/lifecycle.json --bindings path/to/owner-bindings.json` performs the first privileged ownership-verification step. The owner-record store records, at creation time and while the creator still held descriptor-bound authority, the kernel identity of each created resource: the `/run/netns` mount device and inode pair for a namespace, or the creation-time interface scope and index for an interface. Records are validated against the lifecycle journal, are immutable once written, and are written through the same locked, atomic, symlink-refusing pattern as the other stores.

The preflight re-derives each recorded identity from fresh read-only discovery and classifies every allocation: `verified_current`, `resource_missing`, `identity_conflict` (including suspected name reuse), `unbound_claim`, `uncertain_intent`, `interrupted_transition`, `uncertain_state`, `consistent_retired`, `possible_name_reuse`, or `unsupported_resource_kind`. Observations that no allocation claims are listed separately and are treated as belonging to something else. A resource's documented name never verifies anything: a binding must match the live observation.

One unverified, foreign or uncertain allocation fails the verification of the whole batch, and offline or incomplete discovery evidence is refused rather than partially classified. Pass `--intents` to load an operation-intent store; unresolved pending or uncertain intents additionally block verification of their allocation.

```bash
python nord_tools.py manage ownership-preflight --journal journal.json --bindings owner-bindings.json
python tools/probe_ownership_preflight.py
sudo python tools/probe_ownership_preflight.py --run-privileged
```

The privileged acceptance probe creates one disposable namespace, records its binding while the creating process still holds the namespace descriptor, requires the preflight to accept the verified binding and reject a deliberately mistaken interface claim, then retires the namespace and requires the recorded retirement to classify consistently. A passing result establishes creation-time binding continuity **within one boot session only**: `/run/netns` is tmpfs, mount identities after a reboot cannot be rebound automatically, and a hostile process with access to the store directory is outside this evidence model. Even a verified batch never authorises mutation or deletion in this layer; later execution paths must re-verify ownership at the moment of action. The command and probe are read-only apart from the probe's explicitly authorised disposable namespace.

### Persistent desired-state reconciliation (persistent-state reconciliation)

`python nord_tools.py manage reconcile-live --journal path/to/lifecycle.json --bindings path/to/owner-bindings.json` compares the saved **persistent** desired policy against observed, ownership-verified resources and prints a deterministic reconciliation report. The command accepts an optional operation-intent store (`--intents`) and an optional profile dependency graph (`--graph`); with a graph, a blocked prerequisite blocks every desired dependent, matching the offline dependency planner.

The actual per-profile state is derived only from verified evidence: a profile's resources are present when the preflight classifies them `verified_current`, and `consistent_retired` resources count as absent. A profile's provisioned configuration counts as recorded only when the owner bindings agree on an identical recorded configuration. The classifications are `converged`, `configuration_changed`, `configuration_unverified`, `blocked`, `create_pending` and `retire_pending`. Converged means every resource is ownership-verified and the recorded configuration equals desired intent exactly; anything less is a plan, not an action. The report always states `safe_to_execute: false`, and the command neither touches networking nor the journal, intent or binding stores.

```bash
python nord_tools.py manage reconcile-live --journal journal.json --bindings owner-bindings.json
```

Transient intent is structurally excluded: `--transient` is rejected, because session intent must never be restored at boot or reconciled later. `create_pending` never allocates anything automatically; retired verified resources re-enter creation only through a future authorised provisioner, and retirement of undesired verified resources is reserved for the separately confirmed cleanup command. Running the command twice on unchanged inputs produces an identical report.

### Startup restoration with systemd (startup restoration)

startup restoration closes the loop between the reconciliation foundations and the boot system. `nord_tools_internal/nordvpn_restore_executor.py` binds durable creation intents, 7.1 owner records and the existing privileged namespace, isolation, routing and WireGuard primitives into one transactional boot path, and two `manage` commands expose it:

```bash
python nord_tools.py manage startup-plan --config path/to/startup.json
python nord_tools.py manage startup-install --config path/to/startup.json --execute
python nord_tools.py manage restore-startup --config path/to/startup.json
python nord_tools.py manage apply-live --config path/to/startup.json
python nord_tools.py manage apply-live --config path/to/startup.json --execute
```

`startup-plan` renders the `nord-tools-restore.service` unit and reports what installation would do without writing anything. `startup-install` writes the unit atomically into the target directory, refuses to replace a foreign pre-existing unit, keeps an already-identical unit untouched, and rewrites a previously generated one as needed; it never enables the service. `restore-startup` is the unit's `ExecStart`: it obtains a fresh read-only ownership preflight, reconciles the persistent desired policy, restores only pinned profiles whose owned resources are entirely absent in this boot session, retires journal records for resources that an earlier boot lost, and appends a bounded startup run record. Transient intent is refused outright.

The startup configuration is a version 1 JSON document pinning every persistent path (policy, journal, owner bindings, operation intents, run record), the provider tunnel plans and the credential inputs. `tunnel_addresses` accepts one canonical address per family; a saved single `tunnel_address` remains readable and is normalised before execution:

```json
{
  "version": 1,
  "policy": "/etc/nord-tools/desired-policy.json",
  "journal": "/var/lib/nord-tools/lifecycle.json",
  "bindings": "/var/lib/nord-tools/owner-bindings.json",
  "intent": "/var/lib/nord-tools/operation-intents.json",
  "run_record": "/var/lib/nord-tools/startup-runs.json",
  "tunnels": {
    "primary": {
      "peer_public_key": "REDACTED_PUBLIC_PEER_KEY",
      "endpoint_address": "198.51.100.10",
      "endpoint_port": 51820,
      "tunnel_addresses": ["10.5.0.2/32", "fd42:5::2/128"],
      "peer_allowed_ips": ["0.0.0.0/0", "::/0"],
      "underlay": {"namespace_address": "10.214.0.2/30", "host_address": "10.214.0.1/30"}
    }
  },
  "credentials": {"primary": "/etc/nord-tools/primary.key"}
}
```

The restoring service orders after `network-online.target`, is skipped while either the configuration or the persistent policy is absent, and runs `Type=oneshot` with `RemainAfterExit`. Private keys are never arguments, environment variables or configuration content: the unit declares `LoadCredential` entries, systemd hands the executor read-only descriptors, and the executor's descriptor boundary re-validates the file every time. Enable the unit explicitly when you want restoration at every boot:

```fish
sudo systemctl daemon-reload
sudo systemctl enable --now nord-tools-restore.service
```

Idempotency is structural: a converged profile is left untouched, so a repeat run (manual or after a service restart) reports `network_changes_applied: false` and appends exactly one run record. Ordering follows an optional dependency graph, prerequisites are restored first, and a dependent is refused when a prerequisite cannot be restored or is merely blocked. Failure handling is fail-closed: the first uncertain step stops the whole run, the attempt's own namespace is rolled back, its allocations are recorded as failed and its creation intent stays uncertain for review, and running profiles that never began remain exactly as observed.

Two boundaries must be stated plainly. First, provider tunnel plans pin a single numeric endpoint, peer key and one or two tunnel addresses per profile: NordVPN's fastest-server selection and country pools are not resolvable at boot without provider data, so unpinned profiles are reported as not restored rather than guessed. Second, the restoration scope is the namespace domain: the default profile's host-domain routing (the host kill switch) modifies host firewall and routing state and is deliberately outside this increment, and the executor reports any such profile rather than partially configuring it. The production-installed dual-stack path has scoped guest evidence, while application DNS bypass, failure injection and host-domain acceptance remain outstanding. Run acceptance probes only on a disposable-capable Linux test system:

```bash
python tools/probe_restore_startup.py
sudo python tools/probe_restore_startup.py --run-privileged
```

Inspect `sudo ip netns list` and the created host interfaces afterwards; the probe retires only the one disposable namespace whose recorded binding it re-verified, and removes only its own underlay pair.

### Ownership-aware cleanup and reset (ownership-aware cleanup)

The cleanup executor is the project's only destructive path, and its classification is entirely ownership-evidence based. The dry run is the default invocation and prints the exact classification and the exact deletion sequence that `--execute` would run; nothing changes without it:

```bash
python nord_tools.py manage cleanup --journal path/to/lifecycle.json --bindings path/to/owner-bindings.json
python nord_tools.py manage cleanup --journal path/to/lifecycle.json --bindings path/to/owner-bindings.json --intents path/to/operation-intents.json --execute
python nord_tools.py manage clear-ownership --config path/to/startup.json --execute
```

`cleanup` consults the saved persistent policy: verified resources of retained profiles are preserved, and every verified resource outside it is removable. A fuller classification covers every allocation exactly once: `removable`, `preserved` (including records that are consistently retired and foreign-safe), `review_required` and the separately listed `unclaimed` observations that belong to something else. A profile with any disputed finding, an unresolved intent, an identity conflict or a name-reuse suspicion is reviewed whole rather than partially deleted, and execution is refused while any uncertainty remains. Executing requires the operation-intent store, so an interrupted or failed prior attempt is visible and blocks the run until review.

Execution order deletes dependents before prerequisites (using the optional `--graph`), and one deletion never proceeds without three confirmations: a durable retire intent recorded first, the recorded owner identity re-verified against the live kernel at the moment of deletion, and a fresh observation confirming absence before the journal records `retired`. Deleting a verified namespace removes its namespace-local interfaces and firewall table with it; deleting the verified host underlay interface removes the underlay pair and its auto connected route; routes, nftables objects and DNS configuration are therefore never flushed or rewritten on the host outside what the verified namespaces and interfaces carried. Resolver directories under `/etc/netns` are removed only with `--resolvers`, and only where the namespace identity is verified and the directory contains exactly the expected `resolv.conf`; anything unexpected is review-required. A failed attempt leaves uncertain intents and journal states for review and stops the whole run, so partial failure is always connectable to exact evidence.

`clear-ownership` is the explicitly confirmed full reset: every verified owned resource is removed regardless of the saved policy, and after the teardown the journal, bindings, intents and run record are byte-verified archives under `ownership-reset-archive/` before empty stores are created in their place. The archive keeps every retirement record, so the name-reuse detection evidence survives; the saved policy itself is untouched and remains removable with `manage clear`. Repeat runs converge: after a completed cleanup the plan is empty and nothing changes, and after a full reset there is nothing recorded to plan at all.

The privileged acceptance probe is designed to run the full cycle on a disposable Linux test host: restore one pinned profile, clean it, then verify that its namespace and host underlay are gone. Unrelated host namespaces are outside the fixture and remain untouched. As before, inspect `sudo ip netns list` and any leftover host interfaces afterwards:

```fish
python tools/probe_cleanup.py
sudo python tools/probe_cleanup.py --run-privileged
```

### Crash, restart and interrupted-cleanup recovery (interrupted-operation recovery)

`nord_tools_internal/nordvpn_recovery_executor.py` is the only sanctioned path for resolving the uncertainty the provisioning and cleanup executors can leave behind. The `recovery` command plans from the evidence on disk and never from assumption: every unresolved operation intent and every interrupted lifecycle state is paired with a fresh read-only observation and classified with its exact obligations:

```bash
python nord_tools.py manage recovery --journal path/to/lifecycle.json --bindings path/to/owner-bindings.json --intents path/to/operation-intents.json
python nord_tools.py manage recovery --journal path/to/lifecycle.json --bindings path/to/owner-bindings.json --intents path/to/operation-intents.json --execute
```

Two authority walls divide the plan. Boot execution, which now runs first inside every `restore-startup` run, only converges state already certified by recorded creation time bindings: it finishes the durable bookkeeping of a creation whose whole binding set was recorded and still matches the kernel, rolls back a half-built creation recorded with a pending intent by deleting the identity-verified namespace and re-provisioning fresh, resolves failed and retirement records for resources the kernel does not hold, and aborts the boot entirely when anything uncertain or disputed remains. Operator execution adds everything that deletes or resolves an uncertain outcome: resuming a confirmed retirement, rolling back anything the boot wall refused, and evidencing-gated resolution of uncertain intents with `completed` or `failed`. A lookalike namespace, a live-but-unbound resource or mixed evidence is never touched: it appears under `review_required` with its exact finding and the classifier treats the surrounding profile conservatively, so no executable item shares evidence with the same-name stranger.

Recovery is idempotent by construction: an executed run changes evidence once, and a repeat run reports no items and no kernel changes. Interrupted snapshots stay honest: a failed attempt leaves its intents and journal states for review and nothing else moves. The host stays untouched outside the owned namespaces and interfaces, as in every other executor, and the command is persistent-scope only. Bring a disposable-capable Linux test host for the acceptance probe, which stops a restore child at a deterministic test-only checkpoint after durable creation intent and before the first kernel creation callback. It then terminates the child, converges through the same recovery commands and retires the recovered fixture through confirmed cleanup:

```fish
python tools/probe_recovery.py
sudo python tools/probe_recovery.py --run-privileged
```

The retirement history the journal deliberately keeps means that even a fully resolved recovery retains past generations, so name reuse detection never loses its evidence; archived history is replaced only through `clear-ownership`.

### startup restoration and cleanup privileged acceptance status

On 3 November 2026, the final tree passed 702 automated tests with 298 subtests. The standalone integrated startup restoration and cleanup matrix then passed persistence, deterministic interruption recovery, selective cleanup, repeat convergence, final verified teardown and host-state comparison. A fresh startup restoration and cleanup matrix also passed as the fifth stage of the complete privileged lifecycle acceptance runner. These results establish the documented cooperating-process lifecycle acceptance; they do not establish production fail-closed behaviour, recovery after arbitrary partial kernel provisioning or safety against independent privileged mutators.

### Integrated startup restoration and cleanup acceptance (integrated lifecycle acceptance)

One privileged matrix binds the previous increments into an operational workflow with host-isolation evidence at every stage boundary:

```fish
python tools/probe_startup_restoration_lifecycle.py
sudo python tools/probe_startup_restoration_lifecycle.py --run-privileged
```

Stage by stage it verifies exactly what the acceptance requires. Persistence: two pinned profiles restore together while a deliberately different transient policy sits in the runtime scope, and reconciliation proves the decisions identical with and without it. Recovery: the secondary profile is retired, its recreation is interrupted after durable creation intent and before kernel mutation, and recovery converges both profiles. Authorised cleanup: removing an application reference is pure bookkeeping, the departed profile is cleaned with its exact four deletions, and the shared profile's namespace, bindings and convergence survive untouched. Convergence: repeat runs leave reconciliation decisions, cleanup plans, recovery items and the kernel unchanged. Final teardown retires the surviving fixture before its temporary ownership stores are removed. Isolation: host IPv4/IPv6 routes, nftables configuration and resolver contents are compared across every stage boundary, and any unexplained drift fails the run. The matrix finishes by printing the production work that remains after lifecycle acceptance:

```fish
sudo ip netns list
ip link | grep nthl
cat /tmp/nt-part7-acceptance-*/startup-runs.json 2>/dev/null
```

Only pinned tunnel plans are provisioned, credentials travel through `LoadCredential`-style descriptor inputs, and no stage touches host firewall or resolver state. Run the privileged matrix only on the disposable test host and preserve the evidence directory when a stage fails.

## Internal package organisation

The supported entry point remains `python nord_tools.py`. Lifecycle, identity, discovery, reconciliation and ownership implementation modules now reside in `nord_tools_internal/`; they are not standalone user commands. Development and privileged acceptance probes remain in `tools/`. Existing command-line options and the privileged namespace smoke probe retain their entry points.

recovery triage establishes offline lifecycle and operation-intent records, read-only Linux evidence correlation, inter-process journal locking and process-bound disposable namespace identity checks. The privileged normal-operation namespace smoke test passed on Arch Linux, including confirmation that no named namespaces remained. Later startup restoration and cleanup and privileged lifecycle acceptance cover deterministic interruption before the first kernel creation callback, but does not prove safe deletion under concurrent privileged name replacement or recovery after arbitrary partial kernel provisioning.

## WireGuard provisioning development

provisioning has delivered experimental disposable WireGuard configuration, peer verification and journal-gated execution, alongside a validated offline specification and descriptor-based credential input. The production restoration executor can provision pinned WireGuard allocations with durable creation-time ownership, recovery and namespace firewall/routing controls. Provider credential acquisition, server selection and end-to-end VPN-bound application confinement remain incomplete. Host-default protection now has a separate executable lifecycle, described below, but it still needs disposable privileged acceptance before it should be enabled on an ordinary workstation. See `docs/VPN-ROUTING-DESIGN.md` and `TODO.md` for the remaining acceptance boundaries.

## Host-default protection

The host-default executor supports one deliberately narrow Linux arrangement: a stable, statically addressed IPv4 physical egress, `systemd-resolved`, one pinned numeric IPv4 WireGuard endpoint, dual-stack tunnel addresses and no NetworkManager, firewalld, UFW or second WireGuard tunnel competing for host networking. Other arrangements are refused. Restricting the underlay to IPv4 avoids pretending that an IPv6 endpoint can work while neighbour discovery and router advertisements are deliberately blocked. The executor creates only the dedicated `inet nord_tools_host` nftables table, the plan's WireGuard interface, two dedicated policy rules and route table, and resolver state attached to that interface.

Previewing a plan performs no inventory or mutation:

```bash
python nordvpn_manage.py host-plan --host-plan examples/host-protection-plan.json --host-store /var/lib/nord-tools/host-protection.json
```

The host firewall confines established inbound traffic to the tunnel interface and permits pinned inbound WireGuard transport packets separately. Its physical-output exception also requires the configured WireGuard socket mark, in addition to the endpoint, port, source and interface restrictions. A sufficiently privileged process could forge that mark; the policy does not claim to authenticate the originating process. Pre-existing non-VPN underlay sessions may be interrupted. Privileged packet and DNS leak acceptance is still required.

Activation requires root, a private store directory and a root-readable WireGuard private-key file. It records intent before every mutation, installs and reads back the deny barrier first, then adds the endpoint-only physical path, WireGuard interface, dual-stack routing and `systemd-resolved` link state. A current handshake is required for `active_verified`; without it the state remains `protected_tunnel_unavailable`, with the deny barrier retained.

```bash
sudo install -d -m 0700 /var/lib/nord-tools
sudo python nordvpn_manage.py host-activate --execute \
  --host-plan /etc/nord-tools/host-protection.json \
  --host-store /var/lib/nord-tools/host-protection.json \
  --private-key /etc/nord-tools/default.key
sudo python nordvpn_manage.py host-status \
  --host-plan /etc/nord-tools/host-protection.json \
  --host-store /var/lib/nord-tools/host-protection.json
```

Failure and process death do not trigger automatic fallback to ordinary host egress. `host-recovery` is read-only unless `--execute` is supplied, and even its executing form never removes the barrier. Deactivation re-verifies each recorded object, retires resolver, routes, WireGuard and the endpoint exception in dependency order, then requires both `--execute` and `--expose-host-egress` before removing the final barrier:

```bash
sudo python nordvpn_manage.py host-deactivate --execute --expose-host-egress \
  --host-plan /etc/nord-tools/host-protection.json \
  --host-store /var/lib/nord-tools/host-protection.json
```

This path coordinates cooperating Nord Tools processes and checks identities immediately before removal. A separate privileged actor can still race a verified kernel object, and the filesystem lock does not exclude such an actor. Use only a disposable VM with out-of-band console access while the privileged host matrix remains outstanding.

Persistent protection uses two generated systemd units. The barrier unit has no ordinary default dependencies, waits for the filesystems containing its inputs, and runs before `network-pre.target`; it installs and verifies only the deny table. Failure isolates `emergency.target` instead of deliberately continuing the boot without a barrier. The activation unit requires that service, waits for `network-online.target`, receives the private key through a systemd credential and continues the same current-boot transaction. Prior-boot evidence is archived only after every recorded kernel object is absent. Preview and installation are separate:

```bash
sudo python nordvpn_manage.py host-startup-plan \
  --host-plan /etc/nord-tools/host-protection.json \
  --host-store /var/lib/nord-tools/host-protection.json \
  --private-key /etc/nord-tools/default.key
sudo python nordvpn_manage.py host-startup-install --execute \
  --host-plan /etc/nord-tools/host-protection.json \
  --host-store /var/lib/nord-tools/host-protection.json \
  --private-key /etc/nord-tools/default.key
sudo systemctl daemon-reload
sudo systemctl enable nord-tools-host-barrier.service nord-tools-host-activate.service
```

The store directory and plan must exist before the early unit runs. Neither unit automatically removes the barrier: a failed activation or later tunnel loss remains fail closed, and administrative deactivation still uses the explicit command above. Unit ordering and reboot recovery have offline regression coverage, but the disposable reboot and packet-capture matrix has not yet been run.

`python tools/probe_host_default_lifecycle.py --plan PLAN --store STORE` previews the ordered lifecycle without inspecting the host. On a disposable root-owned VM, the privileged form requires a fresh store, a mode 0700 evidence directory and explicit permission to restore ordinary host egress after successful verified retirement:

The paths below are examples. Nord Tools does not create `/etc/nord-tools/host-protection.json`, obtain a provider peer, or generate `/etc/nord-tools/default.key`; the operator must install a real plan and matching key from the controlled WireGuard fixture first. Do not substitute the state of an already-running NordVPN client, since the supported preflight refuses competing WireGuard links and network managers.

```bash
sudo python tools/probe_host_default_lifecycle.py \
  --run-privileged --allow-host-egress-on-success \
  --plan /etc/nord-tools/host-protection.json \
  --store /var/lib/nord-tools/host-protection-probe.json \
  --private-key /etc/nord-tools/default.key \
  --evidence-dir /var/lib/nord-tools/host-probe-evidence
```

The probe captures links, routes, rules, nftables and resolver-file evidence before activation and after retirement. If activation cannot reach `active_verified`, it retains the deny barrier and stops; use `host-status` and `host-recovery` from the console rather than performing broad cleanup. Passing this lifecycle probe does not cover process death, a real reboot, packet capture or application-level encrypted DNS, so it is one input to the required host matrix rather than final acceptance.

## WireGuard credential input boundary

The internal provisioning foundation accepts a WireGuard private key only from an already-open file descriptor referring to a pipe or a regular file with private permissions. It validates canonical key encoding and overwrites its temporary input buffer on exit. The descriptor remains the caller's responsibility. This is not secure-memory storage, a credential broker, or an operational tunnel executor. Never place private keys in command-line arguments, logs or provisioning plans.

The internal operation-intent store provides locked, durable, non-privileged intent recording. It does not authorise network changes, and separate lifecycle and intent files do not form a single atomic transaction.

### Experimental disposable WireGuard configuration

`nord_tools_internal.nordvpn_wireguard_session.configure_disposable_wireguard` is an internal, explicitly experimental building block that configures a WireGuard interface inside an already-created, descriptor-bound disposable namespace. It consumes a private key through an inherited descriptor and does not install routes, change DNS, or modify host firewall settings. It does not create or retire namespaces, record durable operation intents, establish crash-persistent ownership, or provide production provisioning. The caller remains responsible for journal handling, namespace lifetime, failure recovery and all privileged authorisation. It is not exposed as a public CLI command.

### Experimental disposable WireGuard configuration probe

Run `python tools/probe_wireguard_session.py` to inspect the dry-run description. On a disposable Linux test host, `sudo python tools/probe_wireguard_session.py --run-privileged` creates one named namespace, configures a WireGuard interface through the descriptor-based session component, verifies its public key and peer, and retires the namespace. It does not establish a peer handshake or prove production provisioning, persistent ownership or fail-closed routing. Inspect `sudo ip netns list` after execution; do not delete uncertain resources based on names alone.

### Experimental creation intent execution

`nord_tools_internal.nordvpn_provision_execution.execute_recorded_creation` requires an existing validated operation store and persists a pending creation intent before invoking a caller-supplied operation. It records completion only after a caller-supplied verification succeeds. Exceptions and failed verification leave an uncertain or pending intent that blocks automatic retry. This is an internal experimental coordination boundary, not a public command or a privileged provisioning executor. The callbacks must independently establish their authority to create disposable resources. Separate lifecycle and intent files are not transactional, and these records never authorise resource deletion or production VPN provisioning.

### Journal-gated disposable WireGuard sessions

The internal `execute_disposable_session` adapter combines an existing operation-intent store, an allocation-bound lifecycle journal, descriptor-bound namespace creation, WireGuard configuration and caller-supplied kernel peer verification. It records the pending intent before creating a namespace and records completion only after the disposable namespace context returns. This is an experimental integration boundary, not persistent provisioning or proof of crash-safe ownership. Failed or uncertain sessions require manual review and are not retried automatically. Interruption, verifier failure and namespace retirement failure retain an unresolved intent; if recording uncertainty itself fails, the executor reports that persistence failure explicitly and leaves the pending intent in place.

### Integrated disposable provisioning acceptance

`python tools/probe_disposable_execution.py` is a no-change dry run. On a disposable Linux test machine, `sudo python tools/probe_disposable_execution.py --run-privileged` exercises the journal-gated creation path, kernel peer verification and namespace retirement. Afterwards, inspect `sudo ip netns list` for leftovers. This is an experimental acceptance probe, not a production VPN provisioning command. Crash-persistent ownership, race-safe deletion, full recovery and leak prevention remain outstanding.

## Production network-isolation acceptance status

The production provisioning path verifies the dedicated namespace firewall rules and objects, IPv4 and IPv6 default routes, the pinned WireGuard endpoint route, and optional namespace DNS configuration against live route, peer AllowedIPs and resolver readback. Its production confinement probe installs one owned profile with IPv4 and IPv6 tunnel addresses, carries live traffic over both families, checks endpoint-port refusal, retires the profile through verified ownership and compares host routes, nftables and resolver state before and after. The separate adversarial matrix adds DNS-shaped packet exchange, interruption recovery and lifecycle-lock checks. Application-selected alternative DNS, failed establishment, tunnel loss/restart, host-default execution and the registered VPN-bound launch path remain outstanding. See `TODO.md` and `docs/PRODUCTION-PROVISIONING-CONTRACT.md` for the exact acceptance boundary.

## network confinement: Experimental namespace isolation policy

The internal `NamespaceIsolationPolicy` renders a proposed namespace-local nftables `inet` table with default-drop input, output and forwarding, loopback allowance, established inbound replies, tunnel-bound output and one narrowly scoped UDP underlay endpoint exception. It does not install the rules, modify host firewall state or configure DNS. Production leak protection requires atomic installation before traffic is possible, routing and resolver confinement, verified ownership, and privileged failure-injection acceptance.

## Experimental namespace firewall installation (network confinement)

`nord_tools_internal.nordvpn_isolation_install.install_disposable_isolation` provides an internal, explicitly experimental check-and-apply boundary for a freshly created, otherwise empty disposable namespace. It verifies process-bound namespace evidence around an `nft -c -f -` preflight, an `nft -f -` apply and an `nft -j list table` readback. Readback requires exactly the three expected `inet` base chains, with the expected filter hooks, zero hook priorities and default-drop policies; missing or malformed evidence blocks success. This is a structural confirmation, not verification of every rule or proof of leak prevention. The ruleset is passed on standard input, not interpolated into a shell command. The caller must install it before bringing up any interfaces or starting network traffic. The new `execute_isolated_disposable_session` entry point wires this boundary into the journal-gated disposable WireGuard path, requiring the firewall check and installation before WireGuard configuration. The existing unisolated experimental entry point remains available for compatibility and must not be mistaken for fail-closed execution. This ordering does not prove that firewall installation is atomic with namespace creation. No DNS confinement, route isolation, tunnel-loss verification, restart protection or production ownership is provided. An error must block further network configuration and be investigated, not treated as a successful installation. No host firewall modifications are intended.

### Markdown checks

GitHub Actions runs `markdownlint-cli2` with a pinned version against project Markdown files. The `.markdownlint-cli2.jsonc` configuration preserves unwrapped prose by disabling MD013 (line length); generated dependencies and Git metadata are excluded. To reproduce this check locally with Node.js 22 and npm, run:

```bash
npm install --no-save --no-package-lock 'markdownlint-cli2@0.18.1'
./node_modules/.bin/markdownlint-cli2 '**/*.md'
```

This check is independent of Python tests and does not require privileged networking access.

The disposable namespace isolation probe derives a short, namespace-specific veth interface name to respect the Linux 15-byte interface naming limit. This avoids failing during test setup before firewall enforcement can be measured.

### Disposable DNS underlay probe

The opt-in `tools/probe_namespace_isolation.py --execute` probe now sends synthetic UDP and TCP packets to port 53 over its isolated IPv4 and IPv6 underlay, before and after simulated tunnel loss. It requires the corresponding namespace-local nftables drop counter to advance for every attempt. These packets use literal test addresses and do not query a resolver, alter the host DNS configuration or establish that a real VPN confines application DNS. The probe remains an experimental privileged test and must not be used as evidence of production leak prevention.

The disposable DNS packet probe accepts a synchronous `EPERM` from the packet generator only when the corresponding namespace nftables DNS drop counter advances. Other generator errors remain failures; this does not establish actual resolver confinement.

### Experimental offline namespace resolver policy

`nord_tools_internal.nordvpn_resolver_policy.NamespaceResolverPolicy` validates one to three numeric IPv4/IPv6 DNS server addresses and renders deterministic `resolv.conf` content without querying the host resolver or modifying any files. The policy rejects hostnames, duplicate servers, unsuitable local or multicast addresses and newline injection. Its public plan explicitly reports that DNS is not confined and no configuration has been installed. Before this can be used by an application, privileged integration must install namespace-specific resolver configuration, prove that each resolver is routed only through the protected tunnel, and test resolver failure and tunnel loss. The existing disposable firewall probe demonstrates synthetic port 53 underlay blocking only; it does not establish those properties.

### Experimental namespace resolver installation

`nord_tools_internal.nordvpn_resolver_install` can exclusively create a namespace-specific `/etc/netns/NAME/resolv.conf` from a validated `NamespaceResolverPolicy`. Linux `ip netns exec` uses this file as the resolver configuration for processes launched through that namespace mechanism. The installer refuses pre-existing directories, symlinked or writable resolver roots, and unexpected cleanup state. It does not modify the host's `/etc/resolv.conf` and is also used by the pinned restoration provisioning path; standalone installation does not itself establish packet confinement. Callers must own the namespace, ensure processes have stopped before cleanup, and distinguish the accepted namespace resolver visibility and real WireGuard DNS probes from the outstanding combined production-installed application DNS test. Filesystem races with untrusted privileged actors are outside this preliminary helper's guarantees.

### Disposable namespace resolver visibility probe

`python tools/probe_namespace_resolver.py` describes a read-only dry run. On a disposable, privileged Linux test system, `sudo python tools/probe_namespace_resolver.py --execute` creates a temporary network namespace and installs a validated resolver file under `/etc/netns/NAME/resolv.conf`, then verifies that `ip netns exec` sees those bytes rather than the host's resolver contents. It checks that the host resolver contents remain unchanged and attempts to remove only the resources it created. The probe requires an existing, trusted `/etc/netns` directory and refuses to replace pre-existing namespace resolver data. Inspect `sudo ip netns list` and `/etc/netns` if cleanup reports a warning. This does not test DNS traffic, resolver reachability, tunnel routing or real VPN leak prevention.

### Disposable DNS route-confinement probe

The synthetic DNS targets are deliberately outside the directly connected underlay subnets. In particular, the IPv6 target uses `fd42:5::53`, rather than the underlay `fd42:4::/64`, so kernel route selection actually exercises the simulated tunnel default route.

`python tools/probe_dns_route_confinement.py` is a no-change dry run. On a disposable Linux test system, `sudo python tools/probe_dns_route_confinement.py --execute` checks that IPv4 and IPv6 synthetic DNS destinations select the simulated tunnel while it is up and do not fall back to the underlay after the tunnel is brought down. The probe explicitly installs an IPv6 simulated-tunnel default route in addition to the shared harness IPv4 default route, and installs the existing namespace-local default-drop nftables policy, but this increment examines kernel routing decisions rather than proving packet delivery or resolver behaviour. The simulated tunnel is a dummy interface, not WireGuard. Successful checks cannot establish real DNS confinement, leak prevention, endpoint exceptions or production VPN safety. Inspect `sudo ip netns list` after execution to confirm cleanup.

### Disposable WireGuard endpoint exception probe

Run `python tools/probe_endpoint_exception.py` to inspect the dry-run description, then `sudo python tools/probe_endpoint_exception.py --execute` on a disposable-capable Linux test system. The probe installs a counter-instrumented form of the offline isolation policy inside temporary namespaces and checks that numeric IPv4/IPv6 UDP endpoint packets match the authorised exception while packets to an adjacent port match the underlay drop rule. Inspect `sudo ip netns list` after the run. No real WireGuard endpoint, DNS service or host firewall is exercised; this is not proof of production fail-closed behaviour.

The optional `python tools/probe_wireguard_host_integrity.py` dry run describes a privileged disposable two-pair WireGuard regression. Run `sudo python tools/probe_wireguard_host_integrity.py --execute` only on a suitable Linux test system with `ip`, `wg`, `nft` and `ping`. It compares read-only host IPv4/IPv6 routing, nftables rules and resolver contents before and after the experiment. Concurrent host-network changes can cause a conservative failure. This does not test real WireGuard DNS delivery or prove production fail-closed operation.

### Network confinement acceptance status

All four disposable network confinement development increments have passed privileged acceptance on Arch Linux. Namespace resolver visibility, synthetic dual-stack DNS route confinement, and counter-verified IPv4/IPv6 UDP endpoint exceptions passed their separate probes. The final disposable two-pair WireGuard host-integrity regression passed ten checks: both pairs exchanged packets, shutdown isolation worked independently, and read-only observations of host IPv4/IPv6 routes, nftables rules and resolver contents were unchanged. The final `ip netns list` output was empty. These tests do not establish actual DNS packet confinement through WireGuard, production fail-closed routing, crash-safe resource ownership, or safe recovery after interruption. Consult `TODO.md` for the remaining production blockers before treating this as an operational VPN manager.

Registered applications may explicitly select `"vpn": "direct"` in the policy. This launches the registered executable as the specified non-root identity using the **host** network namespace, routing table and resolver policy, without allocating a Nord Tools tunnel or consumer lease. It does not guarantee a physical-interface path or bypass an independently configured host VPN. An omitted `vpn` assignment still inherits the shared default VPN; failed VPN provisioning never changes a VPN-bound application into direct mode. `manage launch-consumer` shows `routing_mode` and `host_vpn_may_apply` in its preview. The direct launch deliberately uses a minimal child environment and does not promise desktop-session integration. The non-mutating preview and privileged host-namespace probe are `python tools/probe_application_routing_modes.py` and `sudo python tools/probe_application_routing_modes.py --run-privileged --uid UID --gid GID` respectively, using an existing non-root user and group. A privileged disposable real-WireGuard dual-stack DNS and concurrent direct-application confinement probe has passed; successful VPN-bound registered-application launch-to-packet and desktop DNS bypass acceptance remain outstanding.

Per-application routing has an offline planning foundation in `nord_tools_internal/nordvpn_application_plan.py`. It resolves registered executables, default-profile inheritance and logical shared or isolated allocation keys without launching processes or authorising namespace operations. A gated registered-application launch path is available through `manage launch-consumer`, but requires an already provisioned, independently verified allocation and a durable lease store. It is not a default-routing manager, and successful privileged VPN-bound launch-to-packet acceptance remains outstanding.

The internal application-binding planner models registered applications as logical references to shared or isolated allocations. Binding and unbinding are deterministic, side-effect-free operations: releasing the final reference does not remove a namespace, terminate a process or authorise deletion of a tunnel. Conflicting rebinding requires explicit release before replanning. The separate operational `manage launch-consumer` command now provides gated execution; this logical binding planner remains side-effect-free. The resource ownership underneath the references is established by the startup restoration and cleanup executors.

The application launch preparation implementation adds offline application launch request preparation in `nord_tools_internal/nordvpn_application_launch.py`. It requires an exact existing logical binding and produces an immutable argument vector without shell interpretation. The original offline execution entry point remains deliberately disabled. The separate privileged `manage launch-consumer` path uses a pre-exec gate, verifies the provisioned namespace and ownership evidence, reserves a durable lease before releasing the executable, and drops to an explicit non-root identity. Full production firewall/DNS packet confinement and privileged desktop compatibility acceptance remain outstanding.

The application session lifecycle implementation adds offline application session lifecycle modelling and a documented checklist for eventual namespace-aware launching, including desktop environment integration. These records are not process handles, and no application execution or privileged namespace operation is enabled.

The offline application audit completes the five-increment offline programme with a read-only consistency audit for logical application bindings and sessions. It detects orphaned or stale sessions and allocation keys shared across incompatible profiles, and produces deterministic allocation summaries. A successful audit is not evidence of running processes, namespace ownership or fail-closed networking. The separate privileged `manage launch-consumer` executor is implemented, but its registered VPN-bound launch-to-packet confinement and desktop integration remain outstanding as specified in `TODO.md`.

The reconciliation evidence gate adds `nord_tools_internal.nordvpn_reconciliation_gate` for deterministic offline assessment of reconciliation operations against explicitly supplied ownership and freshness observations. The gate never authorises live changes; independent privileged verification and crash-safe coordination remain required.

The recovery coordinator provides `nordvpn_recovery_coordinator.py`, an offline validator for ordered transaction checkpoints and interrupted/failed operation assessments. Checkpoint records are not kernel observations or creation-time ownership evidence; they cannot authorise resume, rollback, deletion or live networking changes.

The staged replacement planner adds `nord_tools_internal/nordvpn_replacement_stage.py`, an offline staged-replacement planner. It preserves existing logical assignments, identifies verification obligations and never authorises live cut-over or resource retirement. The separate production lifecycle executors provide ownership-verified generation replacement and bounded recovery; general in-place updates and disputed-resource repair remain outstanding.

### Offline drift assessment

`nord_tools_internal.nordvpn_drift_assessment.assess_drift` classifies supplied desired and observed logical snapshots into missing, unexpected, matching, allocation drift and configuration drift. Caller-supplied ownership statuses are untrusted. The resulting diagnostic cannot authorise privileged changes, deletion, rollback or repair. General in-place drift correction remains blocked pending a separately specified, ownership-verified repair authority. Generation replacement and bounded recovery are implemented; independently privileged hostile mutators are outside the release authority model.

The cross-contract audit adds `nord_tools_internal/nordvpn_reconciliation_audit.py`, a read-only cross-contract audit of reconciliation-gate and drift reports with optional recovery and replacement reports. It detects mismatched profile scopes, duplicate decisions and reports claiming mutation authority. A consistent audit is not permission to execute, resume, roll back or delete resources; privileged ownership and crash-safe operational integration remain outstanding.

The five-increment live reconciliation offline programme remains a non-authorising planning layer. Separate production executors now provide verified boot creation, generation replacement, confirmed cleanup and constrained interrupted-operation recovery. General live update/drift repair and combined production VPN-bound application and packet acceptance remains outstanding. See `TODO.md` for the remaining operational and acceptance requirements.

### Privileged authority preflight

`nord_tools_internal.nordvpn_authority_preflight.inspect_authority_directory` provides a read-only inspection of a dedicated privileged state directory and its path components. It rejects symlinks, writable ancestors, unexpected ownership, and unsafe state entries. The report is advisory and explicitly non-authorising: even a trusted directory cannot establish crash-persistent kernel ownership or permit mutation without independent live verification and operation-specific coordination. The cooperating-process privileged lifecycle acceptance matrix has passed; independently privileged hostile mutators are outside the supported release authority model. The final project-wide consistency audit remains outstanding.

### Privileged lifecycle authority boundary

The read-only authority-directory inspector now traverses path components using opened directory descriptors and refuses symlink traversal, writable ancestors, unsafe file modes and multiply linked state files. Its report is diagnostic, not an authorisation token: directory renames after inspection, independent kernel resource identity and operation-specific locking remain production blockers.

### privileged lifecycle authority lifecycle execution lock

Restoration, cleanup and recovery share a stable journal-specific execution lock. The lock is opened relative to the journal directory and checked for safe ownership, permissions and identity after acquisition. This prevents cooperating executors from interleaving their lifecycle operations; it does not authorise kernel mutations, make separate state stores atomic, or protect against a hostile actor with directory replacement privileges. The remaining authority and adversarial tests are tracked in TODO.md.

### kernel mutation authority namespace descriptor lifetime

The production cleanup adapter now releases its opened namespace descriptor on both successful retirement and ownership-verification refusal. This prevents a failed retirement from retaining a privileged reference to a namespace. It does not solve the pathname replacement race between verification and the kernel deletion command, or establish independent authority over host interfaces. Those issues remain blockers for completion of 8.1.4 and adversarial acceptance.

### kernel mutation authority additional namespace verification

Namespace ownership verification now rejects invalid bound names and non-regular held descriptors before any retirement command. These checks do not eliminate pathname replacement between verification and deletion; kernel mutation authority remains incomplete.

### kernel mutation authority host-interface mutation boundary

The cleanup executor checks the live host-interface name and index mapping before issuing a Linux rtnetlink `RTM_DELLINK` request by numeric interface index, requiring an explicit kernel acknowledgement. This avoids userspace name re-resolution at deletion, but does not close the race if a privileged adversary replaces and reuses the index before the kernel processes the request. Namespace retirement also remains pathname-based; neither mutation is claimed to be safe against a concurrent privileged adversary. A kernel-supported identity-bound deletion mechanism or a justified exclusive authority model is required before this mutation could be safe against concurrent privileged replacement.

### kernel mutation authority namespace-directory mutation precondition

Before retiring a namespace, the executor requires `/run/netns` to be a root-owned directory without group/other write permission, and checks its opened descriptor against the current pathname. An unsafe or unavailable directory refuses retirement. This check does not protect against a privileged mount replacement between inspection and `ip netns del`, and it is not a substitute for an exclusive authority model or an atomic kernel mutation mechanism. kernel mutation authority remains open.

### privileged lifecycle authority kernel namespace type attestation

The ownership verifier now queries the Linux namespace filesystem (`NS_GET_NSTYPE`) through the held descriptor and requires `CLONE_NEWNET`. A matching path, inode and regular-file mode cannot substitute for kernel confirmation that the descriptor actually identifies a network namespace. This attestation does not make `ip netns del NAME` an identity-bound operation: a concurrent process with mount authority can still replace the pathname after verification. Namespace retirement against such an adversary remains blocked pending an exclusive-authority design or an identity-bound kernel primitive.

### Kernel mutation authority limitation

Privileged lifecycle operations require an administratively controlled host authority domain: the shared execution lock serialises cooperating Nord Tools processes, and the lock directory must belong to the effective execution identity without group or other write access. The kernel does not provide an atomic ownership compare-and-delete operation for the namespace pathname or interface index used here. An independent privileged actor with mount or network administration capabilities can replace those resources between verification and deletion. This risk is not eliminated by the checks in kernel mutation authority. See `docs/PRIVILEGED-AUTHORITY-BOUNDARY.md` for the supported deployment boundary and outstanding adversarial acceptance.

### Startup restoration and privileged lifecycle acceptance

On 3 November 2026, the standalone startup restoration and cleanup matrix and the complete five-stage privileged lifecycle acceptance runner passed on the Arch Linux test host. The runner passed ownership preflight, startup restoration, confirmed cleanup, deterministic interrupted-operation recovery and a fresh integrated startup restoration and cleanup matrix. startup restoration and cleanup restored two pinned profiles, proved transient policy inert, interrupted recreation after durable intent but before kernel mutation, recovered both profiles, retired only the selected profile, verified repeat convergence, performed a final ownership-aware teardown and confirmed that host IPv4/IPv6 routes, nftables configuration and resolver contents were unchanged.

The final probes account for fixture effects without weakening the host checks. IPv4 comparison ignores only exact kernel-connected fixture routes on interfaces whose live indices match their creation-time bindings, including their expected removal during cleanup. Nftables comparison ignores packet and byte readings only. Namespace absence checks are scoped to the current fixture, so unrelated host namespaces are preserved. Failed probes retain their raw host snapshots and ownership stores; successful startup restoration and cleanup runs retire the surviving fixture before deleting those stores.

Recovery now evaluates the current non-retired profile generation, rather than mixing a recreated generation with retired history. The deterministic checkpoint proves recovery when interruption occurs after durable namespace creation intent and before the first kernel creation callback. It does not establish recovery after arbitrary partial kernel provisioning. Kernel mutation races involving independent privileged actors remain outside the documented cooperating-process authority model. Production-installed dual-stack confinement and separate real-tunnel DNS, routing, replacement and application lifecycle probes have passed, but failure injection on the installed profile, general in-place updates and registered VPN-bound launch-to-packet acceptance remain open in `TODO.md`.

### Live reconciliation and generation replacement

`manage apply-live --config PATH` remains create-only. Generation replacement is explicit: add a profile-to-path entry to the startup configuration's optional `handovers` object, initialise a version 2 runtime lease store, preview with `manage replace-profile`, and add `--execute` to provision, verify and activate B. `manage replacement-status` combines durable intent with fresh ownership and lease observations. `manage recover-generation --config PATH --profile PROFILE --runtime-consumers PATH` performs read-only generation recovery and drift classification; `--execute` permits verified prepared-record promotion, while `--execute --reprovision-absent` additionally authorises the production executor to restore an independently verified-absent, unselected replacement. Active-generation drift always fails closed and requires explicit review. `manage retire-generation --generation ID` previews exact old-generation retirement; `--execute` invokes verified cleanup only after its leases and reservations are gone.

Live replacement preparation can be inspected without network changes using `python nord_tools.py manage replacement-readiness --config /absolute/path/startup.json --profile PROFILE --runtime-consumers /absolute/path/leases.json`. Active A consumers are compatible with preparing and activating B, but remain explicit retirement blockers. After activation, new cooperating launches select B while already-running processes remain in A. A failed selected-generation verification refuses launch and never falls back to `direct` or the host namespace. Privileged end-to-end acceptance remains required before treating this path as deployment-certified.

## Generation replacement acceptance

The [generation replacement and recovery acceptance contract](docs/GENERATION-REPLACEMENT-ACCEPTANCE.md) documents the production A/B handover, conservative drift recovery, repeatability and fail-closed checks, disposable real-peer privileged test commands, and the remaining limits of interruption coverage.
