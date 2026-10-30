# Nord Tools

Nord Tools is a collection of Linux-focused utilities for benchmarking NordVPN servers and exploring policy-driven VPN routing. The working benchmarker discovers and ranks NordVPN endpoints; the newer policy tools validate a default VPN profile, describe application-specific overrides and inspect proposed routing domains. **Multi-tunnel routing and automatic default-server switching are not implemented yet.**

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

The `policy` and `topology` commands are offline only. The namespace probe is experimental: its default invocation is a dry run, and `--execute` performs privileged network changes. The entry point does not provide a live per-application VPN manager or safe default-tunnel switching yet.

## What works today

The benchmarker reads local OpenVPN `.ovpn` files or downloads NordVPN's official configuration archive, probes endpoints concurrently and ranks them by packet loss, latency and stability. These are endpoint measurements, not throughput measurements through an established VPN tunnel. ICMP-unresponsive servers are not necessarily offline.

The existing `--auto-connect` option can request a connection through the installed NordVPN Linux CLI after benchmarking. It manages that client's single connection, **not** independent per-application tunnels. See [Connecting to a ranked server on Linux](#connecting-to-a-ranked-server-on-linux).

### Experimental resource lifecycle journal

Part 2 introduces a strict offline lifecycle journal for future Nord Tools-owned resources. It validates allocation-bound event histories, rejects illegal state transitions and detects mismatched simulated identities. A matching identifier is **not** independent kernel ownership evidence. No lifecycle command creates, modifies or removes networking resources.

```bash
python nord_tools.py manage lifecycle --journal path/to/lifecycle.json
python nord_tools.py manage lifecycle --journal path/to/lifecycle.json --observed path/to/simulated-observations.json
```

The internal lifecycle modules provide permission-restricted atomic journal persistence and advisory locking for cooperating writers. They reject invalid histories and unsafe journal paths, but do not establish kernel ownership or defend against hostile writers with directory access. See the [routing design](docs/VPN-ROUTING-DESIGN.md) for the safety boundary.

## Tunnel management implementation status

The offline management foundation is complete, but **the operational tunnel manager is not implemented or ready for production use**. The following work remains before Nord Tools can safely manage multiple live VPN connections:

| Area | Current state | Required before live use |
| --- | --- | --- |
| Tunnel provisioning | Experimental disposable WireGuard configuration, connectivity and journal-gated execution have been implemented and tested in controlled probes | Implement production-authorised provisioning, crash-safe ownership, provider credentials and endpoint selection |
| Network isolation | Disposable simulated firewall probe | Validate fail-closed IPv4/IPv6 routing, DNS confinement and underlay exceptions using real tunnels |
| Ownership and reconciliation | Allocation ledgers, read-only discovery and offline plans | Bind allocations to independently verifiable resources, detect drift and apply changes transactionally |
| Replacement and recovery | Non-executable transaction stages | Implement protected cut-over, rollback, crash recovery and durable operation journals |
| Startup and persistence | Persistent desired policy by default | Install and test systemd restoration, including safe startup ordering and transient-policy exclusion |
| Cleanup | Simulated cleanup preview | Remove only verified Nord Tools-owned resources and restore prior host state safely |
| Integration and acceptance | Automated offline tests | Privileged Linux integration tests, failure injection and checks for compatibility with the official NordVPN client |

`manage graph` depicts **configured intent**, not live connectivity. Likewise, `manage cleanup-plan` and `manage transaction-plan` are advisory; they do not execute network changes. These boundaries apply even if a saved policy is persistent.

## VPN routing work in progress

The intended manager will route ordinary traffic through a default VPN country or server, while explicitly assigned applications can use other VPN profiles. Default-server optimisation will eventually select a better eligible endpoint without reconnecting or reselecting independent application overrides. Applications sharing the default profile will still be affected by default changes.

The current implementation is limited to offline policy validation, advisory default-server selection and topology inspection. It does **not** establish VPN tunnels, modify routes or DNS, or enforce a kill switch.

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

The experimental `manage` command validates and stores **desired routing intent only**. It does not create tunnels, change host networking, install systemd units or restore a VPN on boot. Its default scope is persistent and stores the policy under `XDG_CONFIG_HOME/nord-tools/` (or `~/.config/nord-tools/`) for future startup integration. Pass `--transient` to use session-only storage under `XDG_RUNTIME_DIR` instead. Persisting a policy does **not** currently activate automatic restoration.

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

`plan` previews whether intent would be created, replaced or left unchanged; `configure` stores it atomically. `clear` removes only the saved intent for the selected scope, **not** networking resources. Transient and persistent settings are independent. The transient scope requires a valid session runtime directory and does not silently fall back to durable storage. A future manager will reconcile these policies against resources it owns, enforce fail-closed routing and restore persistent profiles at boot. No such guarantees are claimed for this offline stage.

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

The check reports the platform and Python version, and whether `ping`, `nordvpn`, `ip`, `nft`, `wg` and `systemctl` are available. Only the platform and Python version are universal requirements. Other executables are feature-specific: `ping` is needed for ICMP benchmarks, `nordvpn` for CLI connection support, and `ip`/`nft` for the privileged namespace experiment. WireGuard and systemd checks describe planned capabilities, not functionality already implemented. `--strict` fails if any listed tool is missing. This is a local executable-availability check, not a guarantee of kernel support, privileges, VPN credentials or working network connectivity.

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

The proposed default-VPN and per-application routing architecture is documented in [docs/VPN-ROUTING-DESIGN.md](docs/VPN-ROUTING-DESIGN.md). An offline default-optimisation preview is available through `nordvpn_policy.py`; it reads an existing versioned benchmark report and **does not** connect, disconnect or modify networking. Independent application tunnels and automatic switching are not implemented yet.

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

`python nord_tools.py manage identities --registry examples/managed-allocations.json` validates a version 2 allocation ledger containing a random, per-resource `allocation_id`. Allocation identities are distinct from interface and namespace names, which can be reused. This command is read-only and does not establish that a kernel resource belongs to Nord Tools. A future provisioner must bind allocation identifiers to independently verifiable kernel or service evidence before authorising any update, replacement or cleanup.

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

The output identifies missing names, ambiguous interface scopes and possible lifecycle drift. A name match, allocation token or journal entry does **not** establish kernel resource ownership. The command cannot authorise modification or deletion. Durable ownership proof and operational recovery remain future work; cooperating journal writers already use advisory locking. Use `--observed` instead for an explicitly simulated fixture; the two options cannot be combined.

### Ownership and recovery diagnostics

Internal fingerprint, lifecycle, recovery and operation-intent modules support read-only assessment of resource drift and interrupted work. They do not prove kernel ownership or execute recovery. The experimental disposable namespace primitive retains a process-bound descriptor for identity checks, but is not a production cleanup mechanism. The privileged smoke probe (`sudo python tools/probe_namespace_ownership.py --run-privileged`) passed on Arch Linux with no named namespaces left behind. See the [routing design](docs/VPN-ROUTING-DESIGN.md#process-bound-disposable-namespace-ownership-experiment) for limitations and safe test instructions.

## Internal package organisation

The supported entry point remains `python nord_tools.py`. Lifecycle, identity, discovery, reconciliation and ownership implementation modules now reside in `nord_tools_internal/`; they are not standalone user commands. Development and privileged acceptance probes remain in `tools/`. Existing command-line options and the privileged namespace smoke probe retain their entry points.

Part 2 establishes offline lifecycle and operation-intent records, read-only Linux evidence correlation, inter-process journal locking and process-bound disposable namespace identity checks. The privileged normal-operation namespace smoke test passed on Arch Linux, including confirmation that no named namespaces remained. This does not prove crash-persistent ownership, safe deletion under concurrent name replacement, or automatic recovery. These are explicit prerequisites for any later privileged manager operation that would rely on them.

## WireGuard provisioning development

Part 3 has delivered experimental disposable WireGuard configuration, peer verification and journal-gated execution, alongside a validated offline specification and descriptor-based credential input. The isolated probes can create and configure real WireGuard interfaces, but no production-authorised provider tunnel manager, crash-safe ownership, automated recovery or fail-closed routing is available. See `docs/VPN-ROUTING-DESIGN.md` and `TODO.md` for the remaining acceptance boundaries.

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

## Part 4: Experimental namespace isolation policy

The internal `NamespaceIsolationPolicy` renders a proposed namespace-local nftables `inet` table with default-drop input, output and forwarding, loopback allowance, established inbound replies, tunnel-bound output and one narrowly scoped UDP underlay endpoint exception. It does not install the rules, modify host firewall state or configure DNS. Production leak protection requires atomic installation before traffic is possible, routing and resolver confinement, verified ownership, and privileged failure-injection acceptance.

## Experimental namespace firewall installation (Part 4)

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

`nord_tools_internal.nordvpn_resolver_install` can exclusively create a namespace-specific `/etc/netns/NAME/resolv.conf` from a validated `NamespaceResolverPolicy`. Linux `ip netns exec` uses this file as the resolver configuration for processes launched through that namespace mechanism. The installer refuses pre-existing directories, symlinked or writable resolver roots, and unexpected cleanup state. It does not modify the host's `/etc/resolv.conf` and is not yet integrated into the privileged VPN lifecycle. Callers must own the namespace, ensure processes have stopped before cleanup, and treat the installation as unverified until namespace execution, route confinement and resolver behaviour are independently tested. Filesystem races with untrusted privileged actors are outside this preliminary helper's guarantees.

### Disposable namespace resolver visibility probe

`python tools/probe_namespace_resolver.py` describes a read-only dry run. On a disposable, privileged Linux test system, `sudo python tools/probe_namespace_resolver.py --execute` creates a temporary network namespace and installs a validated resolver file under `/etc/netns/NAME/resolv.conf`, then verifies that `ip netns exec` sees those bytes rather than the host's resolver contents. It checks that the host resolver contents remain unchanged and attempts to remove only the resources it created. The probe requires an existing, trusted `/etc/netns` directory and refuses to replace pre-existing namespace resolver data. Inspect `sudo ip netns list` and `/etc/netns` if cleanup reports a warning. This does not test DNS traffic, resolver reachability, tunnel routing or real VPN leak prevention.

### Disposable DNS route-confinement probe

The synthetic DNS targets are deliberately outside the directly connected underlay subnets. In particular, the IPv6 target uses `fd42:5::53`, rather than the underlay `fd42:4::/64`, so kernel route selection actually exercises the simulated tunnel default route.

`python tools/probe_dns_route_confinement.py` is a no-change dry run. On a disposable Linux test system, `sudo python tools/probe_dns_route_confinement.py --execute` checks that IPv4 and IPv6 synthetic DNS destinations select the simulated tunnel while it is up and do not fall back to the underlay after the tunnel is brought down. The probe explicitly installs an IPv6 simulated-tunnel default route in addition to the shared harness IPv4 default route, and installs the existing namespace-local default-drop nftables policy, but this increment examines kernel routing decisions rather than proving packet delivery or resolver behaviour. The simulated tunnel is a dummy interface, not WireGuard. Successful checks cannot establish real DNS confinement, leak prevention, endpoint exceptions or production VPN safety. Inspect `sudo ip netns list` after execution to confirm cleanup.

### Disposable WireGuard endpoint exception probe

Run `python tools/probe_endpoint_exception.py` to inspect the dry-run description, then `sudo python tools/probe_endpoint_exception.py --execute` on a disposable-capable Linux test system. The probe installs a counter-instrumented form of the offline isolation policy inside temporary namespaces and checks that numeric IPv4/IPv6 UDP endpoint packets match the authorised exception while packets to an adjacent port match the underlay drop rule. Inspect `sudo ip netns list` after the run. No real WireGuard endpoint, DNS service or host firewall is exercised; this is not proof of production fail-closed behaviour.

The optional `python tools/probe_wireguard_host_integrity.py` dry run describes a privileged disposable two-pair WireGuard regression. Run `sudo python tools/probe_wireguard_host_integrity.py --execute` only on a suitable Linux test system with `ip`, `wg`, `nft` and `ping`. It compares read-only host IPv4/IPv6 routing, nftables rules and resolver contents before and after the experiment. Concurrent host-network changes can cause a conservative failure. This does not test real WireGuard DNS delivery or prove production fail-closed operation.

### Part 4 experimental acceptance status

All four disposable Part 4 development increments have passed privileged acceptance on Arch Linux. Namespace resolver visibility, synthetic dual-stack DNS route confinement, and counter-verified IPv4/IPv6 UDP endpoint exceptions passed their separate probes. The final disposable two-pair WireGuard host-integrity regression passed ten checks: both pairs exchanged packets, shutdown isolation worked independently, and read-only observations of host IPv4/IPv6 routes, nftables rules and resolver contents were unchanged. The final `ip netns list` output was empty. These tests do not establish actual DNS packet confinement through WireGuard, production fail-closed routing, crash-safe resource ownership, or safe recovery after interruption. Consult `TODO.md` for the remaining production blockers before treating this as an operational VPN manager.
