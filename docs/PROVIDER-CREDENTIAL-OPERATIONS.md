# Provider credential operations

Nord Tools imports an official NordVPN WireGuard configuration supplied by the operator. It does not scrape an undocumented provider API, log in to an account, or guess a WireGuard endpoint from the OpenVPN catalogue. Obtain the configuration through NordVPN's supported account workflow and keep the downloaded file private.

Preview an import first:

```bash
python nordvpn_manage.py provider-import \
  --configuration /secure/downloads/gb123.conf \
  --server gb123.nordvpn.com \
  --catalogue /etc/nord-tools/provider-catalogue.json \
  --credential /etc/nord-tools/provider/gb123.key
```

Add `--execute` to write the catalogue and private key. Existing material is never replaced implicitly; rotation additionally requires `--rotate`. The source, destination directories and existing destination files must be private, caller-owned, non-symlinked filesystem objects. The source configuration is bounded and must contain exactly one WireGuard interface and peer. Active directives such as `PostUp` are refused. Keys, numeric addresses, dual-stack default routes, DNS addresses and the endpoint are validated before writing.

The catalogue contains only public connection data, the expected client public identity and the credential path. The private key is written separately with mode `0600`, is passed to `wg pubkey` over standard input, and never appears in command arguments or the import report. Catalogue publication precedes key replacement during rotation. An interruption between those writes leaves an identity mismatch which boot restoration refuses before network mutation.

## Startup selection

A provider-backed startup configuration adds:

```json
{
  "provider": {
    "catalogue": "/etc/nord-tools/provider-catalogue.json",
    "benchmark_report": "/var/lib/nord-tools/benchmark-report.json",
    "max_report_age_seconds": 86400
  },
  "tunnels": {
    "primary": {
      "underlay": {
        "namespace_address": "10.214.0.2/30",
        "host_address": "10.214.0.1/30"
      }
    }
  }
}
```

Pinned selection requires that exact imported server. Country selection chooses the lexically first imported server in the requested country, making repeated boots deterministic. Fastest selection uses only responsive, imported servers matching the saved policy filter in a version 1 benchmark report. It orders candidates by packet loss, median latency and server identity. A missing, future-dated, stale or malformed report is refused; no fallback server is guessed.

The generated systemd unit loads every imported private key with `LoadCredential`. At runtime restoration reads the matching file from `$CREDENTIALS_DIRECTORY`, not the original source path. Before creating a namespace or recording a creation attempt, it derives the loaded key's public identity and compares it with the catalogue. Missing catalogue entries, unresolved preferences, unsafe data and identity mismatches fail the boot service closed. The report records only the selected server and catalogue digest.

The catalogue and benchmark report are local operator inputs, not proof that a provider server is currently reachable. E2 owns live default, shared and isolated provider workflow acceptance.
