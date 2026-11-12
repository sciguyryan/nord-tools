# Provider workflow acceptance

One opt-in probe covers the complete provider-backed namespace workflow. It uses the production importer, selector, restoration executor, registered application gate and cleanup executor. The probe is deliberately excluded from ordinary CI and the unattended acceptance manager because it needs private operator material and contacts the live provider service.

## Preparing the guest and private inputs

Run the probe only inside a newly rebuilt acceptance guest. From the repository root on the host, create the guest and synchronise the reviewed source tree:

```bash
python scripts/acceptance-manager.py rebuild --force
python scripts/acceptance-manager.py test \
  --scenario quality \
  --force-complete-run
python scripts/acceptance-manager.py ssh
```

Obtain four distinct, current WireGuard configurations through the provider's supported account workflow. The four server identities must also exist in the provider's OpenVPN archive so that the benchmarker can rank them. This guide uses `gb123`, `gb124`, `nl123` and `de123` only as placeholders; replace every occurrence with the exact lowercase server ID belonging to the corresponding configuration.

Transfer the files into a private directory in the guest. Do not add them to the repository, terminal output or acceptance evidence. For the default SSH port, these host commands use the acceptance manager's dedicated key and host record. Replace the four source paths with their actual locations:

```bash
acceptance_cache="${XDG_CACHE_HOME:-$HOME/.cache}/nord-tools/acceptance"

ssh -F /dev/null -p 22222 \
  -o "UserKnownHostsFile=$acceptance_cache/known_hosts" \
  -o StrictHostKeyChecking=accept-new \
  -o IdentitiesOnly=yes \
  -i "$acceptance_cache/id_ed25519" \
  arch@127.0.0.1 \
  'install -d -m 0700 /home/arch/provider-input'

scp -F /dev/null -P 22222 \
  -o "UserKnownHostsFile=$acceptance_cache/known_hosts" \
  -o StrictHostKeyChecking=accept-new \
  -o IdentitiesOnly=yes \
  -i "$acceptance_cache/id_ed25519" \
  /private/source/gb123.conf \
  /private/source/gb124.conf \
  /private/source/nl123.conf \
  /private/source/de123.conf \
  arch@127.0.0.1:/home/arch/provider-input/
```

If `NORD_TOOLS_ACCEPTANCE_SSH_PORT` was set when the guest was provisioned, use that port instead. In the guest, install each file as a root-owned private regular file:

```bash
sudo install -d -m 0700 -o root -g root /root/provider
sudo install -m 0600 -o root -g root \
  /home/arch/provider-input/gb123.conf \
  /home/arch/provider-input/gb124.conf \
  /home/arch/provider-input/nl123.conf \
  /home/arch/provider-input/de123.conf \
  /root/provider/

rm /home/arch/provider-input/gb123.conf \
  /home/arch/provider-input/gb124.conf \
  /home/arch/provider-input/nl123.conf \
  /home/arch/provider-input/de123.conf
rmdir /home/arch/provider-input
```

Generate the benchmark report in the guest immediately before the probe. All four imported identities should appear as responsive entries in the report; the probe needs two unreserved responsive identities for its isolated allocations:

```bash
python nord_tools.py benchmark \
  --download \
  --protocol udp \
  --filter='server:gb123|server:gb124|server:nl123|server:de123' \
  --top 4 \
  --report /home/arch/benchmark-report.json

jq -r '.ranking[] | select(.received > 0) | .server' \
  /home/arch/benchmark-report.json

sudo install -m 0600 -o root -g root \
  /home/arch/benchmark-report.json \
  /root/provider/benchmark-report.json
```

If any of the four identities is absent or has no received probes, replace that configuration or investigate guest connectivity before continuing. Do not substitute an old report; fastest selection rejects reports older than the configured maximum age.

## Running and recording the probe

First confirm the opt-in boundary. This command reads no configuration and changes no networking:

```bash
python tools/probe_provider_workflows.py
```

Then run the privileged probe. The target UID and GID must identify the existing non-root `arch` account:

```bash
sudo python tools/probe_provider_workflows.py --run-privileged \
  --uid "$(id -u arch)" --gid "$(id -g arch)" \
  --benchmark-report /root/provider/benchmark-report.json \
  --provider-config gb123=/root/provider/gb123.conf \
  --provider-config gb124=/root/provider/gb124.conf \
  --provider-config nl123=/root/provider/nl123.conf \
  --provider-config de123=/root/provider/de123.conf
```

A successful run ends with `PASS: E2 provider workflow acceptance` and returns zero. Record the complete non-secret console output, release commit identifier, version, guest image date and package evidence listed in the supported-platform document. Do not record configuration contents, private keys or the retained root-only diagnostic directory.

Copy the acceptance record out, then destroy or forcibly rebuild the guest. The files under `/root/provider` remain credential-bearing even though the probe removes the derived temporary credentials. Do not reuse this guest as a clean acceptance baseline.

The current accepted fixture requires IPv4 provider endpoints. Tunnel payload addressing and routes retain the configuration's validated address families. The probe briefly enables IPv4 forwarding and installs a dedicated, collision-checked masquerade table for its `10.216.0.0/16` disposable underlays. It restores the previous forwarding value and removes the table before comparing host routes, nftables configuration and resolver contents with their baseline.

The benchmark report must be a fresh version 1 report produced by the benchmark command, and it must contain enough responsive imported servers for the two isolated allocations. The policy contains a pinned default profile, a country-selected named shared profile and a fastest-selected isolated profile used by two applications. Restoration must reserve four distinct imported provider identities. Pinned selection is allocated first, then country and fastest candidates in deterministic order. If the catalogue cannot provide a distinct eligible identity for every concurrent allocation, restoration stops before creating networking.

Acceptance requires all four production namespaces to establish a WireGuard handshake and resolve an IPv4 hostname through their namespace resolver. The registered launch gate then runs the default, shared and both isolated applications as the requested non-root identity, confirms their verified allocation leases and removes those leases after exit. A repeated restoration must be converged and mutation-free. Final cleanup must remove all sixteen owned resources and namespace resolver files before host integrity is compared.

Private configuration contents and derived keys are never printed. Derived credentials are removed after normal completion and handled failures. If safe cleanup or host restoration fails, the probe retains only the secret-free catalogue, lifecycle, ownership and intent records for diagnosis and returns a failure. A forcibly killed probe may leave its root-only temporary directory, which the operator must inspect and remove inside the disposable guest.

This probe supplies the remaining integrated provider evidence when it passes on the release tree. A dry run proves only that the command is opt-in; static unit tests do not establish provider reachability.
