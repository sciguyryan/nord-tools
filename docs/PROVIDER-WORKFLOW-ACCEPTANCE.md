# Provider workflow acceptance

E2 has one opt-in probe for the complete provider-backed namespace workflow. It uses the production importer, selector, restoration executor, registered application gate and cleanup executor. The probe is deliberately excluded from ordinary CI and the unattended acceptance manager because it needs private operator material and contacts the live provider service.

Run it only inside the supported disposable guest. Supply four distinct, current WireGuard configurations obtained through the provider's supported account workflow. Each source file must be a private regular file owned by root. The target UID and GID must identify an existing non-root guest account:

```bash
sudo python tools/probe_provider_workflows.py --run-privileged \
  --uid 1000 --gid 1000 \
  --benchmark-report /root/provider/benchmark-report.json \
  --provider-config gb123=/root/provider/gb123.conf \
  --provider-config gb124=/root/provider/gb124.conf \
  --provider-config nl123=/root/provider/nl123.conf \
  --provider-config de123=/root/provider/de123.conf
```

The current accepted fixture requires IPv4 provider endpoints. Tunnel payload addressing and routes retain the configuration's validated address families. The probe briefly enables IPv4 forwarding and installs a dedicated, collision-checked masquerade table for its `10.216.0.0/16` disposable underlays. It restores the previous forwarding value and removes the table before comparing host routes, nftables configuration and resolver contents with their baseline.

The benchmark report must be a fresh version 1 report produced by the benchmark command, and it must contain enough responsive imported servers for the two isolated allocations. The policy contains a pinned default profile, a country-selected named shared profile and a fastest-selected isolated profile used by two applications. Restoration must reserve four distinct imported provider identities. Pinned selection is allocated first, then country and fastest candidates in deterministic order. If the catalogue cannot provide a distinct eligible identity for every concurrent allocation, restoration stops before creating networking.

Acceptance requires all four production namespaces to establish a WireGuard handshake and resolve an IPv4 hostname through their namespace resolver. The registered launch gate then runs the default, shared and both isolated applications as the requested non-root identity, confirms their verified allocation leases and removes those leases after exit. A repeated restoration must be converged and mutation-free. Final cleanup must remove all sixteen owned resources and namespace resolver files before host integrity is compared.

Private configuration contents and derived keys are never printed. Derived credentials are removed after normal completion and handled failures. If safe cleanup or host restoration fails, the probe retains only the secret-free catalogue, lifecycle, ownership and intent records for diagnosis and returns a failure. A forcibly killed probe may leave its root-only temporary directory, which the operator must inspect and remove inside the disposable guest.

This probe supplies the missing integrated E1 and E2 guest evidence when it passes on the exact candidate tree. A dry run proves only that the command is opt-in; static unit tests do not establish provider reachability.
