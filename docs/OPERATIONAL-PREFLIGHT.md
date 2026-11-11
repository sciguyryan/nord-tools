# Operational preflight

Production network mutation is admitted only for two operating modes:

- `namespace` covers owned namespace provisioning, cleanup and recovery;
- `host-default` adds the accepted static IPv4 `systemd-networkd` and
  `systemd-resolved` host-protection profile.

Run the read-only preflight as the same root identity that will run the
executor:

```bash
sudo python nord_tools.py manage operational-preflight --mode namespace
sudo python nord_tools.py manage operational-preflight \
  --mode host-default \
  --host-plan /etc/nord-tools/host-protection.json
```

The command never creates lifecycle stores or changes networking. A successful
report still sets `mutation_authorised` to `false`: it records a current
observation, not authority that can be reused later.

## Common checks

Both modes require Linux root, Python 3.10 or newer and the exact accepted
network platform contract. The platform check verifies the admitted Arch kernel
series and versions of iproute2, nftables and WireGuard tools. It also checks
the live JSON and field output consumed by the executors and the ownership and
permissions of `/etc/netns`. A missing command, timeout, malformed response,
unexpected version or unsafe resolver root causes refusal.

The `host-default` mode additionally validates the supplied host protection
plan against fresh inventory. The physical egress identity must match, the
underlay must be the accepted static `systemd-networkd` arrangement,
`systemd-resolved` must be active and no recognised competing manager, firewall
or tunnel may be present.

## Execution boundary

Real restoration, cleanup and recovery run the namespace preflight before they
open or create lifecycle state for an executing operation. Host barrier entry
and a new activation lifecycle run the full host-default admission check. An
activation retry with an already observed deny barrier, deactivation and
recovery may run while ordinary egress is blocked. They repeat the root, runtime
and command checks without rerunning the broad platform probe; their locked
inventory and resource readback revalidate the facts needed for each mutation.
Injected test kernels do not invoke live checks.

These checks deliberately fail closed. If the kernel or a network-tool package
changes while owned resources are active, automated retirement is refused until
that environment has been accepted or the operator follows a separately
reviewed manual recovery procedure. A higher package version is not accepted by
assumption.

Preflight cannot prove that another privileged process will continue to
cooperate. Every executor retains its operation-specific ownership, identity,
readback and locking checks, within the authority boundary described in
[Privileged authority boundary](PRIVILEGED-AUTHORITY-BOUNDARY.md).
