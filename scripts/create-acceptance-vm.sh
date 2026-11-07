#!/usr/bin/env bash
# Compatibility entry point for the Python acceptance manager.
# The manager uses passt userspace networking, so provisioning does not attach a
# host bridge or add host firewall, forwarding, NAT, DNS, or routing rules.
set -Eeuo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec python3 "${script_dir}/acceptance-manager.py" provision
