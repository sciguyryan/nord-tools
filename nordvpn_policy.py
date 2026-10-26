"""Offline default-endpoint planning. This module never changes VPN state."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from types import SimpleNamespace

from nordvpn_connection import normalise_server_identity
from nordvpn_filter import compile_filter
from nordvpn_profiles import ProfileError, validate_policy


class PolicyError(ValueError):
    """The policy or benchmark report cannot support a safe decision."""


def _object(value, label):
    if not isinstance(value, dict):
        raise PolicyError(f"{label} must be an object")
    return value


def _number(value, label):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise PolicyError(f"{label} must be a finite non-negative number")
    return float(value)


def plan_default(policy: dict, report: dict, *, current_server: str | None = None) -> dict:
    """Select a measured default candidate, leaving application assignments untouched.

    The result is advice only. Neither tunnel establishment nor safe switching
    can be inferred from ICMP/TCP probe measurements.
    """
    try:
        policy = validate_policy(policy)
    except ProfileError as exc:
        raise PolicyError(str(exc)) from exc
    report = _object(report, "report")
    if report.get("schema_version") != 1 or not isinstance(report.get("ranking"), list):
        raise PolicyError("expected a version 1 benchmark report with a ranking")
    defaults = _object(policy.get("defaults"), "defaults")
    profiles = _object(policy.get("vpn_profiles"), "vpn_profiles")
    profile_name = defaults.get("vpn")
    if not isinstance(profile_name, str) or profile_name not in profiles:
        raise PolicyError("defaults.vpn must name a configured profile")
    profile = _object(profiles[profile_name], "default profile")
    selection = _object(profile.get("selection"), "default selection")
    if selection.get("mode") != "fastest":
        raise PolicyError("default selection must use fastest mode")
    expression = selection.get("filter")
    if not isinstance(expression, str) or not expression.strip():
        raise PolicyError("default selection requires a non-empty filter")
    # Reuse the benchmarker's own grammar, not a second interpretation.
    try:
        predicate = compile_filter(expression)
    except ValueError as exc:
        raise PolicyError(str(exc)) from exc
    minimum_ms = _number(selection.get("minimum_improvement_ms", 0), "minimum_improvement_ms")
    minimum_percent = _number(selection.get("minimum_improvement_percent", 0), "minimum_improvement_percent")
    if minimum_percent > 100:
        raise PolicyError("minimum_improvement_percent cannot exceed 100")
    if current_server is not None:
        current_server = normalise_server_identity(current_server)
        if current_server is None:
            raise PolicyError("current server must be a canonical NordVPN identity")

    eligible = []
    for record in report["ranking"]:
        record = _object(record, "ranking entry")
        server = record.get("server")
        if not isinstance(server, str) or normalise_server_identity(server) != server.lower():
            raise PolicyError("ranking contains an invalid server identity")
        if record.get("protocol") not in ("udp", "tcp"):
            raise PolicyError("ranking contains an invalid protocol")
        port = record.get("port")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise PolicyError("ranking contains an invalid port")
        endpoint = SimpleNamespace(name=server, protocol=record["protocol"], port=port)
        if not predicate(endpoint):
            continue
        if not record.get("received") or record.get("median_ms") is None:
            continue
        latency = _number(record["median_ms"], "median_ms")
        loss = _number(record.get("loss_pct"), "loss_pct")
        if loss > 100:
            raise PolicyError("loss_pct cannot exceed 100")
        eligible.append((loss, latency, server, record["protocol"], port))
    eligible.sort()
    candidate = eligible[0] if eligible else None
    current = next((item for item in eligible if item[2] == current_server), None)
    decision = "no_eligible_server"
    if candidate:
        if current_server is None:
            decision = "candidate_only_current_unknown"
        elif candidate[2] == current_server:
            decision = "keep_current"
        elif current is None:
            decision = "current_not_measured"
        else:
            improvement = current[1] - candidate[1]
            percent = 100 * improvement / current[1] if current[1] else 0
            decision = (
                "switch_candidate"
                if improvement >= minimum_ms and percent >= minimum_percent and improvement > 0
                else "keep_current"
            )
    return {
        "profile": profile_name,
        "decision": decision,
        "candidate": candidate[2] if candidate else None,
        "current_server": current_server,
        "eligible_measurements": len(eligible),
        "application_overrides_untouched": True,
        "executed": False,
        "warning": "Probe latency is not VPN throughput; no tunnel or routing change has been made.",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Preview default VPN optimisation from an existing benchmark report")
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--validate", action="store_true", help="Validate the policy without a benchmark report")
    parser.add_argument("--current-server")
    args = parser.parse_args(argv)
    try:
        policy = json.loads(args.policy.read_text(encoding="utf-8"))
        if args.validate:
            result = {"valid": True, "policy": validate_policy(policy), "executed": False}
        else:
            if args.report is None:
                parser.error("--report is required unless --validate is used")
            report = json.loads(args.report.read_text(encoding="utf-8"))
            result = plan_default(policy, report, current_server=args.current_server)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
