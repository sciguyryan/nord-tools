#!/usr/bin/env python3
"""Benchmark NordVPN endpoints using ICMP or TCP connection timing."""

from __future__ import annotations

import argparse
from nordvpn_report import build_report, timestamp, write_report
import concurrent.futures as futures
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import random
import re
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from urllib.request import urlopen
import zipfile

from nordvpn_filter import compile_filter, FilterSyntaxError, server_identity
from nordvpn_regions import country_flag, country_name, load_region_lists

ARCHIVE_URL = "https://downloads.nordcdn.com/configs/archives/servers/ovpn.zip"
PRESETS = {"fast": (2, 6), "balanced": (3, 12), "thorough": (5, 25)}
MAX_ARCHIVE_BYTES = 150 * 1024 * 1024
MAX_EXTRACTED_BYTES = 1024 * 1024 * 1024
MAX_FILES = 50000
MAX_PROFILE_BYTES = 2 * 1024 * 1024
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")
# Fixed latency anchors avoid making a uniformly slow server fleet appear green.
LATENCY_ANCHORS = (0.0, 20.0, 40.0, 65.0, 100.0, 150.0, 250.0)
DEFAULT_PALETTE = ("#20b65a", "#59c54a", "#a0c83b", "#d4bb38", "#e89b35", "#e46a34", "#d63b38")
COLOURBLIND_PALETTE = ("#0072b2", "#268cb9", "#56b4e9", "#a5b5ba", "#e6a25a", "#d98238", "#d55e00")
PING_TIME = re.compile(r"\btime\s*[=<]\s*(\d+(?:[.,]\d+)?)\s*ms\b", re.I)


@dataclass(frozen=True)
class Endpoint:
    file: str
    host: str
    port: int
    protocol: str
    name: str


@dataclass
class Measurement:
    address: str
    attempted: int = 0
    samples: list[float] = field(default_factory=list)
    stage: str = "survey"
    error: str = ""
    method: str = "icmp"

    @property
    def mean(self):
        return statistics.mean(self.samples) if self.samples else None

    @property
    def median(self):
        return statistics.median(self.samples) if self.samples else None

    @property
    def jitter(self):
        return statistics.median(abs(x - self.median) for x in self.samples) if self.samples else None

    @property
    def loss(self):
        return (self.attempted - len(self.samples)) / self.attempted * 100 if self.attempted else 100.0


def parse_profile(path: Path) -> list[Endpoint]:
    """Read only OpenVPN directives; embedded certificate/key bodies are ignored."""
    proto = "udp"
    remotes = []
    in_block = False
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if line.startswith("<") and not line.startswith("</"):
            in_block = True
            continue
        if line.startswith("</"):
            in_block = False
            continue
        if in_block or not line or line.startswith(("#", ";")):
            continue
        parts = line.split()
        if parts[0] == "proto" and len(parts) > 1:
            proto = parts[1].lower()
        if parts[0] == "remote" and len(parts) >= 2:
            port = int(parts[2]) if len(parts) > 2 else 1194
            if not 1 <= port <= 65535:
                raise ValueError("invalid remote port")
            remotes.append((parts[1], port, parts[3].lower() if len(parts) > 3 else None))
    result = []
    for host, port, override in remotes:
        transport = override or proto
        if transport.startswith("udp"):
            transport = "udp"
        elif transport.startswith("tcp"):
            transport = "tcp"
        else:
            raise ValueError(f"unsupported transport: {transport}")
        result.append(Endpoint(str(path), host, port, transport, server_identity(path.name)))
    if not result:
        raise ValueError("no remote directive")
    return result


# Only infer a country from filenames following NordVPN's documented naming
# convention. Unknown names must be parsed rather than silently excluded.
PROFILE_COUNTRY = re.compile(
    r"(?:\d+-)?([a-z]{2})\d+\.nordvpn\.com\.(?:udp|tcp)(?:_\d+(?:\.\d+)*)?\.ovpn",
    re.I,
)


def profile_country(path: str) -> str | None:
    from nordvpn_regions import normalise_country_code

    match = PROFILE_COUNTRY.fullmatch(Path(path).name)
    return normalise_country_code(match.group(1).lower()) if match else None


def country_prefilter(expressions, region_lists):
    """Return a conservative filename check for country-only restrictions.

    Each CLI filter is ANDed. Expressions involving other fields are left for
    full profile evaluation, including when mixed with country expressions.
    """
    country_only = []
    for expression in expressions:
        atoms = re.findall(r"[^\s!&|()]+", expression)
        if atoms and all(
            re.fullmatch(r"(?:country:)?[a-z]{2}", atom, re.I) or re.fullmatch(r"list:[a-z][a-z0-9_-]*", atom, re.I)
            for atom in atoms
        ):
            country_only.append(compile_filter(expression, region_lists))

    def eligible(path):
        code = profile_country(str(path))
        if code is None or not country_only:
            return True
        # A synthetic endpoint is safe here because selected predicates depend
        # exclusively on its country identifier, not on profile contents.
        from nordvpn_regions import COUNTRY_ALIASES

        archive_code = next((alias for alias, canonical in COUNTRY_ALIASES.items() if canonical == code), code)
        endpoint = Endpoint(str(path), "", 0, "", f"{archive_code}1.nordvpn.com")
        return all(predicate(endpoint) for predicate in country_only)

    return eligible


def extract_archive(destination: Path, progress, protocol: str = "both", eligible=None) -> None:
    archive = destination / "nordvpn.zip"
    progress("Downloading OpenVPN configurations")
    with urlopen(ARCHIVE_URL, timeout=30) as response, archive.open("wb") as out:
        total = 0
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            if total > MAX_ARCHIVE_BYTES:
                raise ValueError("download exceeds archive size limit")
            out.write(chunk)
            progress(f"Downloaded {total / 1048576:.1f} MiB")
    progress("Inspecting and extracting OpenVPN configurations")
    with zipfile.ZipFile(archive) as z:
        # NordVPN's archive separates transport variants by filename/directory.
        # Filter before applying extraction budgets: the unused TCP collection
        # should not prevent a UDP-only benchmark (or vice versa).
        all_profiles = [x for x in z.infolist() if x.filename.lower().endswith(".ovpn") and not x.is_dir()]

        def matches(info):
            if protocol == "both":
                return True
            name = info.filename.lower()
            # Names commonly end in .udp.ovpn or .udp_2.6.ovpn; archives
            # may also organise profiles beneath ovpn_udp/ovpn_tcp/.
            return (
                f"/{'ovpn_' + protocol}/" in "/" + name
                or re.search(rf"\.{protocol}(?:_\d+(?:\.\d+)*)?\.ovpn$", name) is not None
            )

        entries = [info for info in all_profiles if matches(info) and (eligible is None or eligible(info.filename))]
        if not entries:
            raise ValueError(f"no {protocol} OpenVPN configurations found in archive")
        total_bytes = sum(info.file_size for info in entries)
        if len(entries) > MAX_FILES:
            raise ValueError(f"archive contains {len(entries)} selected profiles; safety limit is {MAX_FILES}")
        if total_bytes > MAX_EXTRACTED_BYTES:
            raise ValueError(
                f"selected profiles total {total_bytes / 1048576:.1f} MiB; safety limit is {MAX_EXTRACTED_BYTES / 1048576:.0f} MiB"
            )
        if any(info.file_size > MAX_PROFILE_BYTES for info in entries):
            raise ValueError(f"archive contains a profile larger than {MAX_PROFILE_BYTES / 1048576:.0f} MiB")
        progress(f"Selected {len(entries)} {protocol} profiles ({total_bytes / 1048576:.1f} MiB uncompressed)")
        for index, info in enumerate(entries, 1):
            # Flatten paths into numbered files: no archive-controlled output paths.
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError("archive contains a symbolic link")
            target = destination / "profiles" / f"{index:05d}-{Path(info.filename).name}"
            target.parent.mkdir(exist_ok=True)
            with z.open(info) as source, target.open("wb") as output:
                remaining = info.file_size
                while block := source.read(min(65536, remaining + 1)):
                    remaining -= len(block)
                    if remaining < 0:
                        raise ValueError("archive entry exceeds declared size")
                    output.write(block)
            if index % 250 == 0:
                progress(f"Extracted {index}/{len(entries)} configurations")
    archive.unlink()
    progress(f"Extracted {len(entries)} configurations")


def ping(address: str, count: int, timeout: float) -> Measurement:
    """Use the system ping utility, capturing individual reply times and loss."""
    result = Measurement(address=address, attempted=count)
    if os.name == "nt":
        cmd = ["ping", "-n", str(count), "-w", str(max(1, int(timeout * 1000))), address]
    elif sys.platform == "darwin":
        cmd = ["ping", "-n", "-c", str(count), "-W", str(max(1, int(timeout * 1000))), address]
    else:
        cmd = ["ping", "-n", "-c", str(count), "-W", str(max(1, math.ceil(timeout))), "-i", "0.2", address]
    try:
        completed = subprocess.run(
            cmd, capture_output=True, text=True, errors="replace", timeout=count * (timeout + 1.0) + 3, check=False
        )
        result.samples = [float(value.replace(",", ".")) for value in PING_TIME.findall(completed.stdout)]
        result.samples = result.samples[:count]
        if not result.samples:
            result.error = "no ICMP replies"
    except subprocess.TimeoutExpired:
        result.error = "ping timed out"
    except OSError as exc:
        result.error = f"ping unavailable: {exc.strerror or exc}"
    return result


def tcp_probe(address: str, port: int, count: int, timeout: float) -> Measurement:
    """Time TCP handshakes to an advertised TCP OpenVPN port, without VPN login."""
    result = Measurement(address=address, attempted=count, method="tcp")
    for _ in range(count):
        start = time.perf_counter()
        try:
            with socket.create_connection((address, port), timeout=timeout):
                result.samples.append((time.perf_counter() - start) * 1000)
        except OSError as exc:
            result.error = f"TCP connection failed: {exc}"
    if not result.samples and not result.error:
        result.error = "no TCP connections succeeded"
    return result


def execute_tcp_stage(targets, count, timeout, workers, label, quiet):
    """Probe unique (address, TCP port) targets concurrently."""
    start = time.monotonic()
    output = {}
    with futures.ThreadPoolExecutor(max_workers=workers) as pool:
        tasks = {pool.submit(tcp_probe, address, port, count, timeout): (address, port) for address, port in targets}
        for task in futures.as_completed(tasks):
            target = tasks[task]
            try:
                output[target] = task.result()
            except Exception as exc:
                output[target] = Measurement(target[0], attempted=count, error=f"probe error: {exc}", method="tcp")
            progress_line(label, len(output), len(targets), sum(bool(m.samples) for m in output.values()), start, quiet)
    if sys.stderr.isatty() and not quiet:
        print(file=sys.stderr)
    return output


def rank(m: Measurement):
    # Reliability first. An unresponsive host is never described as offline.
    return (
        not bool(m.samples),
        m.loss,
        m.median if m.median is not None else float("inf"),
        m.jitter if m.jitter is not None else float("inf"),
        m.address,
    )


def progress_line(stage, completed, total, successes, start, quiet=False):
    if quiet:
        return
    elapsed = time.monotonic() - start
    eta = (elapsed / completed * (total - completed)) if completed else None
    eta_text = f"{eta:.0f}s" if eta is not None else "?"
    message = f"{stage}: {completed}/{total} | responding {successes} | elapsed {elapsed:.1f}s | ETA {eta_text}"
    if sys.stderr.isatty():
        print("\r" + message.ljust(100), end="", file=sys.stderr, flush=True)
    else:
        print(message, file=sys.stderr, flush=True)


def execute_stage(addresses, count, timeout, workers, label, quiet):
    start = time.monotonic()
    output = {}
    last = 0.0
    with futures.ThreadPoolExecutor(max_workers=workers) as pool:
        tasks = {pool.submit(ping, addr, count, timeout): addr for addr in addresses}
        for task in futures.as_completed(tasks):
            addr = tasks[task]
            try:
                output[addr] = task.result()
            except Exception as exc:
                output[addr] = Measurement(addr, attempted=count, error=f"probe error: {exc}")
            now = time.monotonic()
            if now - last >= 0.25 or len(output) == len(addresses):
                progress_line(
                    label, len(output), len(addresses), sum(bool(m.samples) for m in output.values()), start, quiet
                )
                last = now
    if sys.stderr.isatty() and not quiet:
        print(file=sys.stderr)
    return output


def latency_rgb(milliseconds: float, colourblind: bool = False) -> tuple[int, int, int]:
    """Interpolate between fixed latency anchors, clamping outlying values."""
    palette = COLOURBLIND_PALETTE if colourblind else DEFAULT_PALETTE
    value = max(0.0, milliseconds)
    for index in range(len(LATENCY_ANCHORS) - 1):
        left, right = LATENCY_ANCHORS[index : index + 2]
        if value <= right:
            fraction = (value - left) / (right - left)
            a, b = palette[index : index + 2]
            return tuple(
                round(int(a[offset : offset + 2], 16) * (1 - fraction) + int(b[offset : offset + 2], 16) * fraction)
                for offset in (1, 3, 5)
            )
    last = palette[-1]
    return tuple(int(last[offset : offset + 2], 16) for offset in (1, 3, 5))


def colour_latency(value: str, milliseconds: float | None, *, enabled: bool, colourblind: bool = False) -> str:
    """Apply terminal colour only to a numeric mean; retain the value as text."""
    if not enabled or milliseconds is None or not math.isfinite(milliseconds):
        return value
    r, g, b = latency_rgb(milliseconds, colourblind)
    return f"\x1b[38;2;{r};{g};{b}m{value}\x1b[0m"


def terminal_colour_enabled(stream=None) -> bool:
    """Respect conventional no-colour settings and avoid escape codes in pipes."""
    if stream is None:
        stream = sys.stdout
    return bool(
        getattr(stream, "isatty", lambda: False)()
        and os.environ.get("NO_COLOR") is None
        and os.environ.get("TERM", "") != "dumb"
    )


def display_width(value: str) -> int:
    """Measure visible table width, treating a flag pair as two terminal cells."""
    visible = ANSI_ESCAPE.sub("", value)
    # Regional indicator pairs form one flag glyph, generally two cells wide.
    indicators = range(0x1F1E6, 0x1F200)
    count = sum(1 for char in visible if ord(char) in indicators)
    return len(visible) - count + (count // 2) * 2


def render_table(headers, rows, ascii_only=False):
    rows = [[str(x) for x in row] for row in rows]
    widths = [max(len(str(header)), *(display_width(row[i]) for row in rows)) for i, header in enumerate(headers)]
    if ascii_only:
        corner, cross, vert, horiz = "+", "+", "|", "-"
    else:
        corner, cross, vert, horiz = "┼", "┼", "│", "─"
    sep = cross.join(horiz * (width + 2) for width in widths)

    def line(row):
        return (
            vert
            + vert.join(
                " " + str(value) + " " * max(0, width - display_width(str(value))) + " "
                for value, width in zip(row, widths)
            )
            + vert
        )

    return "\n".join(
        [
            ("+" if ascii_only else "┌") + sep.replace("┼", "┬") + ("+" if ascii_only else "┐"),
            line(headers),
            corner + sep + corner,
            *(line(row) for row in rows),
            ("+" if ascii_only else "└") + sep.replace("┼", "┴") + ("+" if ascii_only else "┘"),
        ]
    )


def records_for(endpoints, measurements):
    records = []
    for endpoint in endpoints:
        m = (
            measurements[(endpoint.host, endpoint.port)]
            if (endpoint.host, endpoint.port) in measurements
            else measurements[endpoint.host]
        )
        records.append(
            {
                "server": endpoint.name,
                "country": country_name(endpoint.name),
                "config_file": Path(endpoint.file).name,
                "address": endpoint.host,
                "port": endpoint.port,
                "protocol": endpoint.protocol,
                "probe": m.method,
                "stage": m.stage,
                "sent": m.attempted,
                "received": len(m.samples),
                "loss_pct": round(m.loss, 2),
                "median_ms": round(m.median, 3) if m.median is not None else None,
                "mean_ms": round(m.mean, 3) if m.mean is not None else None,
                "jitter_mad_ms": round(m.jitter, 3) if m.jitter is not None else None,
                "samples_ms": m.samples,
                "error": m.error,
            }
        )
    ordered = sorted(
        records,
        key=lambda r: (
            not bool(r["received"]),
            r["loss_pct"],
            r["median_ms"] if r["median_ms"] is not None else float("inf"),
            r["server"],
            r["protocol"],
            r["port"],
        ),
    )
    # One displayed rank per canonical server and measured address. Keep all
    # configuration records separately for lossless CSV/JSON exports.
    return ordered


def tcp_refinement_shortlist(endpoints, survey_results, top):
    """Choose one surveyed TCP port per distinct server/address for refinement.

    Survey results remain port-scoped for exports. Stable tie-breaking ensures
    that archive ordering and thread completion order do not affect selection.
    """
    representatives = {}
    for endpoint in endpoints:
        if endpoint.protocol != "tcp":
            continue
        target = (endpoint.host, endpoint.port)
        identity = (endpoint.name, endpoint.host)
        candidate = (rank(survey_results[target]), endpoint.port, target)
        previous = representatives.get(identity)
        if previous is None or candidate < previous:
            representatives[identity] = candidate
    limit = min(len(representatives), max(top * 3, 20))
    ordered = sorted(representatives.items(), key=lambda item: (item[1][0], item[0], item[1][1]))
    return [candidate[2] for _, candidate in ordered[:limit]]


def merge_refinement(measurements, additions):
    """Accumulate additional attempts without discarding survey observations."""
    for target, extra in additions.items():
        initial = measurements[target]
        initial.attempted += extra.attempted
        initial.samples.extend(extra.samples)
        initial.stage = "refined"
        initial.error = "" if initial.samples else extra.error


def adaptive_contenders(shortlist, measurements, top):
    """Conservatively retain leaders and candidates with overlapping robust ranges.

    This heuristic is not a confidence interval or a significance test. Its
    minimum 1 ms tolerance reduces premature elimination of close candidates.
    """
    responsive = sorted(
        (target for target in shortlist if measurements[target].samples),
        key=lambda target: (rank(measurements[target]), target),
    )
    if not responsive:
        return list(shortlist)
    leader = measurements[responsive[0]]
    leader_upper = leader.median + max(1.0, 3 * leader.jitter)
    selected = set(responsive[:top])
    for target in responsive:
        candidate = measurements[target]
        if candidate.median - max(1.0, 3 * candidate.jitter) <= leader_upper:
            selected.add(target)
    # Keep non-responsive shortlisted targets eligible for a second chance.
    selected.update(target for target in shortlist if not measurements[target].samples)
    return [target for target in shortlist if target in selected]


def adaptive_refine(shortlist, measurements, additional, top, probe, timeout, workers, quiet):
    """Refine every shortlisted target once, then spend remaining samples on contenders.

    Total per-target attempts never exceed the selected accuracy preset.
    """
    first = min(additional, max(4, additional // 2))
    second = additional - first
    executor = execute_tcp_stage if probe == "tcp" else execute_stage
    label = "TCP" if probe == "tcp" else "ICMP"
    merge_refinement(measurements, executor(shortlist, first, timeout, workers, f"{label} refinement 1/2", quiet))
    if second:
        contenders = adaptive_contenders(shortlist, measurements, top)
        if not quiet:
            print(f"Adaptive refinement: {len(contenders)}/{len(shortlist)} targets retained", file=sys.stderr)
        merge_refinement(measurements, executor(contenders, second, timeout, workers, f"{label} refinement 2/2", quiet))


def distinct_servers(records):
    unique = {}
    for record in records:
        unique.setdefault((record["server"], record["address"]), record)
    return list(unique.values())


def median_interval(samples, identity, *, resamples=400):
    """Deterministic percentile bootstrap interval for a sample median.

    This describes sampling uncertainty under an independent, stationary sample
    assumption; it is not a guarantee about future network performance.
    """
    if len(samples) < 8:
        return None
    seed = int.from_bytes(hashlib.sha256(identity.encode("utf-8")).digest()[:8], "big")
    generator = random.Random(seed)
    count = len(samples)
    estimates = sorted(statistics.median(generator.choices(samples, k=count)) for _ in range(resamples))
    return (estimates[int(resamples * 0.05)], estimates[int(resamples * 0.95) - 1])


def stability_report(ranked, measurements, *, top=10):
    """Provide an advisory comparison without modifying the benchmark ranking."""
    candidates = [row for row in ranked if row["received"]][:top]
    if not candidates:
        return "No responsive servers available for stability assessment."
    entries = []
    for row in candidates:
        key = (row["address"], row["port"]) if row["probe"] == "tcp" else row["address"]
        measurement = measurements[key]
        identity = f"{row['server']}|{row['address']}|{row['port']}|{row['probe']}"
        interval = median_interval(measurement.samples, identity)
        entries.append((row, interval))
    leader = entries[0][1]
    lines = ["Exploratory 90% bootstrap median intervals (milliseconds):"]
    for row, interval in entries:
        if interval is None:
            assessment = "insufficient samples (minimum 8)"
            bounds = "n/a"
        else:
            bounds = f"{interval[0]:.2f} to {interval[1]:.2f}"
            if leader is None:
                assessment = "no refined leader interval"
            elif row is entries[0][0]:
                assessment = "ranked leader"
            elif interval[0] <= leader[1] and leader[0] <= interval[1]:
                assessment = "overlaps leader interval"
            else:
                assessment = "non-overlapping intervals"
        lines.append(f"  {row['server']} ({row['address']}:{row['port']}): {bounds}; {assessment}")
    lines.append(
        "Advisory only: overlapping intervals do not establish equivalence, and "
        "non-overlap is not a formal pairwise significance test. "
        "Sequential network samples may be correlated."
    )
    return "\n".join(lines)


def export(records, path, fmt, ascii_only):
    if fmt == "json":
        path.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    elif fmt == "csv":
        with path.open("w", newline="", encoding="utf-8") as stream:
            fields = [key for key in records[0] if key != "samples_ms"]
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            writer.writerows({key: row[key] for key in fields} for row in records)
    else:
        path.write_text(format_results(records, len(records), ascii_only, colour=False) + "\n", encoding="utf-8")


def format_results(records, top, ascii_only, *, colour=False, colourblind=False):
    headers = [
        "#",
        "Server",
        "Country",
        "Transport",
        "Probe",
        "IP",
        "Port",
        "Mean",
        "Median",
        "MAD",
        "Loss",
        "Samples",
        "Stage",
    ]
    rows = []
    for index, r in enumerate(records[:top], 1):
        rows.append(
            [
                index,
                r["server"],
                (
                    r.get("country", "Unknown")
                    if ascii_only or not country_flag(r["server"])
                    else f"{country_flag(r['server'])}  {r.get('country', 'Unknown')}"
                ),
                r["protocol"],
                r.get("probe", "icmp"),
                r["address"],
                r["port"],
                colour_latency(
                    f"{r['mean_ms']:.2f} ms" if r["mean_ms"] is not None else "—",
                    r["mean_ms"],
                    enabled=colour,
                    colourblind=colourblind,
                ),
                f"{r['median_ms']:.2f} ms" if r["median_ms"] is not None else "—",
                f"{r['jitter_mad_ms']:.2f} ms" if r["jitter_mad_ms"] is not None else "—",
                f"{r['loss_pct']:.1f}%",
                f"{r['received']}/{r['sent']}",
                r["stage"],
            ]
        )
    return render_table(headers, rows, ascii_only)


def phase_header(title, *, ascii_only=False, quiet=False, separate=False, stream=None):
    """Announce a real execution phase without interfering with data output."""
    if quiet:
        return
    stream = sys.stderr if stream is None else stream
    if separate:
        print(file=stream, flush=True)
    interactive = bool(getattr(stream, "isatty", lambda: False)())
    if ascii_only or not interactive:
        print(f"-- {title} --", file=stream, flush=True)
        return
    width = max(0, min(shutil.get_terminal_size(fallback=(80, 24)).columns, 100))
    prefix = f"── {title} "
    print(prefix + "─" * max(2, width - len(prefix)), file=stream, flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--config-dir", type=Path)
    source.add_argument("--download", action="store_true")
    parser.add_argument("--cache-file", type=Path, help="derived endpoint JSON cache location")
    parser.add_argument(
        "--cache-ttl", type=float, default=24, metavar="HOURS", help="cache freshness interval in hours (default: 24)"
    )
    parser.add_argument("--refresh-cache", action="store_true", help="force a remote archive check")
    parser.add_argument("--no-cache", action="store_true", help="download and parse without a persistent cache")
    parser.add_argument("--offline", action="store_true", help="use only a previously validated endpoint cache")
    parser.add_argument("--protocol", choices=("udp", "tcp", "both"), default="udp")
    parser.add_argument(
        "--filter",
        action="append",
        default=[],
        metavar="EXPR",
        help="filter configurations; repeated expressions are combined with AND",
    )
    parser.add_argument("--region-list", action="append", default=[], metavar="NAME")
    parser.add_argument("--region-lists-file", type=Path, metavar="PATH")
    parser.add_argument("--list-region-lists", action="store_true")
    parser.add_argument(
        "--probe",
        choices=("icmp", "tcp"),
        default="icmp",
        help="one consistent measurement method: ICMP ping or advertised TCP connection establishment",
    )
    parser.add_argument("--accuracy", choices=tuple(PRESETS), default="balanced")
    parser.add_argument("--top", type=int, default=10)
    parser.add_argument(
        "--adaptive", action="store_true", help="allocate the second refinement round to leading and uncertain targets"
    )
    parser.add_argument(
        "--stability", action="store_true", help="show exploratory bootstrap median intervals for ranked servers"
    )
    parser.add_argument("--workers", type=int, default=24)
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--report", type=Path, help="write a versioned, self-contained JSON benchmark report")
    parser.add_argument("--format", choices=("csv", "json", "table"), default="csv")
    parser.add_argument("--ascii", action="store_true")
    parser.add_argument(
        "--colourblind", "--colorblind", action="store_true", help="use a blue-to-orange latency palette"
    )
    parser.add_argument("--no-colour", "--no-color", action="store_true", help="disable terminal colour output")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument(
        "--allow-active-vpn",
        action="store_true",
        help="permit benchmarking while NordVPN is connected (results may be distorted)",
    )
    parser.add_argument(
        "--auto-connect", action="store_true", help="connect to the selected ranked server using the NordVPN Linux CLI"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="preview the selected NordVPN connection without changing VPN state (requires --auto-connect)",
    )
    parser.add_argument(
        "--connect-rank", type=int, default=1, help="rank to connect to when --auto-connect is enabled (default: 1)"
    )
    parser.add_argument(
        "--replace-connection",
        action="store_true",
        help="allow replacing an existing NordVPN connection without prompting",
    )
    args = parser.parse_args(argv)
    if not args.list_region_lists and not (args.download or args.config_dir):
        parser.error("one of --download or --config-dir is required")
    if args.cache_ttl < 0 or not math.isfinite(args.cache_ttl):
        parser.error("--cache-ttl must be a finite non-negative number of hours")
    if args.offline and (not args.download or args.no_cache or args.refresh_cache):
        parser.error("--offline requires --download and cannot be combined with --no-cache or --refresh-cache")
    if args.top < 1 or not 1 <= args.workers <= 128 or not 0.1 <= args.timeout <= 30:
        parser.error("--top must be positive, --workers 1..128, --timeout 0.1..30")
    if args.connect_rank < 1 or (args.auto_connect and args.connect_rank > args.top):
        parser.error("--connect-rank must be between 1 and --top")
    if args.dry_run and not args.auto_connect:
        parser.error("--dry-run requires --auto-connect")
    if (args.connect_rank != 1 or args.replace_connection) and not args.auto_connect:
        parser.error("--connect-rank and --replace-connection require --auto-connect")
    if args.probe == "tcp" and args.protocol == "udp" and not args.list_region_lists:
        parser.error("--probe tcp requires --protocol tcp or --protocol both")
    try:
        region_lists = load_region_lists(args.region_lists_file)
        if args.list_region_lists:
            for name, item in sorted(region_lists.items()):
                print(f"{name}: {', '.join(item['countries'])} ({item['description']})")
            return 0
        for name in args.region_list:
            if name not in region_lists:
                parser.error(f"unknown region list: {name}")
        filters = [compile_filter(expression, region_lists) for expression in args.filter]
        filters.extend(compile_filter(f"list:{name}", region_lists) for name in args.region_list)
        eligible = country_prefilter([*args.filter, *(f"list:{name}" for name in args.region_list)], region_lists)
    except (FilterSyntaxError, ValueError, OSError, json.JSONDecodeError) as exc:
        parser.error(f"invalid --filter: {exc}")
    from nordvpn_connection import benchmark_preflight

    if not benchmark_preflight(allow_active_vpn=args.allow_active_vpn):
        return 2
    if args.probe == "icmp" and shutil.which("ping") is None:
        parser.error("system ping utility is required")
    started_at = timestamp()
    try:
        phase_header("Configuration", ascii_only=args.ascii, quiet=args.quiet)
        if not args.quiet:
            print(
                f"Probe method: {args.probe.upper()} | Accuracy: {args.accuracy} | Transport: {args.protocol}",
                file=sys.stderr,
            )
            if args.region_list:
                print(f"Region lists: {', '.join(args.region_list)}", file=sys.stderr)
        with tempfile.TemporaryDirectory(prefix="nordvpn-benchmark-") as temp:
            root = Path(temp)
            phase_header("Server discovery", ascii_only=args.ascii, quiet=args.quiet, separate=True)
            endpoints = []
            source_info = {"kind": "download" if args.download else "config-directory"}
            invalid = 0
            filtered = 0
            if args.download and not args.no_cache:
                from nordvpn_cache import default_path, refresh

                cache_path = (args.cache_file or default_path()).expanduser()
                catalogue = refresh(
                    cache_path,
                    ARCHIVE_URL,
                    args.cache_ttl * 3600,
                    lambda msg: None if args.quiet else print(msg, file=sys.stderr),
                    force=args.refresh_cache,
                    offline=args.offline,
                )
                from nordvpn_cache import load as load_cache

                cache_metadata = load_cache(cache_path, ARCHIVE_URL)["source"]
                source_info.update(
                    {
                        "url": ARCHIVE_URL,
                        "archive_sha256": cache_metadata["sha256"],
                        "checked_at": cache_metadata["checked_at"],
                        "catalogue_schema": 1,
                    }
                )
                for entry in catalogue:
                    endpoint = Endpoint(**entry)
                    if not eligible(endpoint.file):
                        filtered += 1
                    elif (args.protocol == "both" or endpoint.protocol == args.protocol) and all(
                        predicate(endpoint) for predicate in filters
                    ):
                        endpoints.append(endpoint)
                    else:
                        filtered += 1
            else:
                if args.download:
                    extract_archive(
                        root, lambda msg: None if args.quiet else print(msg, file=sys.stderr), args.protocol, eligible
                    )
                    config_dir = root / "profiles"
                    source_info["url"] = ARCHIVE_URL
                else:
                    config_dir = args.config_dir.expanduser()
                    source_info["path"] = str(config_dir.resolve())
                    if not config_dir.is_dir():
                        parser.error(f"configuration directory does not exist: {config_dir}")
                for path in sorted(config_dir.rglob("*.ovpn")):
                    if not eligible(path):
                        filtered += 1
                        continue
                    try:
                        for endpoint in parse_profile(path):
                            if args.protocol == "both" or endpoint.protocol == args.protocol:
                                if all(predicate(endpoint) for predicate in filters):
                                    endpoints.append(endpoint)
                                else:
                                    filtered += 1
                    except (ValueError, UnicodeError, OSError) as exc:
                        invalid += 1
                        if args.verbose:
                            print(f"Skipping {path}: {exc}", file=sys.stderr)
            if not endpoints:
                parser.error("no matching valid OpenVPN endpoints found (check --protocol and --filter)")
            addresses = sorted({e.host for e in endpoints})
            random.Random(0).shuffle(addresses)
            survey, additional = PRESETS[args.accuracy]
            tcp_targets = sorted({(e.host, e.port) for e in endpoints if e.protocol == "tcp"})
            if args.probe == "tcp" and not tcp_targets:
                parser.error("no TCP OpenVPN endpoints matched; use --protocol tcp or both")
            if not args.quiet:
                print(
                    f"Found {len(endpoints)} endpoints across {len(addresses)} addresses ({invalid} invalid profiles, {filtered} filtered endpoints)",
                    file=sys.stderr,
                )
            measurements = {}
            phase_header("Initial benchmarking", ascii_only=args.ascii, quiet=args.quiet, separate=True)
            if args.probe == "icmp":
                measurements = execute_stage(addresses, survey, args.timeout, args.workers, "ICMP survey", args.quiet)
                shortlist_size = min(len(addresses), max(args.top * 3, 20))
                shortlist = sorted(addresses, key=lambda a: rank(measurements[a]))[:shortlist_size]
                phase_header("Refinement", ascii_only=args.ascii, quiet=args.quiet, separate=True)
                if args.adaptive:
                    adaptive_refine(
                        shortlist, measurements, additional, args.top, "icmp", args.timeout, args.workers, args.quiet
                    )
                else:
                    merge_refinement(
                        measurements,
                        execute_stage(shortlist, additional, args.timeout, args.workers, "ICMP refinement", args.quiet),
                    )
            if args.probe == "tcp":
                targets = tcp_targets
                if targets:
                    tcp_results = execute_tcp_stage(
                        targets, survey, args.timeout, args.workers, "TCP survey", args.quiet
                    )
                    shortlist = tcp_refinement_shortlist(endpoints, tcp_results, args.top)
                    phase_header("Refinement", ascii_only=args.ascii, quiet=args.quiet, separate=True)
                    if args.adaptive:
                        adaptive_refine(
                            shortlist, tcp_results, additional, args.top, "tcp", args.timeout, args.workers, args.quiet
                        )
                    else:
                        merge_refinement(
                            tcp_results,
                            execute_tcp_stage(
                                shortlist, additional, args.timeout, args.workers, "TCP refinement", args.quiet
                            ),
                        )
                    measurements = tcp_results
            # TCP records are port-scoped. ICMP results remain address-scoped.
            if args.probe == "tcp":
                measured_endpoints = [e for e in endpoints if e.protocol == "tcp"]
            else:
                measured_endpoints = endpoints
            records = records_for(measured_endpoints, measurements)
            assert len({record["probe"] for record in records}) <= 1, "mixed probe methods in one benchmark"
            ranked = distinct_servers(records)
            if not any(row["received"] for row in ranked):
                print(
                    "Warning: no responsive endpoints; VPN availability remains unknown and no reliable fastest server can be identified.",
                    file=sys.stderr,
                )
            phase_header("Results", ascii_only=args.ascii, quiet=args.quiet, separate=True)
            print(
                format_results(
                    ranked,
                    args.top,
                    args.ascii,
                    colour=not args.no_colour and terminal_colour_enabled(),
                    colourblind=args.colourblind,
                )
            )
            if args.stability:
                print("\n" + stability_report(ranked, measurements, top=args.top))
            if args.output:
                destination = args.output.expanduser()
                export(records if args.format in ("csv", "json") else ranked, destination, args.format, args.ascii)
                if not args.quiet:
                    print(f"Wrote {len(records)} results to {destination}", file=sys.stderr)
            if args.report:
                report = build_report(
                    started_at=started_at,
                    finished_at=timestamp(),
                    settings={
                        "probe": args.probe,
                        "protocol": args.protocol,
                        "accuracy": args.accuracy,
                        "top": args.top,
                        "workers": args.workers,
                        "timeout_seconds": args.timeout,
                        "filters": args.filter,
                        "region_lists": args.region_list,
                        "stability_enabled": args.stability,
                        "adaptive_enabled": args.adaptive,
                    },
                    source=source_info,
                    methodology={
                        "survey_samples_per_target": survey,
                        "refinement_additional_samples_per_target": additional,
                        "adaptive_refinement": (
                            "two rounds, robust-range contender selection; maximum per-target attempts unchanged"
                            if args.adaptive
                            else "disabled; fixed refinement samples"
                        ),
                        "ranking": "responsiveness, loss, median latency, median absolute deviation",
                        "tcp_refinement": "one representative port per server and destination IP",
                        "latency_unit": "milliseconds",
                        "probe_description": (
                            "TCP connection establishment" if args.probe == "tcp" else "ICMP echo round trip"
                        ),
                    },
                    records=records,
                    ranked=ranked,
                    stability=stability_report(ranked, measurements, top=args.top) if args.stability else None,
                )
                write_report(args.report.expanduser(), report)
                if not args.quiet:
                    print(f"Wrote benchmark report to {args.report}", file=sys.stderr)
            if args.auto_connect and (args.connect_rank > len(ranked) or not ranked[args.connect_rank - 1]["received"]):
                print(
                    "Connection error: selected rank has no successful probe; cannot identify a fastest server.",
                    file=sys.stderr,
                )
                return 2
            if args.auto_connect:
                if not args.quiet:
                    print(file=sys.stderr)
                from nordvpn_connection import ConnectionError, connect, preview_connection

                def confirm(existing, selected):
                    if not sys.stdin.isatty():
                        return False
                    answer = input(
                        f"Replace existing VPN connection ({existing or 'unknown server'}) with {selected}? [y/N] "
                    )
                    return answer.strip().lower() in ("y", "yes")

                try:
                    if args.dry_run:
                        preview_connection(ranked, args.connect_rank, replace_existing=args.replace_connection)
                    else:
                        connect(ranked, args.connect_rank, replace_existing=args.replace_connection, confirm=confirm)
                except ConnectionError as exc:
                    print(f"Connection error: {exc}", file=sys.stderr)
                    return 2
        return 0
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
