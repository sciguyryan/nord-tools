"""Versioned, validated derived catalogue for NordVPN OpenVPN endpoints."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import zipfile

SCHEMA = 1
MAX_BYTES = 150 * 1024 * 1024
MAX_PROFILES = 50000
MAX_PROFILE_BYTES = 2 * 1024 * 1024
MAX_CACHE_BYTES = 30 * 1024 * 1024


def default_path():
    base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return base / "nord-bench" / "endpoints.json"


def load(path, url):
    try:
        if path.stat().st_size > MAX_CACHE_BYTES:
            raise ValueError("cache exceeds size limit")
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("schema_version") != SCHEMA or data.get("source", {}).get("url") != url:
            raise ValueError("cache schema or source mismatch")
        source = data["source"]
        if not isinstance(source["sha256"], str) or len(source["sha256"]) != 64:
            raise ValueError("invalid archive digest")
        if not isinstance(source["checked_at"], (int, float)) or source["checked_at"] < 0:
            raise ValueError("invalid cache timestamp")
        entries = data["endpoints"]
        if not isinstance(entries, list) or len(entries) > MAX_PROFILES * 10:
            raise ValueError("invalid endpoint catalogue")
        if (
            data.get("catalogue_sha256")
            != hashlib.sha256(
                json.dumps(entries, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            ).hexdigest()
        ):
            raise ValueError("endpoint catalogue checksum mismatch")
        for entry in entries:
            if set(entry) != {"file", "host", "port", "protocol", "name"}:
                raise ValueError("invalid endpoint fields")
            if any(not isinstance(entry[k], str) or len(entry[k]) > 512 for k in ("file", "host", "protocol", "name")):
                raise ValueError("invalid endpoint value")
            if not isinstance(entry["port"], int) or not 1 <= entry["port"] <= 65535:
                raise ValueError("invalid endpoint port")
            if entry["protocol"] not in ("tcp", "udp"):
                raise ValueError("invalid endpoint protocol")
        return data
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid endpoint cache: {exc}") from exc


def save(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=path.parent, prefix=".endpoints-", suffix=".tmp", delete=False
        ) as output:
            temporary = Path(output.name)
            os.chmod(temporary, 0o600)
            json.dump(data, output, separators=(",", ":"), ensure_ascii=False)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def refresh(path, url, ttl, progress, *, force=False, offline=False):
    """Return validated endpoint dictionaries; never overwrite valid cache on failure."""
    try:
        previous = load(path, url)
    except ValueError:
        previous = None
    if offline:
        if previous is None:
            raise ValueError("offline mode requires an existing valid endpoint cache")
        progress("Using cached endpoint catalogue (offline)")
        return previous["endpoints"]
    if previous and not force and time.time() - previous["source"]["checked_at"] < ttl:
        progress("Using cached endpoint catalogue (within freshness interval)")
        return previous["endpoints"]

    headers = {}
    if previous and not force:
        if previous["source"].get("etag"):
            headers["If-None-Match"] = previous["source"]["etag"]
        elif previous["source"].get("last_modified"):
            headers["If-Modified-Since"] = previous["source"]["last_modified"]
    progress("Checking NordVPN OpenVPN archive")
    with tempfile.TemporaryDirectory(prefix="nord-bench-cache-") as temp:
        archive = Path(temp) / "ovpn.zip"
        try:
            response = urlopen(Request(url, headers=headers), timeout=30)
        except HTTPError as exc:
            if exc.code != 304 or previous is None:
                raise
            previous["source"]["checked_at"] = time.time()
            save(path, previous)
            progress("Archive unchanged (HTTP 304); using cached catalogue")
            return previous["endpoints"]
        with response, archive.open("wb") as output:
            digest = hashlib.sha256()
            size = 0
            while block := response.read(1024 * 1024):
                size += len(block)
                if size > MAX_BYTES:
                    raise ValueError("archive exceeds size limit")
                digest.update(block)
                output.write(block)
            etag = response.headers.get("ETag")
            modified = response.headers.get("Last-Modified")
        checksum = digest.hexdigest()
        if previous and checksum == previous["source"]["sha256"]:
            previous["source"].update(checked_at=time.time(), etag=etag, last_modified=modified)
            save(path, previous)
            progress("Archive SHA-256 unchanged; using cached catalogue")
            return previous["endpoints"]

        # Import lazily to avoid circular imports; reuse the authoritative profile parser.
        from nordvpn_benchmark import parse_profile

        entries = []
        extracted_bytes = 0
        progress("Parsing updated OpenVPN archive into endpoint catalogue")
        with zipfile.ZipFile(archive) as zipped:
            profiles = [
                info for info in zipped.infolist() if info.filename.lower().endswith(".ovpn") and not info.is_dir()
            ]
            if not profiles or len(profiles) > MAX_PROFILES:
                raise ValueError("archive profile count outside safety limits")
            for info in profiles:
                extracted_bytes += info.file_size
                if extracted_bytes > 1024 * 1024 * 1024:
                    raise ValueError("archive profiles exceed total extraction limit")
                if info.file_size > MAX_PROFILE_BYTES or (info.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ValueError("archive contains oversized profile or symbolic link")
                # Preserve the NordVPN basename so server identity remains canonical.
                profile = Path(temp) / Path(info.filename).name
                with zipped.open(info) as source:
                    payload = source.read(MAX_PROFILE_BYTES + 1)
                    if len(payload) != info.file_size:
                        raise ValueError("archive profile size mismatch")
                    profile.write_bytes(payload)
                try:
                    for endpoint in parse_profile(profile):
                        entries.append(
                            {
                                "file": Path(info.filename).name,
                                "host": endpoint.host,
                                "port": endpoint.port,
                                "protocol": endpoint.protocol,
                                "name": endpoint.name,
                            }
                        )
                except (ValueError, UnicodeError, OSError):
                    pass
                finally:
                    profile.unlink(missing_ok=True)
        if not entries:
            raise ValueError("archive yielded no valid endpoints")
        data = {
            "schema_version": SCHEMA,
            "source": {
                "url": url,
                "sha256": checksum,
                "checked_at": time.time(),
                "etag": etag,
                "last_modified": modified,
            },
            "endpoints": entries,
        }
        data["catalogue_sha256"] = hashlib.sha256(
            json.dumps(entries, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        save(path, data)
        progress(f"Cached {len(entries)} parsed endpoints")
        return entries
