"""The credential-bearing E2 probe must remain opt-in and secret-free by default."""

import contextlib
import io
import json
from pathlib import Path
import tempfile

import pytest

from tools import probe_provider_workflows as probe


def test_dry_run_does_not_read_provider_inputs_or_change_networking():
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        assert probe.main([]) == 0
    assert "DRY RUN" in output.getvalue()
    assert "No provider configuration is read" in output.getvalue()


def test_configuration_argument_is_explicit_and_unambiguous():
    assert probe.parse_configuration("gb123=/secure/gb123.conf") == ("gb123", Path("/secure/gb123.conf"))
    with pytest.raises(Exception, match="SERVER=/private/path.conf"):
        probe.parse_configuration("/secure/gb123.conf")


def test_active_namespace_mapping_requires_complete_active_identity():
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        document = {
            "allocations": {
                "resources": [
                    {"allocation_id": "namespace", "profile": "primary", "kind": "namespace", "identifier": "nt-a"},
                    {"allocation_id": "wireguard", "profile": "primary", "kind": "interface", "identifier": "ntwg1"},
                ]
            },
            "events": [
                {"allocation_id": "namespace", "state": "active"},
                {"allocation_id": "wireguard", "state": "active"},
            ],
        }
        (root / "lifecycle.json").write_text(json.dumps(document))
        assert probe.active_namespaces(root) == {"primary": ("nt-a", "ntwg1")}
        document["events"][1]["state"] = "failed"
        (root / "lifecycle.json").write_text(json.dumps(document))
        with pytest.raises(probe.ProbeError, match="lacks one namespace"):
            probe.active_namespaces(root)
