"""Process-bound reference evidence refuses unverified acquisition and release."""

import os
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from nord_tools_internal.nordvpn_consumer_reference_store import ConsumerReferenceError
from nord_tools_internal.nordvpn_runtime_consumers import (
    _active_profile_resources,
    acquire_runtime_consumer,
    initialise_runtime_consumers,
    read_runtime_consumers,
    release_exited_consumer,
)
from tests.test_application_plan import POLICY


class RuntimeConsumerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "runtime.json"
        self.name = sorted(POLICY["applications"])[0]
        self.executable = POLICY["applications"][self.name]["executable"]
        initialise_runtime_consumers(self.path, POLICY)

    def test_initialisation_refuses_overwrite(self):
        with self.assertRaisesRegex(ConsumerReferenceError, "already exists"):
            initialise_runtime_consumers(self.path, POLICY)

    def test_active_profile_resources_exclude_retired_generation(self):
        journal = {
            "allocations": {
                "resources": [
                    {"allocation_id": "retired", "profile": "alpha", "kind": "namespace"},
                    {"allocation_id": "active", "profile": "alpha", "kind": "namespace"},
                    {"allocation_id": "other", "profile": "beta", "kind": "namespace"},
                ]
            },
            "events": [
                {"allocation_id": "retired", "state": "retired"},
                {"allocation_id": "active", "state": "active"},
                {"allocation_id": "other", "state": "active"},
            ],
        }
        self.assertEqual(
            _active_profile_resources(journal, "alpha"),
            [{"allocation_id": "active", "profile": "alpha", "kind": "namespace"}],
        )

    def test_acquire_live_and_release_only_after_exit(self):
        with patch(
            "nord_tools_internal.nordvpn_runtime_consumers._identity", return_value=("boot", "123", self.executable)
        ):
            acquire_runtime_consumer(self.path, POLICY, self.name, os.getpid())
            with self.assertRaisesRegex(ConsumerReferenceError, "already has a lease"):
                acquire_runtime_consumer(self.path, POLICY, self.name, os.getpid())
            with self.assertRaisesRegex(ConsumerReferenceError, "remains alive"):
                release_exited_consumer(self.path, POLICY, self.name)
        with patch(
            "nord_tools_internal.nordvpn_runtime_consumers._identity", return_value=("boot", "124", self.executable)
        ):
            release_exited_consumer(self.path, POLICY, self.name)
        self.assertEqual(read_runtime_consumers(self.path, POLICY)["leases"], [])

    def test_wrong_executable_and_policy_change_refused(self):
        with (
            patch("nord_tools_internal.nordvpn_runtime_consumers._identity", return_value=("boot", "123", "/wrong")),
            self.assertRaisesRegex(ConsumerReferenceError, "executable"),
        ):
            acquire_runtime_consumer(self.path, POLICY, self.name, os.getpid())
        altered = {**POLICY, "applications": {}}
        with self.assertRaises(ConsumerReferenceError):
            read_runtime_consumers(self.path, altered)

    def test_cross_generation_release_is_refused(self):
        with patch(
            "nord_tools_internal.nordvpn_runtime_consumers._identity", return_value=("boot", "123", self.executable)
        ):
            acquire_runtime_consumer(
                self.path,
                POLICY,
                self.name,
                os.getpid(),
                generation_id="generation-a",
                kernel_profile="ntgen_a",
            )
            with self.assertRaisesRegex(ConsumerReferenceError, "different or ambiguous generation"):
                release_exited_consumer(self.path, POLICY, self.name, expected_generation_id="generation-b")
        lease = read_runtime_consumers(self.path, POLICY)["leases"][0]
        self.assertEqual((lease["generation_id"], lease["kernel_profile"]), ("generation-a", "ntgen_a"))

    def test_corrupt_and_symlinked_evidence_refused(self):
        self.path.write_text("{}")
        with self.assertRaises(ConsumerReferenceError):
            read_runtime_consumers(self.path, POLICY)
        alias = self.path.with_name("alias")
        alias.symlink_to(self.path)
        with self.assertRaises(ConsumerReferenceError):
            read_runtime_consumers(alias, POLICY)
