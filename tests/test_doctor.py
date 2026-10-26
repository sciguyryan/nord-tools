"""Platform and dependency preflight contracts."""

import contextlib
import io
import json
import unittest
from unittest.mock import patch

import nord_tools
import nordvpn_doctor


class DoctorTests(unittest.TestCase):
    @patch("nordvpn_doctor.shutil.which", return_value=None)
    def test_unsupported_platform_is_failure(self, _which):
        checks = nordvpn_doctor.inspect(system="Windows", version=(3, 11, 0))
        self.assertEqual(checks[0].status, "unsupported")
        self.assertTrue(checks[0].required)

    @patch("nordvpn_doctor.shutil.which", return_value=None)
    def test_missing_optional_tools_do_not_fail_default(self, _which):
        with (
            patch("nordvpn_doctor.platform.system", return_value="Linux"),
            patch("nordvpn_doctor.sys.version_info", (3, 11, 0)),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(nordvpn_doctor.main([]), 0)
            self.assertEqual(nordvpn_doctor.main(["--strict"]), 2)

    @patch("nordvpn_doctor.shutil.which", return_value="/usr/bin/tool")
    def test_python_minimum(self, _which):
        self.assertEqual(nordvpn_doctor.inspect(system="Linux", version=(3, 9, 9))[1].status, "missing")

    @patch("nordvpn_doctor.shutil.which", return_value=None)
    def test_json_output_and_dispatch(self, _which):
        with (
            patch("nordvpn_doctor.platform.system", return_value="Linux"),
            patch("nordvpn_doctor.sys.version_info", (3, 11, 0)),
        ):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(nord_tools.main(["doctor", "--json"]), 0)
            result = json.loads(output.getvalue())
            self.assertIn("checks", result)
            self.assertEqual(result["checks"][0]["name"], "platform")


if __name__ == "__main__":
    unittest.main()
