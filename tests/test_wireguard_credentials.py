"""Credential input boundaries must fail without disclosing key material."""

import base64
import os
import tempfile
import unittest

from nord_tools_internal.nordvpn_wireguard_credentials import CredentialError, private_key_from_fd


KEY = base64.b64encode(bytes(range(32)))


class CredentialDescriptorTests(unittest.TestCase):
    def test_private_regular_file_and_buffer_zeroisation(self):
        with tempfile.TemporaryFile() as file:
            os.fchmod(file.fileno(), 0o600)
            file.write(KEY + b"\n")
            file.seek(0)
            with private_key_from_fd(file.fileno()) as buffer:
                self.assertEqual(bytes(buffer), KEY)
                held = buffer
            self.assertEqual(held, bytearray(b"\x00" * 44))

    def test_rejects_world_readable_file(self):
        with tempfile.TemporaryFile() as file:
            os.fchmod(file.fileno(), 0o644)
            file.write(KEY)
            file.seek(0)
            with self.assertRaisesRegex(CredentialError, "permissions"), private_key_from_fd(file.fileno()):
                pass

    def test_pipe_input_is_accepted(self):
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, KEY)
            os.close(write_fd)
            write_fd = -1
            with private_key_from_fd(read_fd) as buffer:
                self.assertEqual(bytes(buffer), KEY)
        finally:
            os.close(read_fd)
            if write_fd != -1:
                os.close(write_fd)

    def test_rejects_invalid_or_oversized_keys_without_echoing(self):
        for invalid in (b"invalid", KEY + b"extra", b"!" * 44, KEY + b"\n\n"):
            with self.subTest(length=len(invalid)), tempfile.TemporaryFile() as file:
                os.fchmod(file.fileno(), 0o600)
                file.write(invalid)
                file.seek(0)
                with self.assertRaises(CredentialError) as caught, private_key_from_fd(file.fileno()):
                    pass
                self.assertNotIn(invalid.decode("ascii"), str(caught.exception))

    def test_rejects_bad_descriptors(self):
        for fd in (-1, True, "3"):
            with self.subTest(fd=fd), self.assertRaises(CredentialError), private_key_from_fd(fd):
                pass

    def test_rejects_directory_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            fd = os.open(directory, os.O_RDONLY)
            try:
                with self.assertRaises(CredentialError), private_key_from_fd(fd):
                    pass
            finally:
                os.close(fd)
