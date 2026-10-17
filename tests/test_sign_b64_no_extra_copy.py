"""Regression tests: sign_file must not create an extra immutable bytes copy
of the signature for Base64 output.

Contract:
- base64.b64encode receives a buffer-protocol view (memoryview) of the wipeable
  ctypes buffer, NOT a bytes(...) copy: the explicit wrapper created a second
  full un-wipeable copy of the signature in the heap (the project policy — see
  encrypt_file/decrypt_and_check/verify_signature — is to minimise immutable
  copies of sensitive material).
- Base64 output is byte-for-byte identical to base64 of the last measured
  signature (multi-operation sequence, including a CKR_BUFFER_TOO_SMALL retry).
- On self-check failure (CKR_SIGNATURE_INVALID) sign_file still raises with the
  user-facing stderr message, and all signature buffers (including the Base64
  source buffer) are wiped.
- On success no signature buffer stays unwiped.
"""
import base64
import ctypes
import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import app
from test_file_input_errors import sign_pair_funcs


class SignFileBase64NoExtraCopyTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.file_path = Path(self.tmpdir.name) / "data.bin"
        self.file_path.write_bytes(b"PLAINTEXT-DATA" * 10)

    def tearDown(self):
        self.tmpdir.cleanup()

    def run_sign_file(self, warmup_count, count, sign_steps, verify_rv=app.CKR_OK):
        """Run sign_file. Returns (calls, verify_addrs, verify_data, memsets,
        output, stderr, error)."""
        calls = []
        verify_addrs = []
        verify_data = []
        funcs = sign_pair_funcs(sign_steps, calls, verify_data)

        def verify(session, data, data_len, sig, sig_len):
            verify_addrs.append(ctypes.cast(sig, ctypes.c_void_p).value)
            if verify_rv != app.CKR_OK:
                return verify_rv
            return orig_verify(session, data, data_len, sig, sig_len)

        orig_verify = funcs["C_Verify"]
        funcs["C_Verify"] = verify

        orig_memset = ctypes.memset
        memsets = []

        def logging_memset(addr, value, size):
            memsets.append(ctypes.cast(addr, ctypes.c_void_p).value)
            return orig_memset(addr, value, size)

        inputs = iter([str(self.file_path), str(warmup_count), ""])
        out, err = io.StringIO(), io.StringIO()
        error = None
        with mock.patch.object(ctypes, "memset", logging_memset), \
             mock.patch("builtins.input", lambda *a: next(inputs)), \
             mock.patch.object(app, "prompt_operation_count", lambda action: count), \
             mock.patch.object(app, "prompt_warmup_count", lambda: warmup_count), \
             redirect_stdout(out), redirect_stderr(err):
            try:
                app.sign_file(1, funcs)
            except app.PKCS11Error as exc:
                error = exc
        return calls, verify_addrs, verify_data, memsets, out.getvalue(), err.getvalue(), error

    def test_base64_output_matches_last_measured_signature_after_retry(self):
        # warmup=1, count=2: op1 retries (B*300), op2 retries as well (the fake
        # token needs 300 bytes, the default RSA capacity is 256) and signs
        # C*300 into its retry buffer. The printed Base64 must be that of the
        # LAST measured signature C*300.
        steps = [
            ("ok", b"A" * 256),
            ("too_small", 300), ("ok", b"B" * 300),
            ("too_small", 300), ("ok", b"C" * 300),
        ]
        calls, verify_addrs, verify_data, memsets, output, err, error = self.run_sign_file(1, 2, steps)
        self.assertIsNone(error)
        self.assertIn("Самопроверка подписи: успешно", output)
        expected = base64.b64encode(b"C" * 300).decode("ascii")
        printed = output.split("Подпись (Base64):")[1]
        self.assertEqual(printed.replace("\n", "").strip(), expected)
        # Self-check verified exactly the last signature (one C_Verify call,
        # signature content B...no: C*300 read from the Base64 source buffer).
        self.assertEqual(len(verify_addrs), 1)
        self.assertEqual(verify_data[-1], b"C" * 300)

    def test_b64encode_receives_buffer_not_bytes(self):
        # Regression detector: without the fix, base64.b64encode was called with
        # an explicit bytes(...) copy of the full signature; now it must receive
        # a memoryview of the wipeable ctypes buffer (bytes input fails the test).
        seen_types = []
        seen_snapshot = []

        orig_b64encode = base64.b64encode

        def spy_b64encode(data, *args, **kwargs):
            seen_types.append(type(data))
            seen_snapshot.append(bytes(memoryview(data)))
            return orig_b64encode(data, *args, **kwargs)

        steps = [("ok", b"S" * 256), ("ok", b"S" * 256)]
        with mock.patch.object(base64, "b64encode", spy_b64encode):
            calls, verify_addrs, verify_data, memsets, output, err, error = self.run_sign_file(1, 1, steps)
        self.assertIsNone(error)
        self.assertEqual(len(seen_types), 1, "b64encode must be called exactly once")
        self.assertIsNot(seen_types[0], bytes, "explicit bytes copy must not be passed")
        self.assertIsNot(seen_types[0], bytearray)
        self.assertEqual(seen_snapshot[0], b"S" * 256)
        expected = base64.b64encode(b"S" * 256).decode("ascii")
        printed = output.split("Подпись (Base64):")[1]
        self.assertEqual(printed.replace("\n", "").strip(), expected)

    def test_self_check_failure_raises_and_wipes_signature_buffers(self):
        # Negative case: C_Verify reports CKR_SIGNATURE_INVALID; sign_file must
        # raise, print the user-facing message, and wipe every signature buffer
        # (the Base64 source buffer included) before propagating.
        steps = [("ok", b"S" * 256), ("ok", b"T" * 256)]
        calls, verify_addrs, verify_data, memsets, output, err, error = self.run_sign_file(
            0, 2, steps, verify_rv=app.CKR_SIGNATURE_INVALID
        )
        self.assertIsNotNone(error)
        self.assertIn("Самопроверка подписи: НЕ УСПЕШНО", err)
        sign_addrs = {addr for kind, addr in calls if kind == "sign"}
        self.assertTrue(sign_addrs, "at least one sign call expected")
        for addr in sign_addrs:
            self.assertIn(addr, memsets, f"signature buffer at {addr} was never wiped")
        # The buffer handed to C_Verify (the Base64 source) must be wiped too.
        self.assertEqual(len(verify_addrs), 1)
        self.assertIn(verify_addrs[0], memsets)

    def test_success_sequence_wipes_all_signature_buffers(self):
        # Multi-operation success sequence with a mid-sequence retry: every
        # signature buffer seen by C_Sign and the final Base64 source buffer
        # must be wiped exactly via finally (no leftover open resources).
        steps = [
            ("ok", b"A" * 256),
            ("too_small", 300), ("ok", b"B" * 300),
            ("too_small", 300), ("ok", b"C" * 300),
        ]
        calls, verify_addrs, verify_data, memsets, output, err, error = self.run_sign_file(1, 2, steps)
        self.assertIsNone(error)
        sign_addrs = {addr for kind, addr in calls if kind == "sign"}
        for addr in sign_addrs:
            self.assertIn(addr, memsets, f"signature buffer at {addr} was never wiped")
        self.assertEqual(len(verify_addrs), 1)
        self.assertIn(verify_addrs[0], memsets, "Base64 source buffer was never wiped")


if __name__ == "__main__":
    unittest.main(verbosity=2)
