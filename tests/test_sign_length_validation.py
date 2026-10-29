"""Regression tests: sign_file must not trust the ulSignatureLen reported by
the (untrusted) PKCS#11 module.

Contract:
- If the module returns CKR_OK with a signature length greater than the
  capacity of the buffer that actually received the signature (the main
  signature buffer, or the CKR_BUFFER_TOO_SMALL retry buffer), sign_file must
  raise InvalidModuleLengthError with a diagnostic message BEFORE any memmove copy or
  C_Verify call: otherwise ctypes.memmove reads past the end of the signature
  buffer (heap over-read) and C_Verify is invoked with an oversized length,
  causing a native out-of-bounds read inside the module.
- The retry buffer must be wiped even when the length check fails (finally).
- Normal flows are unaffected: a length equal to the buffer capacity is valid,
  multi-operation sequences with retries keep working and the last measured
  signature is verified and printed.
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
from test_file_input_errors import _to_int, sign_pair_funcs


def inflate_sign_lengths(base_funcs, extra):
    """Wrap C_Sign so every successful call reports a length inflated by
    `extra` bytes (simulating a faulty or hostile module)."""
    orig_sign = base_funcs["C_Sign"]

    def inflating_sign(session, data, size, output, output_length):
        rv = orig_sign(session, data, size, output, output_length)
        if rv == app.CKR_OK:
            ol = ctypes.cast(output_length, ctypes.POINTER(app.CK_ULONG))
            ol[0] = app.CK_ULONG(_to_int(ol[0]) + extra)
        return rv

    base_funcs["C_Sign"] = inflating_sign
    return base_funcs


class SignLengthValidationTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.file_path = Path(self.tmpdir.name) / "data.bin"
        self.file_path.write_bytes(b"PLAINTEXT-DATA" * 10)

    def tearDown(self):
        self.tmpdir.cleanup()

    def run_sign_file(self, warmup_count, count, sign_steps, wrap=None):
        """Run sign_file with the shared fake. Returns (verify_out, memsets,
        output, stderr, error)."""
        calls = []
        verify_out = []
        funcs = sign_pair_funcs(sign_steps, calls, verify_out)
        if wrap is not None:
            wrap(funcs)

        orig_memset = ctypes.memset
        memsets = []

        def logging_memset(addr, value, size):
            memsets.append(_to_int(size))
            return orig_memset(addr, value, size)

        inputs = iter([str(self.file_path), ""])
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
        return verify_out, memsets, out.getvalue(), err.getvalue(), error

    def test_inflated_length_no_retry_raises_before_verify(self):
        # RSA capacity is 256; every successful sign reports 256 + 16. The
        # first measured operation must fail with a diagnostic PKCS11Error,
        # C_Verify must not be called and the signature/data buffers wiped.
        steps = [("ok", b"A" * 256), ("ok", b"B" * 256)]
        verify_out, memsets, output, err, error = self.run_sign_file(
            1, 1, steps, wrap=lambda f: inflate_sign_lengths(f, 16),
        )
        self.assertIsInstance(error, app.InvalidModuleLengthError)
        self.assertNotIsInstance(error, app.SelfCheckError)
        self.assertIn("некорректную длину подписи", str(error))
        self.assertIn("272", str(error))
        self.assertEqual(verify_out, [], "C_Verify must not be called")
        # data buffer (140) and signature buffer (256) wiped in finally
        self.assertIn(140, memsets)
        self.assertIn(256, memsets)

    def test_inflated_length_on_retry_buffer_raises_and_wipes_retry(self):
        # Warmup is fine; the measured operation retries into a 300-byte
        # buffer, then reports 300 + 16. The retry buffer must be wiped even
        # though the length check fails.
        steps = [
            ("ok", b"W" * 256),
            ("too_small", 300), ("ok", b"B" * 300),
        ]
        verify_out, memsets, output, err, error = self.run_sign_file(
            1, 1, steps, wrap=lambda f: inflate_sign_lengths(f, 16),
        )
        self.assertIsInstance(error, app.InvalidModuleLengthError)
        self.assertNotIsInstance(error, app.SelfCheckError)
        self.assertIn("316 > ёмкости буфера 300", str(error))
        self.assertEqual(verify_out, [])
        self.assertIn(300, memsets, "retry buffer must be wiped")
        self.assertIn(140, memsets)
        self.assertIn(256, memsets)

    def test_length_equal_to_capacity_still_succeeds(self):
        # A length exactly equal to the buffer capacity is valid: the
        # multi-operation sequence with a retry must keep working and verify
        # the last measured signature.
        steps = [
            ("ok", b"A" * 256),
            ("too_small", 300), ("ok", b"B" * 300),
            ("ok", b"C" * 256),
        ]
        verify_out, memsets, output, err, error = self.run_sign_file(1, 2, steps)
        self.assertIsNone(error)
        self.assertIn("Самопроверка подписи: успешно", output)
        self.assertEqual(verify_out, [b"C" * 256])
        expected = base64.b64encode(b"C" * 256).decode("ascii")
        printed = output.split("Подпись (Base64):")[1]
        self.assertEqual(printed.replace("\n", "").strip(), expected)

    def test_inflated_length_after_good_ops_leaves_no_unwiped_buffers(self):
        # warmup ok, measured op1 ok, op2 inflated: everything allocated so
        # far (data, signature, last-signature copy of op1) must be wiped and
        # no C_Verify call must happen.
        steps = [("ok", b"A" * 256), ("ok", b"B" * 256)]
        verify_out, memsets, output, err, error = self.run_sign_file(
            1, 2, steps, wrap=lambda f: inflate_sign_lengths(f, 1),
        )
        self.assertIsInstance(error, app.InvalidModuleLengthError)
        self.assertIn("257", str(error))
        self.assertEqual(verify_out, [])
        self.assertIn(140, memsets)
        self.assertIn(256, memsets)


if __name__ == "__main__":
    unittest.main()
