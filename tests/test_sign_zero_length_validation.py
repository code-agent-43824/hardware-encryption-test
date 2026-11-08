"""Regression tests: sign_file must reject a zero ulSignatureLen reported by
the (untrusted) PKCS#11 module together with CKR_OK.

Contract:
- If the module returns CKR_OK with ulSignatureLen == 0 (main signature
  buffer or CKR_BUFFER_TOO_SMALL retry buffer), sign_file must raise
  InvalidModuleLengthError BEFORE the memmove copy and BEFORE C_Verify:
  an empty signature is meaningless for C_Verify, and the module failure
  must not be masked as a routine self-check failure (same "untrusted
  length validated before use" contract as sign_once /
  signature_buffer_length / encrypt_with_generated_key).
- All allocated buffers (data, signature, retry) must still be wiped.
- Normal multi-operation sequences are unaffected.
"""
import ctypes
import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import app
from test_file_input_errors import _to_int, sign_pair_funcs


def zero_sign_lengths(base_funcs):
    """Wrap C_Sign so every successful call reports length 0 (simulating a
    faulty or hostile module)."""
    orig_sign = base_funcs["C_Sign"]

    def zeroing_sign(session, data, size, output, output_length):
        rv = orig_sign(session, data, size, output, output_length)
        if rv == app.CKR_OK:
            ol = ctypes.cast(output_length, ctypes.POINTER(app.CK_ULONG))
            ol[0] = app.CK_ULONG(0)
        return rv

    base_funcs["C_Sign"] = zeroing_sign
    return base_funcs


class SignZeroLengthValidationTests(unittest.TestCase):
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

    def test_zero_length_main_buffer_raises_before_verify(self):
        # Warmup ok; the measured operation returns CKR_OK with length 0.
        # sign_file must fail with InvalidModuleLengthError (not masked as
        # SelfCheckError), must not call C_Verify and must wipe buffers.
        steps = [("ok", b"A" * 256), ("ok", b"B" * 256)]
        verify_out, memsets, output, err, error = self.run_sign_file(
            1, 1, steps, wrap=zero_sign_lengths,
        )
        self.assertIsInstance(error, app.InvalidModuleLengthError)
        self.assertNotIsInstance(error, app.SelfCheckError)
        self.assertIn("некорректную длину подписи", str(error))
        self.assertIn("(ёмкость буфера 256)", str(error))
        self.assertEqual(verify_out, [], "C_Verify must not be called")
        # data buffer (140) and signature buffer (256) wiped in finally
        self.assertIn(140, memsets)
        self.assertIn(256, memsets)

    def test_zero_length_on_retry_buffer_raises_and_wipes_retry(self):
        # Warmup ok; measured operation retries into a 300-byte buffer, then
        # reports length 0. The retry buffer must be wiped even though the
        # zero-length check fails.
        steps = [
            ("ok", b"W" * 256),
            ("too_small", 300), ("ok", b"B" * 300),
        ]
        verify_out, memsets, output, err, error = self.run_sign_file(
            1, 1, steps, wrap=zero_sign_lengths,
        )
        self.assertIsInstance(error, app.InvalidModuleLengthError)
        self.assertNotIsInstance(error, app.SelfCheckError)
        self.assertIn("некорректную длину подписи", str(error))
        self.assertIn("(ёмкость буфера 300)", str(error))
        self.assertEqual(verify_out, [])
        self.assertIn(300, memsets, "retry buffer must be wiped")
        self.assertIn(140, memsets)
        self.assertIn(256, memsets)

    def test_zero_length_after_good_ops_leaves_no_unwiped_buffers(self):
        # Multi-operation sequence: warmup ok, measured op1 ok, op2 zero.
        # Everything allocated so far must be wiped and no C_Verify call
        # must happen.
        steps = [("ok", b"A" * 256), ("ok", b"B" * 256)]
        verify_out, memsets, output, err, error = self.run_sign_file(
            1, 2, steps, wrap=zero_sign_lengths,
        )
        self.assertIsInstance(error, app.InvalidModuleLengthError)
        self.assertIn("некорректную длину подписи", str(error))
        self.assertEqual(verify_out, [])
        self.assertIn(140, memsets)
        self.assertIn(256, memsets)

    def test_normal_multi_op_flow_with_retry_unaffected(self):
        # Control: without the zero-length fault the normal flow (including
        # a retry) still succeeds and verifies the last measured signature.
        steps = [
            ("ok", b"A" * 256),
            ("too_small", 300), ("ok", b"B" * 300),
            ("ok", b"C" * 256),
        ]
        verify_out, memsets, output, err, error = self.run_sign_file(1, 2, steps)
        self.assertIsNone(error)
        self.assertIn("Самопроверка подписи: успешно", output)
        self.assertEqual(verify_out, [b"C" * 256])


if __name__ == "__main__":
    unittest.main()
