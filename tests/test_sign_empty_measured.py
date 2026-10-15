"""Regression tests: sign_file must fail fast when no measured operations remain.

encrypt_file guards against an empty measured-operations list; sign_file did
not, silently "succeeding" with zero operations, an empty signature and a
self-check against a zero-length signature. These tests monkeypatch
app.prompt_operation_count to return 0 (bypassing the 1..10000 input loop,
e.g. a programmatic call) and require a clear PKCS11Error after warmup, with
no self-check attempt and all signature buffers wiped.
"""
import ctypes
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import app
from test_file_input_errors import sign_pair_funcs


class SignFileEmptyMeasuredTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.file_path = Path(self.tmpdir.name) / "data.bin"
        self.file_path.write_bytes(b"PLAINTEXT-DATA" * 10)

    def tearDown(self):
        self.tmpdir.cleanup()

    def run_sign_file(self, warmup_count, sign_steps):
        """Run sign_file with count=0 (prompt bypassed). Returns a tuple
        (calls, verify_out, memsets, output, error) where error is the caught
        exception or None."""
        calls = []
        verify_out = []
        funcs = sign_pair_funcs(sign_steps, calls, verify_out)
        orig_memset = ctypes.memset
        memsets = []

        def logging_memset(addr, value, size):
            memsets.append(ctypes.cast(addr, ctypes.c_void_p).value)
            return orig_memset(addr, value, size)

        inputs = iter([str(self.file_path), str(warmup_count), ""])
        out = io.StringIO()
        error = None
        with mock.patch.object(ctypes, "memset", logging_memset), \
             mock.patch("builtins.input", lambda *a: next(inputs)), \
             mock.patch.object(app, "prompt_operation_count", lambda action: 0), \
             redirect_stdout(out):
            try:
                app.sign_file(1, funcs)
            except BaseException as exc:  # noqa: BLE001 - recorded, re-raised by callers via assert
                error = exc
        return calls, verify_out, memsets, out.getvalue(), error

    def test_zero_count_raises_clear_error_after_warmup(self):
        # warmup=1: the warmup sign runs, then the empty measured list must
        # raise PKCS11Error instead of a silent zero-operation "success".
        calls, verify_out, memsets, output, error = self.run_sign_file(1, [("ok", b"S" * 256)])
        self.assertIsInstance(error, app.PKCS11Error)
        self.assertIn("Нет ни одной операции подписания", str(error))
        sign_calls = [c for c in calls if c[0] == "sign"]
        self.assertEqual(len(sign_calls), 1, "only the warmup sign must run")
        self.assertEqual(verify_out, [], "self-check must not run with an empty signature")

    def test_warmup_signature_buffer_is_wiped_on_failure(self):
        calls, verify_out, memsets, output, error = self.run_sign_file(1, [("ok", b"S" * 256)])
        self.assertIsInstance(error, app.PKCS11Error)
        for entry in calls:
            if entry[0] == "sign":
                self.assertIn(entry[1], memsets, f"signature buffer at {entry[1]} was never wiped")

    def test_multiple_warmup_operations_then_error(self):
        # warmup=2: a multi-operation sequence (with a mid-sequence retry)
        # still stops cleanly with the clear error and wiped buffers.
        calls, verify_out, memsets, output, error = self.run_sign_file(
            2, [("ok", b"A" * 256), ("too_small", 300), ("ok", b"B" * 300)]
        )
        self.assertIsInstance(error, app.PKCS11Error)
        sign_calls = [c for c in calls if c[0] == "sign"]
        self.assertEqual(len(sign_calls), 3, "warmup sequence (including retry) must complete")
        self.assertEqual(verify_out, [])
        for entry in sign_calls:
            self.assertIn(entry[1], memsets, f"signature buffer at {entry[1]} was never wiped")


if __name__ == "__main__":
    unittest.main(verbosity=2)
