"""Regression tests: a C_DestroyObject that RAISES instead of returning
a CK_RV must not break encrypt_file's finally-cleanup.

The finally-block wipes sensitive buffers AFTER destroying the key, using
the deferred cleanup_error mechanism so the wipe runs on every exit path.
That contract only works if the destroy call cannot skip the wipe loop with
its own exception: a broken binding / funcs wrapper may raise instead of
returning CK_RV. Previously such an exception aborted the finally-block
before the memset loop, leaving the plaintext, ciphertext, retry and preview
buffers unwiped and masking the original operation error.

Contract:
- The destroy exception is converted into cleanup_error (same channel as a
  nonzero CK_RV); the key-destroy attempt happens exactly once.
- Every sensitive buffer is wiped on every exit path (success path raises
  PKCS11Error mentioning C_DestroyObject AFTER the wipe; operation-failure
  path propagates the ORIGINAL error and reports the cleanup failure as a
  stderr warning).
- Holds on multi-step sequences, including CKR_BUFFER_TOO_SMALL retries.
"""
import ctypes
import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import app
from test_encrypt_retry_wipe_order import encrypt_funcs

FILE_SIZE = 140  # b"PLAINTEXT-DATA" * 10


class EncryptDestroyExceptionCleanupTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.file_path = Path(self.tmpdir.name) / "data.bin"
        self.file_path.write_bytes(b"PLAINTEXT-DATA" * 10)

    def tearDown(self):
        self.tmpdir.cleanup()

    def _run_with_raising_destroy(self, steps, init_results=None):
        """Build scripted funcs whose C_DestroyObject raises; log ctypes.memset."""
        events = []
        state = {}
        funcs = encrypt_funcs(events, steps, state, init_results=init_results)
        state["destroys"] = 0

        def raising_destroy(session, handle):
            state["destroys"] += 1
            raise RuntimeError("binding blew up")

        funcs["C_DestroyObject"] = raising_destroy

        memsets = []
        orig_memset = ctypes.memset

        def logging_memset(addr, value, size):
            memsets.append(
                (ctypes.cast(addr, ctypes.c_void_p).value if not isinstance(addr, int) else addr, size)
            )
            return orig_memset(addr, value, size)

        return funcs, events, state, memsets, logging_memset

    def _call(self, funcs):
        seq = iter([str(self.file_path), "2", "1", "0", "0"])
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("builtins.input", lambda *a: next(seq)), \
             redirect_stdout(out), redirect_stderr(err):
            try:
                app.encrypt_file(1, funcs, 1)
                error = None
            except BaseException as raised:
                error = raised
        return error, out.getvalue(), err.getvalue()

    def test_raising_destroy_on_success_path_raises_after_wiping_buffers(self):
        # warmup(1) + measured(2), no retries: plain success path.
        funcs, events, state, memsets, logging_memset = self._run_with_raising_destroy(
            [("ok", 0), ("ok", 0)]
        )
        with mock.patch.object(ctypes, "memset", logging_memset):
            error, out, err = self._call(funcs)

        # The RuntimeError must NOT surface: it is converted into a
        # PKCS11Error mentioning C_DestroyObject.
        self.assertIsNotNone(error)
        self.assertIsInstance(error, app.PKCS11Error)
        self.assertNotIsInstance(error, RuntimeError)
        self.assertIn("C_DestroyObject(secret encryption key)", str(error))
        self.assertIn("binding blew up", str(error))
        # The key-destroy was attempted exactly once (no re-raise loops).
        self.assertEqual(state["destroys"], 1)
        # No success/benchmark output reached the user.
        self.assertNotIn("успешно", out)
        self.assertNotIn("Размер последнего шифротекста", out)
        # All sensitive buffers wiped BEFORE the raise:
        # plaintext data buffer (140), main ciphertext buffer (140+32),
        # Base64 preview buffer (140+8).
        sizes = [size for _, size in memsets]
        self.assertIn(FILE_SIZE, sizes, "plaintext data buffer was not wiped")
        self.assertIn(FILE_SIZE + app.MAX_CIPHERTEXT_OVERHEAD, sizes, "ciphertext buffer was not wiped")
        self.assertIn(FILE_SIZE + 8, sizes, "preview buffer was not wiped")
        main_output_addr = next(entry[1] for entry in events if entry[0] == "encrypt")
        wiped_addrs = {addr for addr, _ in memsets}
        self.assertIn(main_output_addr, wiped_addrs, "main ciphertext buffer address was not wiped")

    def test_raising_destroy_does_not_mask_operation_error(self):
        # First measured C_EncryptInit fails (init #2 after the warmup init).
        funcs, events, state, memsets, logging_memset = self._run_with_raising_destroy(
            [("ok", 0)], init_results=[app.CKR_OK, app.CKR_SESSION_HANDLE_INVALID],
        )
        with mock.patch.object(ctypes, "memset", logging_memset):
            error, out, err = self._call(funcs)

        # The ORIGINAL operation error propagates, not the cleanup failure.
        self.assertIsNotNone(error)
        self.assertIn("C_EncryptInit", str(error))
        self.assertNotIn("C_DestroyObject", str(error))
        # The cleanup failure is reported as a warning on stderr...
        self.assertIn("Предупреждение при очистке после исходной ошибки", err)
        self.assertIn("C_DestroyObject", err)
        # ...and the plaintext buffer is still wiped.
        self.assertIn(FILE_SIZE, [size for _, size in memsets], "data buffer was not wiped")
        self.assertEqual(state["destroys"], 1)

    def test_raising_destroy_after_retry_sequence_wipes_retry_buffer(self):
        # warmup ok; measured op1: too_small -> retry ok; measured op2..3: ok.
        funcs, events, state, memsets, logging_memset = self._run_with_raising_destroy(
            [("ok", 0), ("too_small", 4096), ("ok", 0), ("ok", 0)]
        )
        with mock.patch.object(ctypes, "memset", logging_memset):
            error, out, err = self._call(funcs)

        self.assertIsNotNone(error)
        self.assertIn("C_DestroyObject(secret encryption key)", str(error))
        self.assertEqual(state["destroys"], 1)
        self.assertNotIn("успешно", out)
        # Encrypt calls: warmup(main), op1 too_small(main), op1 retry(retry_buf),
        # op2(main). The retry buffer address must be wiped.
        encrypt_addrs = [entry[1] for entry in events if entry[0] == "encrypt"]
        self.assertEqual(len(encrypt_addrs), 4)
        retry_addr = encrypt_addrs[2]
        main_addr = encrypt_addrs[0]
        self.assertNotEqual(retry_addr, main_addr)
        wiped_addrs = {addr for addr, _ in memsets}
        self.assertIn(retry_addr, wiped_addrs, "retry buffer was not wiped")
        self.assertIn(main_addr, wiped_addrs, "main ciphertext buffer was not wiped")


if __name__ == "__main__":
    unittest.main()
