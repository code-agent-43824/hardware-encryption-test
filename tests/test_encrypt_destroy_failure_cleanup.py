"""Regression tests: C_DestroyObject failure in encrypt_file's finally block.

Contract (the finally-cleanup branch was previously untested):
- On the SUCCESS path a failed C_DestroyObject must wipe every sensitive
  buffer (plaintext data buffer, main ciphertext buffer, retry buffer,
  Base64 preview buffer) BEFORE raising PKCS11Error("C_DestroyObject(...)");
  no success/benchmark output is printed.
- When the operation itself already failed, the original error must NOT be
  masked: the destroy failure is reported as a warning on stderr, and the
  buffers are still wiped.
- The key is destroyed exactly once, and the contract holds on multi-step
  sequences (warmup + measured operations, including CKR_BUFFER_TOO_SMALL
  retry paths).

Without these guards a regression could silently leave plaintext or
ciphertext in memory, mask the real failure, or destroy the key twice.
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

DESTROY_RV = 0x00000002  # CKR_GENERAL_ERROR: any nonzero code fails the cleanup

FILE_SIZE = 140  # b"PLAINTEXT-DATA" * 10


class EncryptDestroyFailureCleanupTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.file_path = Path(self.tmpdir.name) / "data.bin"
        self.file_path.write_bytes(b"PLAINTEXT-DATA" * 10)

    def tearDown(self):
        self.tmpdir.cleanup()

    def _run_with_failing_destroy(self, steps, init_results=None, destroy_rv=DESTROY_RV):
        """Build scripted funcs whose C_DestroyObject fails; log ctypes.memset calls."""
        events = []
        state = {}
        funcs = encrypt_funcs(events, steps, state, init_results=init_results)
        state["destroys"] = 0

        def failing_destroy(session, handle):
            state["destroys"] += 1
            return destroy_rv

        funcs["C_DestroyObject"] = failing_destroy

        memsets = []
        orig_memset = ctypes.memset

        def logging_memset(addr, value, size):
            memsets.append(
                (ctypes.cast(addr, ctypes.c_void_p).value if not isinstance(addr, int) else addr, size)
            )
            return orig_memset(addr, value, size)

        return funcs, events, state, memsets, logging_memset

    def _call(self, funcs, inputs=None):
        seq = iter(inputs or [str(self.file_path), "2", "1", "0", "0"])
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("builtins.input", lambda *a: next(seq)), \
             redirect_stdout(out), redirect_stderr(err):
            try:
                app.encrypt_file(1, funcs, 1)
                error = None
            except app.PKCS11Error as raised:
                error = raised
        return error, out.getvalue(), err.getvalue()

    def test_destroy_failure_on_success_path_raises_after_wiping_buffers(self):
        # warmup(1) + measured(2), no retries: plain success path.
        funcs, events, state, memsets, logging_memset = self._run_with_failing_destroy(
            [("ok", 0), ("ok", 0)]
        )
        with mock.patch.object(ctypes, "memset", logging_memset):
            error, out, err = self._call(funcs)

        self.assertIsNotNone(error)
        self.assertIn("C_DestroyObject(secret encryption key)", str(error))
        # The key was destroyed exactly once.
        self.assertEqual(state["destroys"], 1)
        # No success output reached the user.
        self.assertNotIn("успешно", out)
        self.assertNotIn("Размер последнего шифротекста", out)
        # All sensitive buffers were wiped before the raise:
        # plaintext data buffer (140), main ciphertext buffer (140+32),
        # Base64 preview buffer (140+8).
        sizes = [size for _, size in memsets]
        self.assertIn(FILE_SIZE, sizes, "plaintext data buffer was not wiped")
        self.assertIn(FILE_SIZE + app.MAX_CIPHERTEXT_OVERHEAD, sizes, "ciphertext buffer was not wiped")
        self.assertIn(FILE_SIZE + 8, sizes, "preview buffer was not wiped")
        main_output_addr = next(entry[1] for entry in events if entry[0] == "encrypt")
        wiped_addrs = {addr for addr, _ in memsets}
        self.assertIn(main_output_addr, wiped_addrs, "main ciphertext buffer address was not wiped")

    def test_destroy_failure_does_not_mask_operation_error(self):
        # First measured C_EncryptInit fails (init #2 after the warmup init).
        funcs, events, state, memsets, logging_memset = self._run_with_failing_destroy(
            [("ok", 0)], init_results=[app.CKR_OK, DESTROY_RV],
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

    def test_destroy_failure_after_retry_sequence_wipes_retry_buffer(self):
        # warmup ok; measured op1: too_small -> retry ok; measured op2..3: ok.
        funcs, events, state, memsets, logging_memset = self._run_with_failing_destroy(
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
