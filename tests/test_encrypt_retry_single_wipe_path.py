"""Regression tests: the measured-loop retry buffer in encrypt_file must be
wiped through the single common cleanup path (sensitive_buffers membership).

The retry buffer is registered in sensitive_buffers immediately after it is
produced, and the finally-block wipes every registered buffer exactly once.
A redundant ad-hoc memset of the retry_buffer variable in the same
finally-block duplicated the common wipe whenever the LAST measured operation
produced a retry buffer (retry_buffer was still non-None at that point). The
duplicate suggested that the buffer might not belong to the common list — the
drift that produced the failure mode of commits 2c45d37/a989316. These tests
lock the single-wipe contract: on every exit path the final retry buffer is
memset exactly once, and all other cleanup guarantees still hold.

Buffer sizes are unique per run (plaintext=140, encrypted=172, retry=4096,
preview=148), so memset log entries identify each buffer.
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
from test_file_input_errors import _to_int, encrypt_funcs


class EncryptRetrySingleWipePathTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tmpdir.name) / "data.bin"
        self.path.write_bytes(b"PLAINTEXT-DATA" * 10)
        self.plaintext_len = 140
        self.cipher_len = self.plaintext_len + 8

    def tearDown(self):
        self.tmpdir.cleanup()

    def _run(self, funcs, count, warmup):
        events, orig_memset = [], ctypes.memset

        def logging_memset(addr, value, size):
            addr_value = addr if isinstance(addr, int) else ctypes.cast(addr, ctypes.c_void_p).value
            events.append((addr_value, size))
            return orig_memset(addr, value, size)

        inputs = iter([str(self.path), str(count), str(warmup), "0", "0"])
        out, err = io.StringIO(), io.StringIO()
        error = None
        with mock.patch.object(ctypes, "memset", logging_memset), \
             mock.patch("builtins.input", lambda *a: next(inputs)), \
             redirect_stdout(out), redirect_stderr(err):
            try:
                app.encrypt_file(1, funcs, 1)
            except app.PKCS11Error as exc:
                error = exc
        return out.getvalue(), err.getvalue(), error, events

    def _wipes(self, memsets, size):
        """Indices of memset events for buffers of the given size."""
        return [i for i, (_addr, s) in enumerate(memsets) if s == size]

    def _track_destroys(self, funcs):
        destroys = []
        real_destroy = funcs["C_DestroyObject"]

        def destroy(session, handle):
            destroys.append(_to_int(handle))
            return real_destroy(session, handle)

        funcs["C_DestroyObject"] = destroy
        return destroys

    def test_final_retry_buffer_wiped_exactly_once_on_success(self):
        # Multi-operation success sequence: warmup(1) + measured(2), retry
        # (CKR_BUFFER_TOO_SMALL) on the LAST measured operation. The retry
        # buffer belongs to sensitive_buffers, so the common finally-loop
        # wipes it exactly once; a duplicate ad-hoc wipe of the retry_buffer
        # variable in the same finally-block would make this count 2.
        calls, state = [], {}
        funcs, memsets = encrypt_funcs(
            calls,
            [("ok", 0), ("ok", 0), ("too_small", 4096), ("ok", 0)],
            state,
        )
        destroys = self._track_destroys(funcs)

        out, err, error, memsets = self._run(funcs, 2, 1)

        self.assertIsNone(error)
        self.assertIn("Самопроверка расшифрованием: успешно", out)
        # The preview must show the ciphertext of the last measured operation,
        # which was written into the retry buffer.
        preview_line = out.split(
            "Последний шифротекст (Base64, первые 256 символов):\n"
        )[1].split("\n")[0]
        self.assertEqual(base64.b64decode(preview_line), b"\xC1" * self.cipher_len)

        retry_wipes = self._wipes(memsets, 4096)
        self.assertEqual(
            len(retry_wipes), 1,
            "final retry buffer must be wiped exactly once via the common cleanup list",
        )
        # Resource cleanup: temporary key destroyed exactly once.
        self.assertEqual(len(destroys), 1)

    def test_final_retry_buffer_wiped_exactly_once_on_selfcheck_failure(self):
        # Negative case: warmup(1) + measured(1) with retry, then the decrypt
        # self-check fails. The error must surface as SelfCheckError with a
        # stderr message, no success status, and every sensitive buffer must
        # still be wiped; the retry buffer exactly once (single path).
        calls, state = [], {}
        funcs, memsets = encrypt_funcs(
            calls,
            [("ok", 0), ("too_small", 4096), ("ok", 0)],
            state,
        )
        decrypt_plain = b"\xFF" * self.cipher_len

        def decrypt_failure(session, ct, ct_len, pt, pt_len):
            ctypes.memmove(pt, decrypt_plain, len(decrypt_plain))
            pl = ctypes.cast(pt_len, ctypes.POINTER(app.CK_ULONG))
            pl[0] = app.CK_ULONG(len(decrypt_plain))
            return app.CKR_OK

        funcs["C_Decrypt"] = decrypt_failure
        destroys = self._track_destroys(funcs)

        out, err, error, memsets = self._run(funcs, 1, 1)

        self.assertIsInstance(error, app.SelfCheckError)
        self.assertIn("Самопроверка расшифрования: НЕ УСПЕШНО", err)
        self.assertNotIn("Самопроверка расшифрованием: успешно", out)

        data_wipes = self._wipes(memsets, self.plaintext_len)
        encrypted_wipes = self._wipes(memsets, self.plaintext_len + app.MAX_CIPHERTEXT_OVERHEAD)
        retry_wipes = self._wipes(memsets, 4096)
        self.assertEqual(len(data_wipes), 1, "plaintext buffer must be wiped once")
        self.assertEqual(len(encrypted_wipes), 1, "ciphertext buffer must be wiped once")
        self.assertEqual(
            len(retry_wipes), 1,
            "final retry buffer must be wiped exactly once via the common cleanup list",
        )
        self.assertEqual(len(destroys), 1, "temporary key must be destroyed exactly once")

    def test_mid_sequence_retry_buffer_wiped_exactly_once_total(self):
        # Multi-step: retry on measured op 1, success on op 2 (last). The
        # retry buffer must be wiped once before the next operation starts
        # and NOT wiped a second time by the finally-block: it is registered
        # in sensitive_buffers, but the proactive pre-operation wipe already
        # cleared it, so the common loop must be the only other touch.
        calls, state = [], {}
        funcs, memsets = encrypt_funcs(
            calls,
            [("ok", 0), ("too_small", 4096), ("ok", 0), ("ok", 0)],
            state,
        )
        destroys = self._track_destroys(funcs)

        out, err, error, memsets = self._run(funcs, 2, 1)

        self.assertIsNone(error)
        self.assertIn("Самопроверка расшифрованием: успешно", out)
        retry_wipes = self._wipes(memsets, 4096)
        self.assertEqual(
            len(retry_wipes), 2,
            "mid-sequence retry buffer: pre-operation wipe + common finally wipe, nothing else",
        )
        self.assertEqual(len(destroys), 1)


if __name__ == "__main__":
    unittest.main()
