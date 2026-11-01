"""Regression tests: the measured-loop retry buffer must be registered in
sensitive_buffers (the common cleanup list) in encrypt_file.

encrypt_file historically wiped the measured-loop retry buffer through two
ad-hoc memset passes (before the next operation and via an explicit check in
the finally-block) instead of registering it in sensitive_buffers, unlike
sign_file. Any new exit path added to the measured loop could leave the
ciphertext-bearing retry buffer unwiped (the failure mode of commits 2c45d37
and a989316). Now the buffer is appended to sensitive_buffers immediately, so
the single finally-block cleanup loop covers it on every outcome.

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


class EncryptRetryCleanupMembershipTests(unittest.TestCase):
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

    def _wipes(self, events, size):
        """Indices of memset events for buffers of the given size."""
        return [i for i, (_addr, s) in enumerate(events) if s == size]

    def test_retry_buffer_wiped_by_common_cleanup_loop_on_selfcheck_failure(self):
        # Negative case: warmup(1) + measured(1) with retry, then the decrypt
        # self-check fails. The retry buffer (size 4096) must be wiped by the
        # common sensitive_buffers loop, i.e. BEFORE the preview buffer
        # (size 148) that was appended to the list after it. On the old code
        # the retry buffer was wiped by an explicit second pass AFTER the
        # whole list, so this order assertion fails there.
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

        destroys = []
        real_destroy = funcs["C_DestroyObject"]

        def destroy(session, handle):
            destroys.append(_to_int(handle))
            return real_destroy(session, handle)

        funcs["C_DestroyObject"] = destroy

        out, err, error, memsets = self._run(funcs, 1, 1)

        self.assertIsInstance(error, app.SelfCheckError)
        self.assertIn("Самопроверка расшифрования: НЕ УСПЕШНО", err)
        self.assertNotIn("Самопроверка расшифрованием: успешно", out)

        retry_wipes = self._wipes(memsets, 4096)
        preview_wipes = self._wipes(memsets, 148)
        data_wipes = self._wipes(memsets, self.plaintext_len)
        encrypted_wipes = self._wipes(memsets, self.plaintext_len + app.MAX_CIPHERTEXT_OVERHEAD)

        # Resource cleanup on the failure path: every sensitive buffer wiped,
        # the temporary key destroyed exactly once.
        self.assertEqual(len(data_wipes), 1, "plaintext buffer must be wiped once")
        self.assertEqual(len(encrypted_wipes), 1, "ciphertext buffer must be wiped once")
        self.assertGreaterEqual(len(retry_wipes), 1, "retry buffer must be wiped")
        self.assertGreaterEqual(len(preview_wipes), 1, "preview buffer must be wiped")
        self.assertEqual(len(destroys), 1)

        # The detector: retry buffer belongs to the common cleanup list, so it
        # is wiped during the list traversal, before the preview buffer (the
        # last 148-byte wipe: decrypt_and_check wipes its two 148-byte buffers
        # in its own finally, earlier). On the old code the retry buffer was
        # wiped by an explicit second pass AFTER the preview, so this fails.
        self.assertLess(
            retry_wipes[0], preview_wipes[-1],
            "retry buffer was not wiped by the common sensitive_buffers loop",
        )

    def test_retry_buffer_wiped_before_next_operation_and_in_finally(self):
        # Multi-operation success sequence: warmup(1) + measured(2), retry on
        # the first measured operation. The retry buffer must be wiped before
        # the next C_Encrypt starts AND again by the finally-block cleanup
        # (registered in sensitive_buffers), so nothing survives the run.
        calls, state = [], {}
        funcs, memsets = encrypt_funcs(
            calls,
            [("ok", 0), ("too_small", 4096), ("ok", 0), ("ok", 0)],
            state,
        )
        out, err, error, memsets = self._run(funcs, 2, 1)

        self.assertIsNone(error)
        self.assertIn("Самопроверка расшифрованием: успешно", out)
        # Preview must show the ciphertext of the LAST measured operation.
        preview_line = out.split(
            "Последний шифротекст (Base64, первые 256 символов):\n"
        )[1].split("\n")[0]
        self.assertEqual(base64.b64decode(preview_line), b"\xC1" * self.cipher_len)

        retry_wipes = self._wipes(memsets, 4096)
        self.assertGreaterEqual(
            len(retry_wipes), 2,
            "retry buffer must be wiped before the next operation and in the finally-block",
        )

    def test_retry_buffer_wiped_when_next_operation_fails(self):
        # Negative case: retry on measured op 1, then C_EncryptInit of op 2
        # fails. The retry buffer must still be wiped twice (early pass and
        # finally via the common list) and the error must propagate.
        calls, state = [], {}
        funcs, memsets = encrypt_funcs(
            calls,
            [("ok", 0), ("too_small", 4096), ("ok", 0)],
            state,
        )
        init_state = {"n": 0}

        def encrypt_init(session, mechanism, key):
            init_state["n"] += 1
            if init_state["n"] >= 3:  # warmup, m1 — ok; m2 fails
                return 0x00000005  # CKR_FUNCTION_FAILED
            return app.CKR_OK

        funcs["C_EncryptInit"] = encrypt_init

        out, err, error, memsets = self._run(funcs, 2, 1)

        self.assertIsInstance(error, app.PKCS11Error)
        self.assertNotIsInstance(error, app.SelfCheckError)
        self.assertIn("C_EncryptInit", str(error))
        retry_wipes = self._wipes(memsets, 4096)
        self.assertGreaterEqual(
            len(retry_wipes), 2,
            "retry buffer must be wiped even when the next operation fails",
        )


if __name__ == "__main__":
    unittest.main()
