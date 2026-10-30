"""Regression tests: encrypt_file must not create an immutable bytes copy of
the ciphertext fragment for the Base64 preview.

Contract:
- The preview is copied into a wipeable ctypes buffer (added to
  sensitive_buffers); base64.b64encode receives that buffer (buffer protocol),
  NOT a bytes(...) copy, which would stay in the heap until GC (same policy as
  sign_file — see tests/test_sign_b64_no_extra_copy.py).
- The printed preview is byte-for-byte the head of the LAST measured ciphertext
  (multi-operation sequence including a CKR_BUFFER_TOO_SMALL retry).
- On self-check failure (decrypted plaintext mismatch) encrypt_file still
  raises SelfCheckError with the user-facing stderr message, and the preview
  buffer is wiped together with the other sensitive buffers.
"""
import base64
import ctypes
import io
import pathlib
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

import app
from test_encrypt_output_contract import encrypt_funcs, _to_int


class EncryptPreviewNoBytesCopyTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.tmpdir.name) / "data.bin"
        self.path.write_bytes(b"PLAINTEXT-DATA" * 10)

    def tearDown(self):
        self.tmpdir.cleanup()

    def run_encrypt_file(self, warmup_count, count, encrypt_steps, decrypt_plain=None):
        """Run encrypt_file. Returns (calls, state, memsets, b64_calls, out,
        err, error) where b64_calls collects (type, address, snapshot) of each
        base64.b64encode argument."""
        calls = []
        state = {}
        b64_calls = []
        orig_memset = ctypes.memset
        memsets = []

        def logging_memset(addr, value, size):
            memsets.append(ctypes.cast(addr, ctypes.c_void_p).value)
            return orig_memset(addr, value, size)

        orig_b64encode = base64.b64encode

        def spy_b64encode(data, *args, **kwargs):
            b64_calls.append(
                (
                    type(data),
                    ctypes.cast(data, ctypes.c_void_p).value,
                    bytes(memoryview(data)),
                )
            )
            return orig_b64encode(data, *args, **kwargs)

        funcs = encrypt_funcs(calls, encrypt_steps, state, decrypt_plain=decrypt_plain)

        inputs = iter([str(self.path)])
        out, err = io.StringIO(), io.StringIO()
        error = None
        with mock.patch.object(ctypes, "memset", logging_memset), \
             mock.patch.object(base64, "b64encode", spy_b64encode), \
             mock.patch("builtins.input", lambda *a: next(inputs)), \
             mock.patch.object(app, "prompt_operation_count", lambda action: count), \
             mock.patch.object(app, "prompt_warmup_count", lambda: warmup_count), \
             mock.patch.object(app, "choose_crypto_mode", lambda: app.CRYPTO_MODES[0]), \
             mock.patch.object(app, "choose_encryption_algorithm", lambda: app.ENCRYPTION_ALGORITHMS[0]), \
             redirect_stdout(out), redirect_stderr(err):
            try:
                app.encrypt_file(1, funcs, 1)
            except app.PKCS11Error as exc:
                error = exc
        return calls, state, memsets, b64_calls, out.getvalue(), err.getvalue(), error

    def test_b64encode_receives_wipeable_buffer_not_bytes(self):
        # Regression detector: without the fix the preview was an explicit
        # bytes(...) copy; base64.b64encode must receive the wipeable ctypes
        # buffer instead.
        steps = [("ok", 0), ("ok", 0)]
        calls, state, memsets, b64_calls, out, err, error = self.run_encrypt_file(1, 1, steps)
        self.assertIsNone(error)
        self.assertEqual(len(b64_calls), 1, "b64encode must be called exactly once")
        self.assertIsNot(b64_calls[0][0], bytes, "explicit bytes preview copy must not be passed")
        self.assertIsNot(b64_calls[0][0], bytearray)
        cipher_len = len(state["plaintext"]) + 8
        expected_head = b"\xC1" * min(cipher_len, app.PREVIEW_CIPHERTEXT_BYTES)
        self.assertEqual(b64_calls[0][2][: len(expected_head)], expected_head)

    def test_preview_buffer_is_wiped_on_success(self):
        # Cleanup: the preview buffer handed to b64encode must be wiped in the
        # finally-block (its address must appear in the memset log).
        steps = [("ok", 0), ("ok", 0)]
        calls, state, memsets, b64_calls, out, err, error = self.run_encrypt_file(1, 1, steps)
        self.assertIsNone(error)
        self.assertEqual(len(b64_calls), 1)
        preview_addr = b64_calls[0][1]
        self.assertIsNotNone(preview_addr)
        self.assertIn(preview_addr, memsets, "preview buffer was never wiped")

    def test_multiop_sequence_preview_matches_last_measured_ciphertext(self):
        # warmup(1) + measured(2): ok, retry(4096)->ok, ok. The printed preview
        # must be the head of the LAST measured ciphertext, not of a warmup or
        # retry-operation buffer, and must survive the finally-block wiping.
        steps = [("ok", 0), ("too_small", 4096), ("ok", 0)]
        calls, state, memsets, b64_calls, out, err, error = self.run_encrypt_file(1, 2, steps)
        self.assertIsNone(error)
        self.assertIn("Самопроверка расшифрованием: успешно", out)
        cipher_len = len(state["plaintext"]) + 8
        expected = base64.b64encode(b"\xC1" * cipher_len).decode("ascii")[:256]
        printed = out.split("Последний шифротекст (Base64, первые 256 символов):\n")[1].split("\n")[0]
        self.assertEqual(printed, expected)
        self.assertEqual(len(b64_calls), 1)
        self.assertIn(b64_calls[0][1], memsets, "preview buffer was never wiped")

    def test_self_check_failure_raises_and_wipes_preview_buffer(self):
        # Negative case: C_Decrypt returns a wrong plaintext; encrypt_file must
        # raise SelfCheckError, print the user-facing stderr message, and still
        # wipe the preview buffer (it was created before the failed check).
        steps = [("ok", 0), ("ok", 0)]
        calls, state, memsets, b64_calls, out, err, error = self.run_encrypt_file(
            0, 1, steps, decrypt_plain=b"WRONG-PLAINTEXT"
        )
        self.assertIsNotNone(error)
        self.assertIsInstance(error, app.SelfCheckError)
        self.assertIn("Самопроверка расшифрования: НЕ УСПЕШНО", err)
        self.assertNotIn("Самопроверка расшифрованием: успешно", out)
        self.assertEqual(len(b64_calls), 1)
        self.assertIn(b64_calls[0][1], memsets, "preview buffer was never wiped")


if __name__ == "__main__":
    unittest.main(verbosity=2)
