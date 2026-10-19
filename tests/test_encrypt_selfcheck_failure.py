"""Regression tests: a failed decryption self-check in encrypt_file must be
reported explicitly to stderr (consistent with sign_file) and re-raised,
while cleanup still destroys the secret key and wipes every sensitive buffer,
even after a full multi-operation sequence (warmup + measured).
"""
import ctypes
import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import app
from test_file_input_errors import _to_int, encrypt_funcs


class SelfCheckFailureTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.file_path = Path(self.tmpdir.name) / "data.bin"
        self.file_path.write_bytes(b"PLAINTEXT-DATA" * 10)

    def tearDown(self):
        self.tmpdir.cleanup()

    def make_funcs(self, decrypt_behavior, decrypt_payload, calls, state):
        """decrypt_behavior: 'fail' — C_Decrypt возвращает rv=5 после записи
        decrypt_payload; 'mismatch' — возвращает расшифрованный decrypt_payload
        (не совпадающий с открытым текстом); 'ok' — восстанавливает исходный
        открытый текст (самопроверка проходит)."""
        funcs, memsets = encrypt_funcs(calls, [], state)
        original_decrypt = funcs["C_Decrypt"]

        def decrypt(session, ct, ct_len, pt, pt_len):
            calls.append(("decrypt", ctypes.cast(pt, ctypes.c_void_p).value))
            if decrypt_behavior == "fail":
                if decrypt_payload is not None:
                    ctypes.memmove(pt, decrypt_payload, len(decrypt_payload))
                    pl = ctypes.cast(pt_len, ctypes.POINTER(app.CK_ULONG))
                    pl[0] = app.CK_ULONG(len(decrypt_payload))
                return 5
            if decrypt_behavior == "mismatch":
                ctypes.memmove(pt, decrypt_payload, len(decrypt_payload))
                pl = ctypes.cast(pt_len, ctypes.POINTER(app.CK_ULONG))
                pl[0] = app.CK_ULONG(len(decrypt_payload))
                return app.CKR_OK
            return original_decrypt(session, ct, ct_len, pt, pt_len)

        original_destroy = funcs["C_DestroyObject"]
        destroyed = []

        def destroy(session, handle):
            destroyed.append(_to_int(handle))
            return original_destroy(session, handle)

        funcs["C_Decrypt"] = decrypt
        funcs["C_DestroyObject"] = destroy
        return funcs, memsets, destroyed

    def test_mismatch_reports_to_stderr_and_reraises(self):
        calls = []
        state = {}
        funcs, memsets, destroyed = self.make_funcs(
            "mismatch", b"WRONG-PLAINTEXT", calls, state
        )
        inputs = iter([str(self.file_path), "2", "1", "0", "0"])
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("builtins.input", lambda *a: next(inputs)), \
                redirect_stdout(out), redirect_stderr(err):
            with self.assertRaises(app.PKCS11Error):
                app.encrypt_file(1, funcs, 1)
        self.assertIn("Самопроверка расшифрования: НЕ УСПЕШНО", err.getvalue())

    def test_decrypt_error_reports_to_stderr_and_reraises(self):
        calls = []
        state = {}
        funcs, memsets, destroyed = self.make_funcs("fail", b"SECRET", calls, state)
        inputs = iter([str(self.file_path), "2", "1", "0", "0"])
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("builtins.input", lambda *a: next(inputs)), \
                redirect_stdout(out), redirect_stderr(err):
            with self.assertRaises(app.PKCS11Error):
                app.encrypt_file(1, funcs, 1)
        self.assertIn("Самопроверка расшифрования: НЕ УСПЕШНО", err.getvalue())
        self.assertEqual(destroyed, [1])

    def test_failure_after_sequence_wipes_buffers_and_destroys_key(self):
        # warmup(1) + measured(2): three encryptions, then a failing self-check.
        calls = []
        state = {}
        funcs, memsets, destroyed = self.make_funcs("fail", b"SECRET", calls, state)
        data_addrs = []
        original_encrypt = funcs["C_Encrypt"]

        def encrypt(session, data, size, output, output_length):
            data_addrs.append(ctypes.cast(data, ctypes.c_void_p).value)
            return original_encrypt(session, data, size, output, output_length)

        funcs["C_Encrypt"] = encrypt
        inputs = iter([str(self.file_path), "2", "1", "0", "0"])
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(ctypes, "memset",
                               lambda a, v, s: memsets.append(
                                   (ctypes.cast(a, ctypes.c_void_p).value, s))
                               or _real_memset(a, v, s)), \
                mock.patch("builtins.input", lambda *a: next(inputs)), \
                redirect_stdout(out), redirect_stderr(err):
            with self.assertRaises(app.PKCS11Error):
                app.encrypt_file(1, funcs, 1)

        self.assertEqual(len([c for c in calls if c[0] == "encrypt"]), 3)
        self.assertEqual(len([c for c in calls if c[0] == "decrypt"]), 1)
        # The secret key is destroyed exactly once despite the failure.
        self.assertEqual(destroyed, [1])
        # Every buffer that held plaintext or ciphertext was wiped: the input
        # buffer, each encrypt output buffer, and the decrypt temp buffers.
        wiped_addrs = {addr for addr, _size in memsets}
        for addr in data_addrs:
            self.assertIn(addr, wiped_addrs, f"data buffer {addr} was never wiped")
        for kind, addr in calls:
            self.assertIn(addr, wiped_addrs, f"{kind} buffer {addr} was never wiped")

    def test_success_path_prints_no_stderr_warning(self):
        calls = []
        state = {}
        funcs, memsets, destroyed = self.make_funcs(
            "ok", None, calls, state
        )
        inputs = iter([str(self.file_path), "2", "1", "0", "0"])
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("builtins.input", lambda *a: next(inputs)), \
                redirect_stdout(out), redirect_stderr(err):
            app.encrypt_file(1, funcs, 1)  # must not raise
        self.assertIn("Самопроверка расшифрованием: успешно", out.getvalue())
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(destroyed, [1])


_real_memset = ctypes.memset

if __name__ == "__main__":
    unittest.main(verbosity=2)
