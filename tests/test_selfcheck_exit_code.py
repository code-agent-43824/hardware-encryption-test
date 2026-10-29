"""Regression tests: a failed self-check (signature verification in sign_file
or decryption check in encrypt_file) must surface as app.SelfCheckError that
run_menu does NOT swallow, so the process exits with a non-zero code via main.
An invalid output length from the PKCS#11 module is also fatal. Ordinary
PKCS11Error keeps the old behaviour: message in the menu, loop goes on.

The tests also verify that the existing resource cleanup is preserved:
the key is destroyed once and every sensitive buffer is wiped even when the
self-check fails after a full multi-operation sequence (warmup + measured,
including a CKR_BUFFER_TOO_SMALL retry in the sign flow).
"""
import ctypes
import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import app
from test_file_input_errors import _to_int, encrypt_funcs, sign_pair_funcs


_real_memset = ctypes.memset


def logging_memset(memsets):
    def memset(addr, value, size):
        memsets.append(ctypes.cast(addr, ctypes.c_void_p).value)
        return _real_memset(addr, value, size)
    return memset


class EncryptSelfCheckExitCodeTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.file_path = Path(self.tmpdir.name) / "data.bin"
        self.file_path.write_bytes(b"PLAINTEXT-DATA" * 10)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_failure_after_sequence_raises_selfcheck_error_and_cleans_up(self):
        # warmup(1) + measured(2): three encryptions, then the decryption
        # self-check returns a wrong plaintext.
        calls = []
        state = {}
        funcs, memsets = encrypt_funcs(calls, [], state)
        original_decrypt = funcs["C_Decrypt"]

        def decrypt(session, ct, ct_len, pt, pt_len):
            calls.append(("decrypt", ctypes.cast(pt, ctypes.c_void_p).value))
            ctypes.memmove(pt, b"WRONG-PLAINTEXT", 15)
            pl = ctypes.cast(pt_len, ctypes.POINTER(app.CK_ULONG))
            pl[0] = app.CK_ULONG(15)
            return app.CKR_OK

        original_destroy = funcs["C_DestroyObject"]
        destroyed = []

        def destroy(session, handle):
            destroyed.append(_to_int(handle))
            return original_destroy(session, handle)

        funcs["C_Decrypt"] = decrypt
        funcs["C_DestroyObject"] = destroy

        data_addrs = []
        original_encrypt = funcs["C_Encrypt"]

        def encrypt(session, data, size, output, output_length):
            data_addrs.append(ctypes.cast(data, ctypes.c_void_p).value)
            return original_encrypt(session, data, size, output, output_length)

        funcs["C_Encrypt"] = encrypt

        inputs = iter([str(self.file_path), "2", "1", "0", "0"])
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(ctypes, "memset", logging_memset(memsets)), \
                mock.patch("builtins.input", lambda *a: next(inputs)), \
                redirect_stdout(out), redirect_stderr(err):
            with self.assertRaises(app.SelfCheckError) as ctx:
                app.encrypt_file(1, funcs, 1)

        self.assertIsInstance(ctx.exception, app.PKCS11Error)
        self.assertIn("Самопроверка расшифрования не пройдена", str(ctx.exception))
        self.assertIn("Самопроверка расшифрования: НЕ УСПЕШНО", err.getvalue())
        # Multi-operation sequence actually ran before the failure.
        self.assertEqual(len([c for c in calls if c[0] == "encrypt"]), 3)
        self.assertEqual(len([c for c in calls if c[0] == "decrypt"]), 1)
        # Cleanup preserved: the key is destroyed exactly once.
        self.assertEqual(destroyed, [1])
        # Nothing sensitive stays unwiped: input buffer, every encrypt output
        # buffer and every decrypt temp buffer.
        wiped_addrs = set(memsets)
        for addr in data_addrs:
            self.assertIn(addr, wiped_addrs, f"data buffer {addr} was never wiped")
        for _kind, addr in calls:
            self.assertIn(addr, wiped_addrs, f"buffer {addr} was never wiped")


class SignSelfCheckExitCodeTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.file_path = Path(self.tmpdir.name) / "data.bin"
        self.file_path.write_bytes(b"SIGN-ME" * 20)

    def tearDown(self):
        self.tmpdir.cleanup()

    def run_sign_file(self, sign_steps, verify_rv):
        calls = []
        verify_out = []
        funcs = sign_pair_funcs(sign_steps, calls, verify_out)
        orig_verify = funcs["C_Verify"]

        def verify(session, data, data_len, sig, sig_len):
            verify_out.append(ctypes.string_at(sig, _to_int(sig_len)))
            return verify_rv

        funcs["C_Verify"] = verify
        memsets = []
        inputs = iter([str(self.file_path), "0"])
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(ctypes, "memset", logging_memset(memsets)), \
                mock.patch("builtins.input", lambda *a: next(inputs)), \
                mock.patch.object(app, "prompt_operation_count", lambda action: 2), \
                mock.patch.object(app, "prompt_warmup_count", lambda: 1), \
                redirect_stdout(out), redirect_stderr(err):
            try:
                app.sign_file(1, funcs)
                error = None
            except app.PKCS11Error as exc:
                error = exc
        return calls, memsets, out.getvalue(), err.getvalue(), error

    def test_invalid_signature_raises_selfcheck_error_after_retry_sequence(self):
        # warmup(1, ok) + measured(2: too_small retry then ok) then C_Verify
        # reports the signature as invalid.
        calls, memsets, out, err, error = self.run_sign_file(
            [("ok", b"S" * 256), ("too_small", 300), ("ok", b"S" * 300)],
            app.CKR_SIGNATURE_INVALID,
        )
        self.assertIsInstance(error, app.SelfCheckError)
        self.assertIn("Самопроверка подписи не выполнена", str(error))
        self.assertIn("Самопроверка подписи: НЕ УСПЕШНО", err)
        # Multi-operation sequence with a retry actually ran.
        self.assertEqual(len([c for c in calls if c[0] == "sign"]), 4)
        # Every sign output buffer (main + retry buffers) was wiped.
        wiped_addrs = set(memsets)
        for _kind, addr in calls:
            self.assertIn(addr, wiped_addrs, f"signature buffer {addr} was never wiped")


class RunMenuExitCodeTests(unittest.TestCase):
    def test_invalid_module_length_exits_main_with_code_one(self):
        # Both menu actions must propagate a malformed module result to main;
        # otherwise a subsequent normal menu exit would return code 0.
        with tempfile.TemporaryDirectory() as directory:
            library_path = Path(directory) / "module.so"
            library_path.touch()
            for choice in ("4", "5"):
                with self.subTest(choice=choice):
                    out = io.StringIO()
                    with mock.patch.object(app.platform, "system", return_value="Linux"), \
                            mock.patch("builtins.input", return_value=""), \
                            mock.patch.object(app, "default_library_path", return_value=library_path), \
                            mock.patch.object(app, "resolve_library_path", return_value=library_path), \
                            mock.patch.object(app, "load_library", return_value=object()), \
                            mock.patch.object(app, "prepare_functions", return_value={}), \
                            mock.patch.object(app, "initialize_pkcs11", return_value=False), \
                            mock.patch.object(app, "print_library_info"), \
                            mock.patch.object(app, "get_token_slots", return_value=[1]), \
                            mock.patch.object(app, "choose_token_slot", return_value=1), \
                            mock.patch.object(app, "print_token_info"), \
                            mock.patch.object(app, "show_menu", side_effect=[choice, "0"]) as menu, \
                            mock.patch.object(app, "run_with_session",
                                              side_effect=app.InvalidModuleLengthError("bad length")), \
                            redirect_stdout(out):
                        self.assertEqual(app.main(), 1)
                    self.assertIn("Ошибка: bad length", out.getvalue())
                    self.assertEqual(menu.call_count, 1)

    def test_selfcheck_error_escapes_run_menu(self):
        # The menu must not swallow a failed self-check: the exception has to
        # reach main, which returns exit code 1.
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(app, "show_menu", side_effect=["5", "0"]), \
                mock.patch.object(app, "run_with_session",
                                  side_effect=app.SelfCheckError("bad self-check")), \
                redirect_stdout(out), redirect_stderr(err):
            with self.assertRaises(app.SelfCheckError):
                app.run_menu({}, 1)
        self.assertNotIn("Ошибка: bad self-check", out.getvalue())

    def test_plain_pkcs11_error_still_keeps_menu_running(self):
        # Ordinary PKCS11Error keeps the old behaviour: printed, menu continues.
        out, err = io.StringIO(), io.StringIO()
        calls = []
        def fake_action(funcs, slot_id, action, **kwargs):
            calls.append(1)
            raise app.PKCS11Error("wrong pin")

        with mock.patch.object(app, "show_menu", side_effect=["5", "0"]), \
                mock.patch.object(app, "run_with_session", fake_action), \
                redirect_stdout(out), redirect_stderr(err):
            app.run_menu({}, 1)  # must not raise
        self.assertEqual(len(calls), 1)
        self.assertIn("Ошибка: wrong pin", out.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
