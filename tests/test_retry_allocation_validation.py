"""Regression tests: the retry-buffer size reported on CKR_BUFFER_TOO_SMALL
comes from the untrusted module and must be validated BEFORE allocation.

Contract: in encrypt_with_generated_key and sign_once, a module that answers
CKR_BUFFER_TOO_SMALL with an absurd required size — needed == 0 (contradicts
"buffer too small") or needed > MAX_RETRY_OUTPUT_BYTES (e.g. 1 TiB) — must
cause InvalidModuleLengthError before (CK_BYTE * needed)() is attempted.
Previously the value went straight into the allocation: a hostile or buggy
module reporting a huge size triggered MemoryError (an unexpected exception
with a traceback in run_menu) or swap thrash. The v2.12 length checks validate
only the length reported AFTER the successful retry call, so they cannot catch
this.

Normal flows are unaffected: a sane needed (close to the buffer capacity)
still retries and succeeds, multi-operation sequences with mid-sequence
failures keep the single cleanup path (buffers wiped, key destroyed once).
"""
import ctypes
import io
import pathlib
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

import app
from test_file_input_errors import encrypt_funcs, sign_pair_funcs


def run_sign_file(file_path, count, warmup, steps):
    calls = []
    verify_out = []
    funcs = sign_pair_funcs(steps, calls, verify_out)
    inputs = iter([str(file_path), str(count), str(warmup), ""])
    out = io.StringIO()
    err = io.StringIO()
    with mock.patch("builtins.input", lambda *a: next(inputs)), \
            redirect_stdout(out), redirect_stderr(err):
        app.sign_file(1, funcs)
    return out.getvalue()


def run_encrypt_file(file_path, count, warmup, funcs, memsets):
    inputs = iter([str(file_path), str(count), str(warmup), "0", "0"])
    out = io.StringIO()
    err = io.StringIO()
    with mock.patch("builtins.input", lambda *a: next(inputs)), \
            redirect_stdout(out), redirect_stderr(err):
        app.encrypt_file(1, funcs, 1)
    return out.getvalue()


class SignRetryAllocationValidationTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.file_path = pathlib.Path(self.tmpdir.name) / "data.bin"
        self.file_path.write_bytes(b"PLAINTEXT-DATA" * 10)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_sign_rejects_zero_needed_before_allocation(self):
        # warmup(1): первый же C_Sign отвечает TOO_SMALL с needed = 0.
        steps = [("too_small", 0)]
        with self.assertRaises(app.InvalidModuleLengthError) as ctx:
            run_sign_file(self.file_path, 1, 1, steps)
        self.assertIn("некорректную длину подписи для повторного вызова: 0", str(ctx.exception))

    def test_sign_rejects_huge_needed_before_allocation(self):
        # 1 ТиБ: раньше — безусловная аллокация и MemoryError (unexpected).
        huge = (1 << 40) + 7
        steps = [("too_small", huge)]
        out = io.StringIO()
        with mock.patch("builtins.input", side_effect=[str(self.file_path), "1", "1", ""]), \
                redirect_stdout(out), redirect_stderr(io.StringIO()):
            with self.assertRaises(app.InvalidModuleLengthError) as ctx:
                app.sign_file(1, sign_pair_funcs([("too_small", huge)], [], []))
        self.assertIn(str(huge), str(ctx.exception))
        self.assertNotIn("Неожиданная ошибка", out.getvalue())

    def test_sign_huge_needed_second_measured_op_keeps_earlier_results_clean(self):
        # Многошаговая последовательность: warmup ok; measured op1 ok;
        # op2 TOO_SMALL с гигантским needed → InvalidModuleLengthError,
        # статус успеха не печатается.
        huge = 1 << 40
        steps = [
            ("ok", b"\xA1" * 64),
            ("ok", b"\xA2" * 64),
            ("too_small", huge),
        ]
        with self.assertRaises(app.InvalidModuleLengthError) as ctx:
            run_sign_file(self.file_path, 2, 1, steps)
        self.assertIn(str(huge), str(ctx.exception))

    def test_sign_sane_retry_still_works(self):
        # Контрольный: валидный needed (чуть больше ёмкости) — retry успешен.
        steps = [("too_small", 260), ("ok", b"\xB7" * 256)]
        out = run_sign_file(self.file_path, 1, 1, steps)
        self.assertIn("Самопроверка подписи: успешно", out)
        self.assertIn("Подпись (Base64):", out)


class EncryptRetryAllocationValidationTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.file_path = pathlib.Path(self.tmpdir.name) / "data.bin"
        self.file_path.write_bytes(b"PLAINTEXT-DATA" * 10)

    def tearDown(self):
        self.tmpdir.cleanup()

    def _scripted_funcs(self, script):
        """Fake whose C_Encrypt follows a script of ('too_small', n) / ('ok',)."""
        state = {}
        funcs, _memsets = encrypt_funcs([], [], state)
        state["plaintext"] = b"PLAINTEXT-DATA" * 10
        state["call"] = 0

        def encrypt(session, data, size, output, output_length):
            ol = ctypes.cast(output_length, ctypes.POINTER(app.CK_ULONG))
            step = script[state["call"]] if state["call"] < len(script) else ("ok",)
            state["call"] += 1
            if step[0] == "too_small":
                ol[0] = app.CK_ULONG(step[1])
                return app.CKR_BUFFER_TOO_SMALL
            cipher_len = len(state["plaintext"]) + 8
            ctypes.memmove(output, b"\xC1" * cipher_len, cipher_len)
            ol[0] = app.CK_ULONG(cipher_len)
            return app.CKR_OK

        funcs["C_Encrypt"] = encrypt
        return funcs

    def test_encrypt_rejects_zero_needed_before_allocation(self):
        # warmup(1): первый C_Encrypt отвечает TOO_SMALL с needed = 0.
        funcs = self._scripted_funcs([("too_small", 0)])
        with self.assertRaises(app.InvalidModuleLengthError) as ctx:
            run_encrypt_file(self.file_path, 1, 1, funcs, None)
        self.assertIn("некорректную длину шифротекста для повторного вызова: 0", str(ctx.exception))

    def test_encrypt_rejects_huge_needed_before_allocation(self):
        huge = (1 << 40) + 7
        funcs = self._scripted_funcs([("too_small", huge)])
        out = io.StringIO()
        with mock.patch("builtins.input", side_effect=[str(self.file_path), "1", "1", "0", "0"]), \
                redirect_stdout(out), redirect_stderr(io.StringIO()):
            with self.assertRaises(app.InvalidModuleLengthError) as ctx:
                app.encrypt_file(1, funcs, 1)
        self.assertIn(str(huge), str(ctx.exception))
        self.assertNotIn("Неожиданная ошибка", out.getvalue())
        self.assertNotIn("Самопроверка расшифрования: успешно", out.getvalue())

    def test_encrypt_huge_needed_mid_sequence_cleanup_single_key_destroy(self):
        # Многошаговая последовательность: warmup ok; measured op1 ok;
        # op2 TOO_SMALL с гигантским needed. finally обязан затереть все
        # чувствительные буферы и уничтожить временный ключ ровно один раз.
        huge = 1 << 40
        state = {}
        funcs, _ = encrypt_funcs([], [], state)
        state["plaintext"] = b"PLAINTEXT-DATA" * 10
        state["call"] = 0
        destroys = []
        memsets = []
        orig_memset = ctypes.memset

        def tracking_memset(addr, value, size):
            memsets.append(size)
            return orig_memset(addr, value, size)

        def encrypt(session, data, size, output, output_length):
            ol = ctypes.cast(output_length, ctypes.POINTER(app.CK_ULONG))
            state["call"] += 1
            if state["call"] < 3:  # warmup + первый измеряемый вызов: успех
                cipher_len = len(state["plaintext"]) + 8
                ctypes.memmove(output, b"\xC1" * cipher_len, cipher_len)
                ol[0] = app.CK_ULONG(cipher_len)
                return app.CKR_OK
            ol[0] = app.CK_ULONG(huge)
            return app.CKR_BUFFER_TOO_SMALL

        funcs["C_Encrypt"] = encrypt

        def destroy(session, handle):
            destroys.append(_to_h(handle))
            return app.CKR_OK

        funcs["C_DestroyObject"] = destroy
        inputs = iter([str(self.file_path), "2", "1", "0", "0"])
        out = io.StringIO()
        with mock.patch("builtins.input", lambda *a: next(inputs)), \
                mock.patch("ctypes.memset", tracking_memset), \
                redirect_stdout(out), redirect_stderr(io.StringIO()):
            with self.assertRaises(app.InvalidModuleLengthError) as ctx:
                app.encrypt_file(1, funcs, 1)
        self.assertIn(str(huge), str(ctx.exception))
        self.assertEqual(len(destroys), 1)
        # Затёрты как минимум: буфер файла + основной буфер шифротекста.
        self.assertGreaterEqual(len([m for m in memsets if m > 0]), 2)
        self.assertNotIn("Самопроверка расшифрования: успешно", out.getvalue())

    def test_encrypt_sane_retry_still_works(self):
        # Контрольный: валидный retry в encrypt-пути не сломан фиксом
        # (needed = 148 + запас укладывается в потолок; TOO_SMALL на warmup,
        # затем успешный повтор и успешная измеряемая операция).
        state = {}
        funcs, _ = encrypt_funcs([], [("too_small", 200)], state)
        out = run_encrypt_file(self.file_path, 1, 1, funcs, None)
        self.assertIn("Самопроверка расшифрованием: успешно", out)
        self.assertIn("Размер последнего шифротекста:", out)


def _to_h(handle):
    if isinstance(handle, int):
        return handle
    if hasattr(handle, "value"):
        return int(handle.value)
    return int.from_bytes(bytes(handle), "little")


if __name__ == "__main__":
    unittest.main()
