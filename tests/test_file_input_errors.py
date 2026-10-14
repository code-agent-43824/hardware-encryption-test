"""Tests for user-facing file input errors in encrypt_file/sign_file
and for multi-operation flows (warmup + measured + CKR_BUFFER_TOO_SMALL retry).
"""
import base64
import ctypes
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import app


def _to_int(v):
    if isinstance(v, int):
        return v
    if hasattr(v, "value"):
        return int(v.value)
    return int.from_bytes(bytes(v), "little")


def ulong_bytes(v):
    return bytes(app.CK_ULONG(v))


def sign_pair_funcs(sign_steps, calls, verify_out):
    """Minimal fake PKCS#11 for sign_file: one RSA key pair, scripted C_Sign.

    sign_steps: list of ('ok', payload) / ('too_small', needed) per C_Sign call.
    calls: list that receives ('sign', buffer_addr) for every C_Sign output buffer.
    """
    attrs = {
        1: {app.CKA_ID: b"\x01", app.CKA_LABEL: b"K", app.CKA_KEY_TYPE: ulong_bytes(app.CKK_RSA)},
        2: {app.CKA_ID: b"\x01", app.CKA_LABEL: b"K", app.CKA_KEY_TYPE: ulong_bytes(app.CKK_RSA)},
    }
    state = {"class": None, "batch": 0, "step": 0}

    def get_attr_value(session, handle, template, count):
        for i in range(_to_int(count)):
            t = template[i]
            v = attrs.get(_to_int(handle), {}).get(_to_int(t.type))
            if v is None:
                return app.CKR_ATTRIBUTE_TYPE_INVALID
            t.ulValueLen = app.CK_ULONG(len(v))
            if t.pValue:
                ctypes.memmove(t.pValue, v, len(v))
        return app.CKR_OK

    def find_init(session, template, count):
        state["class"] = None
        for i in range(_to_int(count)):
            if _to_int(template[i].type) == 0 and template[i].pValue:  # CKA_CLASS
                state["class"] = ctypes.cast(template[i].pValue, ctypes.POINTER(app.CK_ULONG)).contents.value
        state["batch"] = 0
        return app.CKR_OK

    def find(session, phObject, max_count, pulCount):
        pul = ctypes.cast(pulCount, ctypes.POINTER(app.CK_ULONG))
        state["batch"] += 1
        if state["batch"] == 1 and state["class"] in (app.CKO_PUBLIC_KEY, app.CKO_PRIVATE_KEY):
            handle = 1 if state["class"] == app.CKO_PUBLIC_KEY else 2
            handles = (app.CK_OBJECT_HANDLE * 1)(handle)
            ctypes.memmove(phObject, handles, ctypes.sizeof(handles))
            pul[0] = app.CK_ULONG(1)
        else:
            pul[0] = app.CK_ULONG(0)
        return app.CKR_OK

    def sign(session, data, size, output, output_length):
        addr = ctypes.cast(output, ctypes.c_void_p).value
        calls.append(("sign", addr))
        step = sign_steps[state["step"]] if state["step"] < len(sign_steps) else ("ok", b"X" * 256)
        state["step"] += 1
        ol = ctypes.cast(output_length, ctypes.POINTER(app.CK_ULONG))
        if step[0] == "too_small":
            ol[0] = app.CK_ULONG(step[1])
            return app.CKR_BUFFER_TOO_SMALL
        payload = step[1]
        ctypes.memmove(output, payload, len(payload))
        ol[0] = app.CK_ULONG(len(payload))
        return app.CKR_OK

    def verify(session, data, data_len, sig, sig_len):
        verify_out.append(ctypes.string_at(sig, _to_int(sig_len)))
        return app.CKR_OK

    return {
        "C_FindObjectsInit": find_init,
        "C_FindObjects": find,
        "C_FindObjectsFinal": lambda *_: app.CKR_OK,
        "C_GetAttributeValue": get_attr_value,
        "C_SignInit": lambda *_: app.CKR_OK,
        "C_Sign": sign,
        "C_VerifyInit": lambda *_: app.CKR_OK,
        "C_Verify": verify,
        "C_DestroyObject": lambda *_: app.CKR_OK,
    }


def encrypt_funcs(calls, encrypt_steps, state):
    """Minimal fake PKCS#11 for encrypt_file in software mode (Magma)."""
    orig_memset = ctypes.memset
    memsets = []

    def logging_memset(addr, value, size):
        memsets.append((ctypes.cast(addr, ctypes.c_void_p).value if not isinstance(addr, int) else addr, size))
        return orig_memset(addr, value, size)

    def generate_random(session, buf, size):
        n = _to_int(size)
        ctypes.memmove(buf, b"\x42" * n, n)
        return app.CKR_OK

    def generate_key(session, mechanism, template, tlen, phandle):
        state["keys"] = state.get("keys", 0) + 1
        h = ctypes.cast(phandle, ctypes.POINTER(app.CK_OBJECT_HANDLE))
        h[0] = app.CK_OBJECT_HANDLE(state["keys"])
        return app.CKR_OK

    def encrypt(session, data, size, output, output_length):
        if "plaintext" not in state:
            state["plaintext"] = ctypes.string_at(data, _to_int(size))
        addr = ctypes.cast(output, ctypes.c_void_p).value
        calls.append(("encrypt", addr))
        step = encrypt_steps[state.get("step", 0)] if state.get("step", 0) < len(encrypt_steps) else ("ok", 0)
        state["step"] = state.get("step", 0) + 1
        ol = ctypes.cast(output_length, ctypes.POINTER(app.CK_ULONG))
        if step[0] == "too_small":
            ol[0] = app.CK_ULONG(step[1])
            return app.CKR_BUFFER_TOO_SMALL
        cipher_len = len(state["plaintext"]) + 8
        ctypes.memmove(output, b"\xC1" * cipher_len, cipher_len)
        ol[0] = app.CK_ULONG(cipher_len)
        return app.CKR_OK

    def decrypt(session, ct, ct_len, pt, pt_len):
        plain = state["plaintext"]
        ctypes.memmove(pt, plain, len(plain))
        pl = ctypes.cast(pt_len, ctypes.POINTER(app.CK_ULONG))
        pl[0] = app.CK_ULONG(len(plain))
        return app.CKR_OK

    def mechanism_list(slot, ptr, pcount):
        pc = ctypes.cast(pcount, ctypes.POINTER(app.CK_ULONG))
        mechs = [app.CKM_MAGMA_KEY_GEN, app.CKM_MAGMA_CTR_ACPKM]
        if ptr:
            arr = ctypes.cast(ptr, ctypes.POINTER(app.CK_MECHANISM_TYPE * len(mechs))).contents
            for i, m in enumerate(mechs):
                arr[i] = app.CK_MECHANISM_TYPE(m)
        pc[0] = app.CK_ULONG(len(mechs))
        return app.CKR_OK

    return {
        "C_GenerateRandom": generate_random,
        "C_GenerateKey": generate_key,
        "C_EncryptInit": lambda *_: app.CKR_OK,
        "C_Encrypt": encrypt,
        "C_DecryptInit": lambda *_: app.CKR_OK,
        "C_Decrypt": decrypt,
        "C_DestroyObject": lambda *_: app.CKR_OK,
        "C_GetMechanismList": mechanism_list,
    }, memsets


class FileInputErrorTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.directory = Path(self.tmpdir.name)
        self.regular_file = self.directory / "data.bin"
        self.regular_file.write_bytes(b"PLAINTEXT-DATA" * 10)

    def tearDown(self):
        self.tmpdir.cleanup()

    def run_encrypt_file(self, path):
        calls = []
        funcs, memsets = encrypt_funcs(calls, [("ok", 0)], {})
        inputs = iter([str(path), "2", "1", "0", "0"])  # path, count, warmup, mode, algorithm
        out = io.StringIO()
        with mock.patch("builtins.input", lambda *a: next(inputs)), redirect_stdout(out):
            app.encrypt_file(1, funcs, 1)
        return out.getvalue(), calls

    def run_sign_file(self, path):
        calls = []
        verify_out = []
        funcs = sign_pair_funcs([("ok", b"S" * 256)], calls, verify_out)
        inputs = iter([str(path), "2", "1", ""])  # path, count, warmup, pair choice
        out = io.StringIO()
        with mock.patch("builtins.input", lambda *a: next(inputs)), redirect_stdout(out):
            app.sign_file(1, funcs)
        return out.getvalue(), calls

    def test_encrypt_file_with_directory_path_prints_clean_message(self):
        out, calls = self.run_encrypt_file(self.directory)
        self.assertIn("не обычный файл", out)
        self.assertNotIn("Неожиданная ошибка", out)
        # Token must not be touched at all.
        self.assertEqual(calls, [])

    def test_sign_file_with_directory_path_prints_clean_message(self):
        out, calls = self.run_sign_file(self.directory)
        self.assertIn("не обычный файл", out)
        self.assertNotIn("Неожиданная ошибка", out)
        self.assertEqual([c for c in calls if c[0] == "sign"], [])

    def test_encrypt_file_handles_vanished_file_as_clean_error(self):
        # Path passes the is_file() check, then disappears before reading.
        victim = self.regular_file
        real_is_file = Path.is_file

        def is_file_once_then_disappear(path_obj):
            result = real_is_file(path_obj)
            if path_obj == victim:
                victim.unlink()
            return result

        calls = []
        funcs, memsets = encrypt_funcs(calls, [("ok", 0)], {})
        inputs = iter([str(victim), "2", "1", "0", "0"])
        out = io.StringIO()
        with mock.patch.object(Path, "is_file", is_file_once_then_disappear), \
             mock.patch("builtins.input", lambda *a: next(inputs)), redirect_stdout(out):
            app.encrypt_file(1, funcs, 1)  # must not raise
        import os as _os
        needle = "Не удалось прочитать файл"
        self.assertIn(needle, out.getvalue())
        self.assertNotIn("Неожиданная ошибка", out.getvalue())
        # Nothing was encrypted and no buffers were allocated for output.
        self.assertEqual([c for c in calls if c[0] == "encrypt"], [])

    def test_sign_file_handles_vanished_file_as_clean_error(self):
        victim = self.regular_file
        real_is_file = Path.is_file

        def is_file_once_then_disappear(path_obj):
            result = real_is_file(path_obj)
            if path_obj == victim:
                victim.unlink()
            return result

        calls = []
        verify_out = []
        funcs = sign_pair_funcs([("ok", b"S" * 256)], calls, verify_out)
        inputs = iter([str(victim), "2", "1", ""])
        out = io.StringIO()
        with mock.patch.object(Path, "is_file", is_file_once_then_disappear), \
             mock.patch("builtins.input", lambda *a: next(inputs)), redirect_stdout(out):
            app.sign_file(1, funcs)  # must not raise
        self.assertIn("Не удалось прочитать файл", out.getvalue())
        self.assertNotIn("Неожиданная ошибка", out.getvalue())
        self.assertEqual([c for c in calls if c[0] == "sign"], [])


class MultiOperationFlowTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.file_path = Path(self.tmpdir.name) / "data.bin"
        self.file_path.write_bytes(b"PLAINTEXT-DATA" * 10)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_sign_file_multi_operations_with_mid_sequence_retry(self):
        # warmup(1) + measured(2): ok, ok, retry->ok. The last measured signature
        # (retry buffer) must be used for self-check and Base64 output; every
        # signature buffer (including the retry buffer) must be wiped before return.
        sig_a = b"A" * 256
        sig_b = b"B" * 256
        sig_c = b"C" * 300
        calls = []
        verify_out = []
        orig_memset = ctypes.memset
        memsets = []

        def logging_memset(addr, value, size):
            memsets.append(ctypes.cast(addr, ctypes.c_void_p).value)
            return orig_memset(addr, value, size)

        funcs = sign_pair_funcs(
            [("ok", sig_a), ("ok", sig_b), ("too_small", 300), ("ok", sig_c)],
            calls,
            verify_out,
        )
        inputs = iter([str(self.file_path), "2", "1", ""])
        out = io.StringIO()
        with mock.patch.object(ctypes, "memset", logging_memset), \
             mock.patch("builtins.input", lambda *a: next(inputs)), redirect_stdout(out):
            app.sign_file(1, funcs)

        sign_calls = [c for c in calls if c[0] == "sign"]
        self.assertEqual(len(sign_calls), 4)
        # Self-check verifies the LAST measured signature, not a stale one.
        self.assertEqual(verify_out, [sig_c])
        self.assertIn("Самопроверка подписи: успешно", out.getvalue())
        printed_b64 = out.getvalue().split("Подпись (Base64):\n")[1].replace("\n", "")
        self.assertEqual(base64.b64decode(printed_b64), sig_c)
        # Cleanup: every buffer that received a signature was wiped.
        for _, addr in sign_calls:
            self.assertIn(addr, memsets, f"signature buffer at {addr} was never wiped")

    def test_encrypt_file_multi_operations_with_mid_sequence_retry(self):
        # warmup(1) + measured(2): ok, ok, retry->ok. All output buffers wiped,
        # self-check passed, key destroyed.
        calls = []
        state = {}
        orig_memset = ctypes.memset
        memsets = []

        def logging_memset(addr, value, size):
            memsets.append(ctypes.cast(addr, ctypes.c_void_p).value)
            return orig_memset(addr, value, size)

        funcs, memsets = encrypt_funcs(calls, [("ok", 0), ("ok", 0), ("too_small", 4096), ("ok", 0)], state)
        inputs = iter([str(self.file_path), "2", "1", "0", "0"])
        out = io.StringIO()
        with mock.patch.object(ctypes, "memset", logging_memset), \
             mock.patch("builtins.input", lambda *a: next(inputs)), redirect_stdout(out):
            app.encrypt_file(1, funcs, 1)

        encrypt_calls = [c for c in calls if c[0] == "encrypt"]
        self.assertEqual(len(encrypt_calls), 4)
        self.assertIn("Самопроверка расшифрованием: успешно", out.getvalue())
        self.assertEqual(state.get("keys"), 1)
        for _, addr in encrypt_calls:
            self.assertIn(addr, memsets, f"output buffer at {addr} was never wiped")


if __name__ == "__main__":
    unittest.main(verbosity=2)
