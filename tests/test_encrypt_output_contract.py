"""Regression tests for the encrypt_file output contract.

encrypt_file must not keep any live reference to a ciphertext buffer after
the finally-block wipes it: the only ciphertext data that survives is the
Base64-preview copy created inside the try-block. The status line is printed
only after a successful self-check, so it must always say "успешно"; on
self-check failure SelfCheckError must propagate and the success status must
never be printed.
"""
import base64
import ctypes
import io
import pathlib
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

import app


def _to_int(v):
    if isinstance(v, int):
        return v
    if hasattr(v, "value"):
        return int(v.value)
    return int.from_bytes(bytes(v), "little")


def encrypt_funcs(calls, encrypt_steps, state, decrypt_plain=None):
    """Minimal fake PKCS#11 for encrypt_file (Magma, software mode).

    encrypt_steps: list of ('ok', 0) / ('too_small', needed) per C_Encrypt call.
    decrypt_plain: None → decrypt echoes recorded plaintext (self-check passes);
    bytes → decrypt returns these bytes instead (self-check fails on mismatch).
    """
    orig_memset = ctypes.memset

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
        state["addrs"] = state.get("addrs", [])
        state["addrs"].append(addr)
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
        plain = decrypt_plain if decrypt_plain is not None else state["plaintext"]
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

    funcs = {
        "C_GenerateRandom": generate_random,
        "C_GenerateKey": generate_key,
        "C_EncryptInit": lambda *_: app.CKR_OK,
        "C_Encrypt": encrypt,
        "C_DecryptInit": lambda *_: app.CKR_OK,
        "C_Decrypt": decrypt,
        "C_DestroyObject": lambda *_: app.CKR_OK,
        "C_GetMechanismList": mechanism_list,
    }
    return funcs


class EncryptOutputContractTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.tmpdir.name) / "data.bin"
        self.path.write_bytes(b"PLAINTEXT-DATA" * 10)
        self.plaintext_len = 140

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_success_sequence_with_retry_prints_success_and_correct_preview(self):
        # warmup(1) + measured(2): ok, retry->ok, ok. After the finally-block
        # wipes every buffer, the printed preview must still contain the real
        # ciphertext (it is a copy, not a reference to a wiped buffer), and the
        # status line must be the unconditional "успешно".
        calls = []
        state = {}
        orig_memset = ctypes.memset
        memsets = []
        destroys = []

        def logging_memset(addr, value, size):
            memsets.append(ctypes.cast(addr, ctypes.c_void_p).value)
            return orig_memset(addr, value, size)

        funcs = encrypt_funcs(calls, [("ok", 0), ("too_small", 4096), ("ok", 0)], state)

        real_destroy = funcs["C_DestroyObject"]

        def destroy(session, handle):
            destroys.append(_to_int(handle))
            return real_destroy(session, handle)

        funcs["C_DestroyObject"] = destroy

        inputs = iter([str(self.path), "2", "1", "0", "0"])  # path, count, warmup, mode, algorithm
        out = io.StringIO()
        with mock.patch.object(ctypes, "memset", logging_memset), \
             mock.patch("builtins.input", lambda *a: next(inputs)), \
             redirect_stdout(out):
            app.encrypt_file(1, funcs, 1)

        text = out.getvalue()
        # Warmup + measured op with retry (2 calls) + last measured op.
        encrypt_calls = [c for c in calls if c[0] == "encrypt"]
        self.assertEqual(len(encrypt_calls), 4)
        # Status: only the success variant is reachable after a passed self-check.
        self.assertIn("Самопроверка расшифрованием: успешно", text)
        self.assertNotIn("не пройдена", text)
        # Preview survives the wipe: it equals the ciphertext prefix, not zeros.
        cipher_len = self.plaintext_len + 8
        self.assertIn(f"Размер последнего шифротекста: {cipher_len} байт", text)
        preview_line = text.split("Последний шифротекст (Base64, первые 256 символов):\n")[1].split("\n")[0]
        self.assertEqual(base64.b64decode(preview_line), b"\xC1" * cipher_len)
        # Cleanup: every ciphertext output buffer was wiped, key destroyed once.
        for _, addr in encrypt_calls:
            self.assertIn(addr, memsets, f"output buffer at {addr} was never wiped")
        self.assertEqual(len(destroys), 1)

    def test_selfcheck_failure_propagates_without_success_status(self):
        # Negative case: token decrypts to wrong plaintext → SelfCheckError,
        # stderr message, no "успешно" status; buffers still wiped, key destroyed.
        calls = []
        state = {}
        orig_memset = ctypes.memset
        memsets = []
        destroys = []

        def logging_memset(addr, value, size):
            memsets.append(ctypes.cast(addr, ctypes.c_void_p).value)
            return orig_memset(addr, value, size)

        funcs = encrypt_funcs(
            calls, [("ok", 0), ("ok", 0)], state, decrypt_plain=b"\xFF" * (self.plaintext_len + 8),
        )

        real_destroy = funcs["C_DestroyObject"]

        def destroy(session, handle):
            destroys.append(_to_int(handle))
            return real_destroy(session, handle)

        funcs["C_DestroyObject"] = destroy

        inputs = iter([str(self.path), "1", "1", "0", "0"])  # path, count, warmup, mode, algorithm
        out = io.StringIO()
        with mock.patch.object(ctypes, "memset", logging_memset), \
             mock.patch("builtins.input", lambda *a: next(inputs)), \
             redirect_stdout(out):
            with self.assertRaises(app.SelfCheckError):
                app.encrypt_file(1, funcs, 1)

        text = out.getvalue()
        self.assertNotIn("Самопроверка расшифрованием: успешно", text)
        # Every ciphertext buffer, the input plaintext buffer and any retry
        # buffer must have been wiped even on the failure path.
        encrypt_calls = [c for c in calls if c[0] == "encrypt"]
        for _, addr in encrypt_calls:
            self.assertIn(addr, memsets, f"output buffer at {addr} was never wiped")
        self.assertEqual(len(destroys), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
