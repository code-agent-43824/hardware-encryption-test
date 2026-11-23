"""Regression tests: InvalidModuleLengthError must not be masked as SelfCheckError.

Contract (v2.12): a module that reports a result length exceeding the buffer
capacity is a distinct error class (possible module failure/substitution) and
must propagate unchanged. The self-check wrappers in encrypt_file/sign_file
previously caught it with a broad `except PKCS11Error` and re-raised it as
SelfCheckError ("самопроверка не пройдена"), losing the module-integrity
diagnostics.

After the fix:
- a too-large pulPlaintextLen reported by C_Decrypt during the encryption
  self-check raises InvalidModuleLengthError (not SelfCheckError), with no
  "Самопроверка расшифрования: НЕ УСПЕШНО" stderr line;
- on the signature side the same module-length violations are raised directly
  by sign_file (ulSignatureLen checks) and must not be re-labeled either —
  covered by test_sign_length_validation; a failing C_Verify self-check
  remains a genuine SelfCheckError — covered by SignSelfCheckFailureTests;
- in both cases all sensitive buffers are still wiped and the temporary
  encryption key is destroyed exactly once (multi-operation sequences,
  including a CKR_BUFFER_TOO_SMALL retry, are exercised);
- a genuine self-check mismatch (decrypt returns wrong plaintext) still
  raises SelfCheckError — covered by test_encrypt_selfcheck_failure.
"""
import ctypes
import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import app
from test_encrypt_output_contract import _to_int, encrypt_funcs


def logging_memset_factory(memsets):
    orig_memset = ctypes.memset

    def logging_memset(addr, value, size):
        memsets.append(ctypes.cast(addr, ctypes.c_void_p).value)
        return orig_memset(addr, value, size)

    return logging_memset


class EncryptSelfCheckModuleLengthTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tmpdir.name) / "data.bin"
        self.path.write_bytes(b"PLAINTEXT-DATA" * 10)

    def tearDown(self):
        self.tmpdir.cleanup()

    def run_encrypt_with_lying_decrypt(self, count, warmup, steps):
        """C_Decrypt returns CKR_OK but reports a plaintext length far beyond
        the buffer capacity → decrypt_and_check must raise
        InvalidModuleLengthError before any comparison."""
        calls = []
        state = {}
        memsets = []
        destroys = []

        def lying_decrypt(session, ct, ct_len, pt, pt_len):
            pl = ctypes.cast(pt_len, ctypes.POINTER(app.CK_ULONG))
            pl[0] = app.CK_ULONG(1 << 20)  # > any plausible capacity
            return app.CKR_OK

        funcs = encrypt_funcs(calls, steps, state)
        funcs["C_Decrypt"] = lying_decrypt

        real_destroy = funcs["C_DestroyObject"]

        def destroy(session, handle):
            destroys.append(_to_int(handle))
            return real_destroy(session, handle)

        funcs["C_DestroyObject"] = destroy

        inputs = iter([str(self.path), str(count), str(warmup), "0", "0"])
        out, err = io.StringIO(), io.StringIO()
        error = None
        with mock.patch.object(ctypes, "memset", logging_memset_factory(memsets)), \
             mock.patch("builtins.input", lambda *a: next(inputs)), \
             redirect_stdout(out), redirect_stderr(err):
            try:
                app.encrypt_file(1, funcs, 1)
            except app.PKCS11Error as exc:
                error = exc
        return calls, memsets, destroys, out.getvalue(), err.getvalue(), error

    def test_lying_plaintext_length_raises_module_length_error_not_selfcheck(self):
        # Multi-operation sequence incl. a CKR_BUFFER_TOO_SMALL retry:
        # warmup(1) + measured(2): ok; retry(4096)->ok; ok.
        calls, memsets, destroys, out, err, error = self.run_encrypt_with_lying_decrypt(
            2, 1, [("ok", 0), ("too_small", 4096), ("ok", 0)],
        )
        self.assertIsInstance(error, app.InvalidModuleLengthError)
        self.assertNotIsInstance(error, app.SelfCheckError)
        self.assertIn("некорректную длину открытого текста", str(error))
        # No self-check failure message: this is a module-length violation,
        # not a self-check failure.
        self.assertNotIn("НЕ УСПЕШНО", err)

    def test_lying_length_cleanup_after_retry_sequence(self):
        calls, memsets, destroys, out, err, error = self.run_encrypt_with_lying_decrypt(
            2, 1, [("ok", 0), ("too_small", 4096), ("ok", 0)],
        )
        self.assertIsInstance(error, app.InvalidModuleLengthError)
        encrypt_calls = [c for c in calls if c[0] == "encrypt"]
        # Every ciphertext output buffer (incl. the retry buffer) was wiped...
        for _, addr in encrypt_calls:
            self.assertIn(addr, memsets, f"output buffer at {addr} was never wiped")
        # ...and the temporary key was destroyed exactly once.
        self.assertEqual(len(destroys), 1)


class SignSelfCheckFailureTests(unittest.TestCase):
    """GOST R 34.10-2012(256) pair through sign_file: the self-check verifies
    the signature with the same combined hash+sign mechanism (with the OID
    parameter) the signing path uses — no separate C_Digest step. A C_Verify
    failure (e.g. CKR_SIGNATURE_INVALID from a faulty or substituted module)
    is a genuine self-check failure and must be re-labeled as SelfCheckError
    with the stderr diagnostic. Module-length violations raised by sign_file
    itself must NOT be re-labeled — covered by test_sign_length_validation."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tmpdir.name) / "data.bin"
        self.path.write_bytes(b"PLAINTEXT-DATA" * 10)

    def tearDown(self):
        self.tmpdir.cleanup()

    def gost_funcs(self, calls, verify_result):
        def ulong_bytes(v):
            return bytes(app.CK_ULONG(v))

        attrs = {
            1: {app.CKA_ID: b"\x01", app.CKA_LABEL: b"K", app.CKA_KEY_TYPE: ulong_bytes(app.CKK_GOSTR3410)},
            2: {app.CKA_ID: b"\x01", app.CKA_LABEL: b"K", app.CKA_KEY_TYPE: ulong_bytes(app.CKK_GOSTR3410)},
        }
        state = {"class": None, "batch": 0, "sign_step": 0}

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
                if _to_int(template[i].type) == 0 and template[i].pValue:
                    state["class"] = ctypes.cast(
                        template[i].pValue, ctypes.POINTER(app.CK_ULONG)
                    ).contents.value
            state["batch"] = 0
            return app.CKR_OK

        def find(session, ph_object, max_count, pul_count):
            pul = ctypes.cast(pul_count, ctypes.POINTER(app.CK_ULONG))
            state["batch"] += 1
            if state["batch"] == 1 and state["class"] in (app.CKO_PUBLIC_KEY, app.CKO_PRIVATE_KEY):
                handle = 1 if state["class"] == app.CKO_PUBLIC_KEY else 2
                handles = (app.CK_OBJECT_HANDLE * 1)(handle)
                ctypes.memmove(ph_object, handles, ctypes.sizeof(handles))
                pul[0] = app.CK_ULONG(1)
            else:
                pul[0] = app.CK_ULONG(0)
            return app.CKR_OK

        def sign(session, data, size, output, output_length):
            addr = ctypes.cast(output, ctypes.c_void_p).value
            calls.append(("sign", addr))
            state["sign_step"] += 1
            ctypes.memmove(output, b"S" * 64, 64)
            ol = ctypes.cast(output_length, ctypes.POINTER(app.CK_ULONG))
            ol[0] = app.CK_ULONG(64)
            return app.CKR_OK

        def verify(session, data, data_len, sig, sig_len):
            addr = ctypes.cast(sig, ctypes.c_void_p).value
            calls.append(("verify", addr))
            return verify_result

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

    def run_sign(self, verify_result, count=2, warmup=1):
        calls = []
        memsets = []
        inputs = iter([str(self.path), str(count), str(warmup), ""])
        out, err = io.StringIO(), io.StringIO()
        error = None
        funcs = self.gost_funcs(calls, verify_result)
        with mock.patch.object(ctypes, "memset", logging_memset_factory(memsets)), \
             mock.patch("builtins.input", lambda *a: next(inputs)), \
             redirect_stdout(out), redirect_stderr(err):
            try:
                app.sign_file(1, funcs)
            except app.PKCS11Error as exc:
                error = exc
        return calls, memsets, out.getvalue(), err.getvalue(), error

    def test_invalid_signature_raises_selfcheck_error(self):
        # A C_Verify failure during the self-check is a genuine self-check
        # failure: re-labeled as SelfCheckError with the stderr diagnostic.
        calls, memsets, out, err, error = self.run_sign(app.CKR_SIGNATURE_INVALID)
        self.assertIsInstance(error, app.SelfCheckError)
        self.assertNotIsInstance(error, app.InvalidModuleLengthError)
        self.assertIn("НЕ УСПЕШНО", err)
        sign_calls = [c for c in calls if c[0] == "sign"]
        verify_calls = [c for c in calls if c[0] == "verify"]
        self.assertEqual(len(sign_calls), 3)  # warmup + 2 measured
        self.assertEqual(len(verify_calls), 1)  # exactly one self-check
        # All signature output buffers were wiped.
        for _, addr in sign_calls:
            self.assertIn(addr, memsets, f"signature buffer at {addr} was never wiped")

    def test_honest_verify_signs_successfully(self):
        # Control: honest module (C_Verify returns CKR_OK) → full success path.
        calls, memsets, out, err, error = self.run_sign(app.CKR_OK)
        self.assertIsNone(error)
        self.assertIn("Самопроверка подписи: успешно", out)
        sign_calls = [c for c in calls if c[0] == "sign"]
        for _, addr in sign_calls:
            self.assertIn(addr, memsets, "signature buffer was never wiped")


if __name__ == "__main__":
    unittest.main(verbosity=2)
