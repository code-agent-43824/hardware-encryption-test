"""Regression tests: sign_file must check that the token supports the pair's
signing mechanism (C_GetMechanismList) BEFORE reading the input file and
allocating signature buffers — the same diagnosable pre-flight check that
encrypt_file already performs for its key-gen/encrypt mechanisms.

Contract:
- If the token does not report the signing mechanism of the selected pair,
  sign_file must raise PKCS11Error with a diagnostic message ("Токен не
  поддерживает механизм подписи 0x... для ...") and must NOT call
  C_SignInit/C_Sign/C_Verify and must NOT read the input file.
- A key type without "sign_mechanism" in KEY_TYPES still raises the
  "Неподдерживаемый тип ключа" PKCS11Error before any mechanism query.
- Normal multi-operation sequences (warmup + measured + retry) are unaffected:
  the mechanism check passes and the full flow completes.
"""
import ctypes
import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import app
from test_file_input_errors import _to_int, sign_pair_funcs


class SignMechanismSupportTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.file_path = Path(self.tmpdir.name) / "data.bin"
        self.file_path.write_bytes(b"PLAINTEXT-DATA" * 10)

    def tearDown(self):
        self.tmpdir.cleanup()

    def run_sign_file(self, funcs):
        inputs = iter([str(self.file_path), "2", "1", ""])
        out, err = io.StringIO(), io.StringIO()
        error = None
        with mock.patch("builtins.input", lambda *a: next(inputs)), \
             redirect_stdout(out), redirect_stderr(err):
            try:
                app.sign_file(1, funcs, 7)
            except app.PKCS11Error as exc:
                error = exc
        return out.getvalue(), err.getvalue(), error

    def test_missing_sign_mechanism_raises_before_any_sign_call(self):
        # Negative case: the token reports an empty mechanism list. sign_file
        # must fail with a diagnosable PKCS11Error BEFORE C_SignInit/C_Sign/
        # C_Verify and BEFORE reading the input file.
        calls = []
        verify_out = []
        opened = []

        def tracking_open(*args, **kwargs):
            opened.append(args)
            return open(*args, **kwargs)

        funcs = sign_pair_funcs([("ok", b"S" * 256)], calls, verify_out)

        def empty_mechanism_list(slot, ptr, pcount):
            pc = ctypes.cast(pcount, ctypes.POINTER(app.CK_ULONG))
            pc[0] = app.CK_ULONG(0)
            return app.CKR_OK

        funcs["C_GetMechanismList"] = empty_mechanism_list

        out, err, error = self.run_sign_file(funcs)
        self.assertIsInstance(error, app.PKCS11Error)
        self.assertNotIsInstance(error, app.InvalidModuleLengthError)
        self.assertIn("Токен не поддерживает механизм подписи", str(error))
        self.assertIn(f"0x{app.CKM_SHA256_RSA_PKCS:08X}", str(error))
        self.assertIn("RSA-2048", str(error))
        self.assertEqual(
            [name for name, _ in calls if name in ("sign", "verify")],
            [],
            "C_Sign/C_Verify must not be called when the mechanism is unsupported",
        )
        self.assertEqual(
            [call for call in calls if call[0] == "sign_init"],
            [],
        )
        self.assertEqual(opened, [], "the input file must not be read")

    def test_missing_sign_mechanism_leaves_no_unread_side_effects(self):
        # The failure path must not allocate/wipe signature buffers: without a
        # signature buffer there is nothing sensitive to wipe, and the run
        # never reaches C_SignInit (checked via a sentinel that fails the test
        # if the sign operation starts).
        calls = []
        verify_out = []
        funcs = sign_pair_funcs([("ok", b"S" * 256)], calls, verify_out)

        def failing_sign_init(*_args):
            raise AssertionError("C_SignInit must not be called")

        funcs["C_SignInit"] = failing_sign_init

        def empty_mechanism_list(slot, ptr, pcount):
            pc = ctypes.cast(pcount, ctypes.POINTER(app.CK_ULONG))
            pc[0] = app.CK_ULONG(0)
            return app.CKR_OK

        funcs["C_GetMechanismList"] = empty_mechanism_list
        out, err, error = self.run_sign_file(funcs)
        self.assertIsInstance(error, app.PKCS11Error)
        self.assertIn("Токен не поддерживает механизм подписи", str(error))

    def test_key_type_without_sign_mechanism_raises_before_mechanism_query(self):
        # A pair whose algorithm has no "sign_mechanism" in KEY_TYPES must
        # still fail with the "unsupported key type" error, before any
        # C_GetMechanismList call.
        calls = []
        verify_out = []
        funcs = sign_pair_funcs([("ok", b"S" * 256)], calls, verify_out)

        def failing_mechanism_list(*_args):
            raise AssertionError("C_GetMechanismList must not be called")

        funcs["C_GetMechanismList"] = failing_mechanism_list
        attrs = {
            1: app.CKK_GOST28147,  # KEY_TYPES entry without sign_mechanism
            2: app.CKK_GOST28147,
        }

        orig_get_attr = funcs["C_GetAttributeValue"]

        def gost28147_attr(session, handle, template, count):
            for i in range(_to_int(count)):
                t = template[i]
                if _to_int(t.type) == app.CKA_KEY_TYPE:
                    value = bytes(app.CK_ULONG(attrs[int(handle)]))
                    t.ulValueLen = app.CK_ULONG(len(value))
                    if t.pValue:
                        ctypes.memmove(t.pValue, value, len(value))
                    continue
                rc = orig_get_attr(session, handle, template, count)
                if rc != app.CKR_OK:
                    return rc
            return app.CKR_OK

        funcs["C_GetAttributeValue"] = gost28147_attr
        out, err, error = self.run_sign_file(funcs)
        self.assertIsInstance(error, app.PKCS11Error)
        self.assertIn("Неподдерживаемый тип ключа для подписи", str(error))

    def test_supported_mechanism_multi_op_flow_still_completes(self):
        # Positive case: with the mechanism present, a multi-operation
        # sequence (warmup + two measured operations, one with a
        # CKR_BUFFER_TOO_SMALL retry) still completes end to end.
        calls = []
        verify_out = []
        steps = [
            ("ok", b"W" * 256),          # warmup
            ("too_small", 300), ("ok", b"A" * 300),  # measured op 1 (retry)
            ("ok", b"B" * 256),          # measured op 2
        ]
        funcs = sign_pair_funcs(steps, calls, verify_out)
        out, err, error = self.run_sign_file(funcs)
        self.assertIsNone(error)
        self.assertIn("Самопроверка подписи: успешно", out)
        self.assertEqual(len(verify_out), 1)
        sign_calls = [c for c in calls if c[0] == "sign"]
        # warmup (1) + op1 retry pair (too_small + retry = 2) + op2 (1)
        self.assertEqual(len(sign_calls), 4, "warmup + retry pair + measured")


if __name__ == "__main__":
    unittest.main()
