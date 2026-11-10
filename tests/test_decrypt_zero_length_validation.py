"""Regression tests: decrypt_and_check must reject a zero plaintext length
reported by the (untrusted) PKCS#11 module together with CKR_OK.

Contract:
- If the module returns CKR_OK with *pulPlaintextLen == 0, decrypt_and_check
  must raise InvalidModuleLengthError BEFORE the length is used to compare the
  decrypted text: a zero-length plaintext violates the PKCS#11 contract, and
  the module failure must not be masked as a routine self-check failure (and
  for an empty expected plaintext a broken module must not pass the check at
  all) — same "0 or inflated length validated before use" contract as
  sign_file / verify_signature / encrypt_with_generated_key.
- On the new error path the plaintext buffer and the ciphertext copy must
  still be wiped (no leak of sensitive data).
- Normal multi-operation sequences are unaffected.
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


def decrypt_unit_funcs(report, captured):
    """Unit-level fake for decrypt_and_check: C_Decrypt writes a full-capacity
    payload but reports the scripted length (simulating a faulty or hostile
    module)."""

    def decrypt(_session, _ct, _ct_len, pt, pt_len):
        capacity = captured["capacity"]
        payload = b"\xAB" * capacity
        ctypes.memmove(pt, payload, capacity)
        captured["plaintext_addr"] = ctypes.cast(pt, ctypes.c_void_p).value
        ctypes.cast(pt_len, ctypes.POINTER(app.CK_ULONG))[0] = app.CK_ULONG(report)
        return app.CKR_OK

    return {
        "C_DecryptInit": lambda *_args: app.CKR_OK,
        "C_Decrypt": decrypt,
    }


ALGORITHM = {"name": "test", "encrypt_mechanism": 1}
CIPHERTEXT = b"\xC1" * 12


class DecryptZeroLengthUnitTests(unittest.TestCase):
    def run_decrypt_and_check(self, funcs, expected_plaintext):
        orig_memset = ctypes.memset
        memsets = []

        def logging_memset(addr, value, size):
            memsets.append((ctypes.cast(addr, ctypes.c_void_p).value, _to_int(size)))
            return orig_memset(addr, value, size)

        with mock.patch.object(ctypes, "memset", logging_memset):
            result, error = None, None
            try:
                result = app.decrypt_and_check(
                    1, funcs, 1, ALGORITHM,
                    CIPHERTEXT, b"", expected_plaintext,
                )
            except app.PKCS11Error as exc:
                error = exc
        return result, error, memsets

    def test_zero_length_raises_invalid_module_length(self):
        # Negative case: CKR_OK with reported plaintext length 0.
        captured = {"capacity": len(CIPHERTEXT)}
        funcs = decrypt_unit_funcs(0, captured)
        expected = memoryview(b"\xAB" * len(CIPHERTEXT))
        _result, error, _memsets = self.run_decrypt_and_check(funcs, expected)
        self.assertIsInstance(error, app.InvalidModuleLengthError)
        message = str(error)
        self.assertIn("некорректную длину открытого текста", message)
        self.assertIn("(ёмкость буфера 12)", message)

    def test_zero_length_wipes_plaintext_and_ciphertext_buffers(self):
        # Resource cleanup: on the new error path both sensitive buffers
        # (plaintext written by the module and the ciphertext copy) must be
        # wiped before the exception propagates.
        captured = {"capacity": len(CIPHERTEXT)}
        funcs = decrypt_unit_funcs(0, captured)
        expected = memoryview(b"\xAB" * len(CIPHERTEXT))
        _result, error, memsets = self.run_decrypt_and_check(funcs, expected)
        self.assertIsInstance(error, app.InvalidModuleLengthError)
        wiped_addrs = {addr for addr, _size in memsets}
        self.assertIn(captured["plaintext_addr"], wiped_addrs)
        wiped_sizes = {size for _addr, size in memsets}
        self.assertIn(len(CIPHERTEXT), wiped_sizes)

    def test_inflated_length_still_rejected(self):
        # Regression guard: the existing oversized-length check keeps working
        # alongside the new zero-length check.
        captured = {"capacity": len(CIPHERTEXT)}
        funcs = decrypt_unit_funcs(len(CIPHERTEXT) + 4, captured)
        expected = memoryview(b"\xAB" * len(CIPHERTEXT))
        _result, error, _memsets = self.run_decrypt_and_check(funcs, expected)
        self.assertIsInstance(error, app.InvalidModuleLengthError)
        self.assertIn("> ёмкости буфера 12", str(error))

    def test_correct_length_passes(self):
        # Control: a correct full-capacity result passes the self-check and
        # returns the mechanism keepalive.
        captured = {"capacity": len(CIPHERTEXT)}
        funcs = decrypt_unit_funcs(len(CIPHERTEXT), captured)
        expected = memoryview(b"\xAB" * len(CIPHERTEXT))
        result, error, memsets = self.run_decrypt_and_check(funcs, expected)
        self.assertIsNone(error)
        self.assertIsNone(result)  # mechanism_keepalive for a plain mechanism
        # Cleanup still happens on the happy path.
        self.assertIn(captured["plaintext_addr"], {addr for addr, _size in memsets})


class DecryptZeroLengthFileTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.file_path = Path(self.tmpdir.name) / "data.bin"
        self.file_path.write_bytes(b"PLAINTEXT-DATA" * 10)  # 140 bytes

    def tearDown(self):
        self.tmpdir.cleanup()

    def run_encrypt_file(self, count, warmup, zero_decrypt):
        calls = []
        state = {}
        funcs, memsets = encrypt_funcs(calls, [], state)
        decrypt_calls = []
        orig_decrypt = funcs["C_Decrypt"]

        def decrypt(session, ct, ct_len, pt, pt_len):
            decrypt_calls.append(1)
            rv = orig_decrypt(session, ct, ct_len, pt, pt_len)
            if rv == app.CKR_OK and zero_decrypt:
                ctypes.cast(pt_len, ctypes.POINTER(app.CK_ULONG))[0] = app.CK_ULONG(0)
            return rv

        funcs["C_Decrypt"] = decrypt

        inputs = iter([str(self.file_path), str(count), str(warmup), "0", "0"])
        out, err = io.StringIO(), io.StringIO()
        error = None
        orig_memset = ctypes.memset

        def logging_memset(addr, value, size):
            memsets.append((ctypes.cast(addr, ctypes.c_void_p).value, _to_int(size)))
            return orig_memset(addr, value, size)

        with mock.patch.object(ctypes, "memset", logging_memset), \
                mock.patch("builtins.input", lambda *a: next(inputs)), \
                redirect_stdout(out), redirect_stderr(err):
            try:
                app.encrypt_file(1, funcs, 1)
            except app.PKCS11Error as exc:
                error = exc
        return memsets, out.getvalue(), err.getvalue(), error, decrypt_calls

    def test_zero_plaintext_not_masked_as_selfcheck_failure(self):
        # The module returns CKR_OK with plaintext length 0 during the
        # self-check of the LAST measured operation. encrypt_file must fail
        # with InvalidModuleLengthError (not SelfCheckError): the zero-length
        # check fires BEFORE the comparison that would mask the module
        # failure as a routine self-check failure.
        memsets, output, err, error, decrypt_calls = self.run_encrypt_file(
            1, 1, zero_decrypt=True,
        )
        self.assertIsInstance(error, app.InvalidModuleLengthError)
        self.assertNotIsInstance(error, app.SelfCheckError)
        self.assertIn("некорректную длину открытого текста", str(error))
        self.assertNotIn("Самопроверка расшифрованием: успешно", output)
        # Ciphertext size reported by the fake module: 140 + 8 = 148.
        self.assertIn("(ёмкость буфера 148)", str(error))
        self.assertEqual(decrypt_calls, [1])
        # Cleanup: data buffer (140) and the main ciphertext buffer (172)
        # wiped in encrypt_file's finally; the decrypt buffers (148) wiped in
        # decrypt_and_check's finally.
        wiped_sizes = {size for _addr, size in memsets}
        self.assertIn(140, wiped_sizes)
        self.assertIn(172, wiped_sizes)
        self.assertIn(148, wiped_sizes)

    def test_zero_plaintext_in_multi_op_sequence_leaves_no_unwiped_buffers(self):
        # Multi-operation sequence: warmup ok, measured op1 self-check ok,
        # measured op2 self-check hits the zero-length fault. Everything
        # allocated so far must be wiped.
        memsets, _output, _err, error, decrypt_calls = self.run_encrypt_file(
            2, 1, zero_decrypt=True,
        )
        # The fault is injected for every C_Decrypt call, so the very first
        # self-check fails; the key point is cleanup and error class.
        self.assertIsInstance(error, app.InvalidModuleLengthError)
        self.assertNotIsInstance(error, app.SelfCheckError)
        self.assertEqual(len(decrypt_calls), 1)
        wiped_sizes = {size for _addr, size in memsets}
        self.assertIn(140, wiped_sizes)
        self.assertIn(172, wiped_sizes)
        self.assertIn(148, wiped_sizes)

    def test_normal_multi_op_flow_unaffected(self):
        # Control: without the zero-length fault the normal multi-operation
        # flow (warmup + 2 measured) still succeeds and the self-check of the
        # LAST measured ciphertext passes (decrypt_and_check runs once per
        # encrypt_file invocation, for the last operation).
        memsets, output, _err, error, decrypt_calls = self.run_encrypt_file(
            2, 1, zero_decrypt=False,
        )
        self.assertIsNone(error)
        self.assertIn("Самопроверка расшифрованием: успешно", output)
        self.assertEqual(len(decrypt_calls), 1)


if __name__ == "__main__":
    unittest.main()
