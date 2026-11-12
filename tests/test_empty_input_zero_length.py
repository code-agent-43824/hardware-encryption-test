"""Regression tests: zero-length results must be rejected only for non-empty
input; an empty ciphertext/plaintext is legitimate for empty input.

Contract:
- encrypt_with_generated_key with data_size == 0 must accept a zero-length
  ciphertext reported with CKR_OK (a stream cipher legitimately produces an
  empty ciphertext for empty input); an INFLATED length is still rejected
  regardless of data_size.
- encrypt_with_generated_key with data_size > 0 must keep raising
  InvalidModuleLengthError for a zero-length ciphertext (v2.12 guard).
- decrypt_and_check with an empty ciphertext must accept a zero-length
  plaintext and pass the comparison (empty == empty); with a non-empty
  ciphertext a zero-length plaintext must still be rejected.
- End to end: encrypt_file with an empty file must succeed across a
  multi-operation sequence (warmup + measured), destroy the secret key and
  wipe every sensitive buffer.
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
from test_encrypt_zero_length_validation import encrypt_unit_funcs, make_operation


ALGORITHM = {"name": "test", "encrypt_mechanism": 1}


def run_encrypt_with_generated_key(funcs, data_size, capacity):
    buffer = (app.CK_BYTE * capacity)()
    result, error = None, None
    try:
        result = app.encrypt_with_generated_key(
            1, funcs, 1, ALGORITHM,
            app.CK_BYTE_PTR(), app.CK_ULONG(data_size), buffer,
            make_operation(capacity),
        )
    except app.PKCS11Error as exc:
        error = exc
    return result, error, buffer


class EmptyInputEncryptUnitTests(unittest.TestCase):
    def test_empty_input_accepts_zero_length_ciphertext(self):
        # Positive case: data_size == 0 and the module reports length 0 with
        # CKR_OK — legitimate for a stream cipher, must not raise.
        funcs = encrypt_unit_funcs([{"rv": app.CKR_OK, "report": 0, "write": b""}], {})
        result, error, buffer = run_encrypt_with_generated_key(funcs, 0, 8)
        self.assertIsNone(error)
        self.assertEqual(result[0], 0)
        self.assertIs(result[2], buffer)

    def test_empty_input_still_rejects_inflated_length(self):
        # Guard: the loosening must not accept an inflated length for empty
        # input — oversized results are rejected regardless of data_size.
        funcs = encrypt_unit_funcs([{"rv": app.CKR_OK, "report": 9, "write": b""}], {})
        _, error, _ = run_encrypt_with_generated_key(funcs, 0, 8)
        self.assertIsInstance(error, app.InvalidModuleLengthError)
        self.assertIn("9 > ёмкости буфера 8", str(error))

    def test_non_empty_input_keeps_rejecting_zero_length(self):
        # Regression guard for the v2.12 contract: non-empty input with a
        # zero-length result is still a module malfunction.
        funcs = encrypt_unit_funcs([{"rv": app.CKR_OK, "report": 0, "write": b""}], {})
        _, error, _ = run_encrypt_with_generated_key(funcs, 4, 8)
        self.assertIsInstance(error, app.InvalidModuleLengthError)
        self.assertIn("длину шифротекста: 0", str(error))


class EmptyInputDecryptUnitTests(unittest.TestCase):
    def decrypt(self, ciphertext_len, report):
        captured = {"capacity": ciphertext_len}
        memsets = []
        orig_memset = ctypes.memset

        def logging_memset(addr, value, size):
            memsets.append((ctypes.cast(addr, ctypes.c_void_p).value, _to_int(size)))
            return orig_memset(addr, value, size)

        def decrypt(_session, _ct, _ct_len, pt, pt_len):
            ctypes.cast(pt_len, ctypes.POINTER(app.CK_ULONG))[0] = app.CK_ULONG(report)
            return app.CKR_OK

        funcs = {"C_DecryptInit": lambda *_: app.CKR_OK, "C_Decrypt": decrypt}
        error = None
        with mock.patch.object(ctypes, "memset", logging_memset):
            try:
                app.decrypt_and_check(
                    1, funcs, 1, ALGORITHM,
                    memoryview(b"\xC1" * ciphertext_len), b"",
                    memoryview(b"\xAB" * ciphertext_len),
                )
            except app.PKCS11Error as exc:
                error = exc
        return error, memsets

    def test_empty_ciphertext_accepts_zero_length_plaintext(self):
        # Positive case: empty ciphertext legitimately decrypts to an empty
        # plaintext; the comparison empty == empty passes.
        error, memsets = self.decrypt(0, 0)
        self.assertIsNone(error)
        # Both temporary buffers (plaintext and ciphertext copy) are wiped.
        self.assertEqual({size for _, size in memsets}, {0})

    def test_non_empty_ciphertext_keeps_rejecting_zero_length_plaintext(self):
        # Guard: a zero-length plaintext for non-empty ciphertext is still a
        # module malfunction (a broken module must not pass the self-check
        # when the expected plaintext is empty but the ciphertext is not).
        error, memsets = self.decrypt(12, 0)
        self.assertIsInstance(error, app.InvalidModuleLengthError)
        self.assertIn("длину открытого текста: 0", str(error))
        # Cleanup: the plaintext buffer and the ciphertext copy are wiped.
        self.assertIn(12, {size for _, size in memsets})


class EmptyFileEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.empty_path = Path(self.tmpdir.name) / "empty.bin"
        self.empty_path.write_bytes(b"")

    def tearDown(self):
        self.tmpdir.cleanup()

    def _stream_cipher_funcs(self, calls, state, report_zero=False):
        """Fake PKCS#11 with stream-cipher semantics.

        report_zero=False (honest module): ciphertext length equals plaintext
        length (0 for empty input). report_zero=True (faulty/hostile module):
        always reports length 0 regardless of input size.
        """
        funcs, _ = encrypt_funcs(calls, [("ok", 0)], state)
        encrypt_calls = {"n": 0}

        def encrypt(session, data, size, output, output_length):
            encrypt_calls["n"] += 1
            n = 0 if report_zero else _to_int(size)
            ctypes.cast(output_length, ctypes.POINTER(app.CK_ULONG))[0] = app.CK_ULONG(n)
            return app.CKR_OK

        def decrypt(session, ct, ct_len, pt, pt_len):
            n = _to_int(ct_len)
            if n:
                ctypes.memmove(pt, ctypes.string_at(ct, n), n)
            ctypes.cast(pt_len, ctypes.POINTER(app.CK_ULONG))[0] = app.CK_ULONG(n)
            return app.CKR_OK

        funcs["C_Encrypt"] = encrypt
        funcs["C_Decrypt"] = decrypt
        destroys = {"n": 0}
        orig_destroy = funcs["C_DestroyObject"]

        def destroy(session, handle):
            destroys["n"] += 1
            return orig_destroy(session, handle)

        funcs["C_DestroyObject"] = destroy
        return funcs, encrypt_calls, destroys

    def _run(self, funcs, path):
        """Run encrypt_file with memset logging; returns (output, error,
        memsets)."""
        memsets = []
        orig_memset = ctypes.memset

        def logging_memset(addr, value, size):
            memsets.append((ctypes.cast(addr, ctypes.c_void_p).value, _to_int(size)))
            return orig_memset(addr, value, size)

        inputs = iter([str(path), "2", "1", "0", "0"])
        out, err = io.StringIO(), io.StringIO()
        error = None
        with mock.patch("builtins.input", lambda *a: next(inputs)), \
             redirect_stdout(out), redirect_stderr(err), \
             mock.patch.object(ctypes, "memset", logging_memset):
            try:
                app.encrypt_file(1, funcs, 1)
            except app.PKCS11Error as exc:
                error = exc
        return out.getvalue(), error, memsets

    def test_empty_file_encrypts_successfully_across_sequence(self):
        # Multi-operation sequence: warmup + 2 measured operations over an
        # empty file must succeed and produce the full report.
        calls, state = [], {}
        funcs, encrypt_calls, destroys = self._stream_cipher_funcs(calls, state)
        output, error, memsets = self._run(funcs, self.empty_path)
        self.assertIsNone(error)
        self.assertIn("Самопроверка расшифрованием: успешно", output)
        self.assertIn("Размер последнего шифротекста: 0 байт", output)
        self.assertIn("Последний шифротекст (Base64, первые 256 символов):", output)
        # Sequence actually ran: 1 warmup + 2 measured operations.
        self.assertEqual(encrypt_calls["n"], 3)
        # Cleanup: the temporary secret key is destroyed exactly once.
        self.assertEqual(destroys["n"], 1)
        # The main ciphertext buffer (empty file + overhead) is wiped.
        wiped_sizes = {size for _, size in memsets}
        self.assertIn(app.MAX_CIPHERTEXT_OVERHEAD, wiped_sizes)

    def test_non_empty_file_with_zero_length_module_still_fails(self):
        # Negative end-to-end guard: a module reporting a zero ciphertext
        # length for non-empty data must still fail the operation.
        calls, state = [], {}
        funcs, _, destroys = self._stream_cipher_funcs(calls, state, report_zero=True)
        data_path = Path(self.tmpdir.name) / "data.bin"
        data_path.write_bytes(b"PLAINTEXT-DATA" * 10)
        _, error, memsets = self._run(funcs, data_path)
        self.assertIsInstance(error, app.InvalidModuleLengthError)
        self.assertIn("длину шифротекста: 0", str(error))
        # Cleanup still ran for the failed operation: the key is destroyed.
        self.assertEqual(destroys["n"], 1)
        # The plaintext data buffer is wiped despite the failure.
        self.assertIn(len(b"PLAINTEXT-DATA" * 10), {size for _, size in memsets})


if __name__ == "__main__":
    unittest.main()
