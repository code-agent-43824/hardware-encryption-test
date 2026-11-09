"""Regression tests: encrypt_with_generated_key must reject a zero ciphertext
length reported by the (untrusted) PKCS#11 module together with CKR_OK.

Contract:
- If the module returns CKR_OK with *pulEncryptedLen == 0 (main buffer or
  CKR_BUFFER_TOO_SMALL retry buffer), encrypt_with_generated_key must raise
  InvalidModuleLengthError BEFORE the length is used for the preview, the
  decrypt self-check or the metrics: a zero-length ciphertext for non-empty
  input violates the PKCS#11 contract, and the module failure must not be
  masked as a routine self-check failure (same "0 or inflated length
  validated before use" contract as sign_file / verify_signature).
- On the retry path the temporary buffer must still be wiped when the
  zero-length check fails (no leak of partially written sensitive data).
- Normal multi-operation sequences (including a retry) are unaffected.
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


def _to_ulong_ptr(raw):
    return ctypes.cast(raw, ctypes.POINTER(app.CK_ULONG))


def zero_encrypt_lengths_on_call(base_funcs, call_numbers):
    """Wrap C_Encrypt so the given 1-based successful calls report length 0
    (simulating a faulty or hostile module)."""
    orig_encrypt = base_funcs["C_Encrypt"]
    state = {"n": 0}

    def zeroing_encrypt(session, data, size, output, output_length):
        state["n"] += 1
        rv = orig_encrypt(session, data, size, output, output_length)
        if rv == app.CKR_OK and state["n"] in call_numbers:
            _to_ulong_ptr(output_length)[0] = app.CK_ULONG(0)
        return rv

    base_funcs["C_Encrypt"] = zeroing_encrypt
    return base_funcs


def make_operation(capacity):
    return {
        "mechanism": app.CK_MECHANISM(1, None, app.CK_ULONG(0)),
        "output_length": app.CK_ULONG(capacity),
    }


def encrypt_unit_funcs(steps, captured):
    """Unit-level fake for encrypt_with_generated_key (same shape as in
    test_encrypt_length_validation.py)."""

    def encrypt(_session, data, size, output, output_length):
        step = steps[captured.get("step", 0)] if captured.get("step", 0) < len(steps) else steps[-1]
        captured["step"] = captured.get("step", 0) + 1
        if step.get("capture") is not None:
            captured[step["capture"]] = ctypes.cast(
                output, ctypes.POINTER(app.CK_BYTE * step["capture_size"])
            ).contents
        payload = step.get("write", b"")
        if payload:
            ctypes.memmove(output, payload, len(payload))
        _to_ulong_ptr(output_length)[0] = app.CK_ULONG(step["report"])
        return step["rv"]

    return {
        "C_EncryptInit": lambda *_args: app.CKR_OK,
        "C_Encrypt": encrypt,
    }


ALGORITHM = {"name": "test", "encrypt_mechanism": 1}


class EncryptZeroLengthUnitTests(unittest.TestCase):
    def test_main_path_zero_length_raises(self):
        # Negative case: CKR_OK with reported length 0 on the main buffer.
        captured = {}
        funcs = encrypt_unit_funcs(
            [{"rv": app.CKR_OK, "report": 0, "write": b""}], captured,
        )
        buffer = (app.CK_BYTE * 8)()
        with self.assertRaises(app.InvalidModuleLengthError) as ctx:
            app.encrypt_with_generated_key(
                1, funcs, 1, ALGORITHM,
                app.CK_BYTE_PTR(), app.CK_ULONG(4), buffer, make_operation(8),
            )
        message = str(ctx.exception)
        self.assertIn("некорректную длину шифротекста", message)
        self.assertIn("0", message)
        self.assertIn("(ёмкость буфера 8)", message)

    def test_retry_path_zero_length_raises_and_wipes_temporary_buffer(self):
        # Negative case on the retry path: the module first reports
        # CKR_BUFFER_TOO_SMALL with needed = 12, then succeeds but reports a
        # zero length. The call must raise and the temporary retry buffer
        # must be wiped before the exception propagates.
        needed = 12
        captured = {}
        funcs = encrypt_unit_funcs(
            [
                {"rv": app.CKR_BUFFER_TOO_SMALL, "report": needed},
                {
                    "rv": app.CKR_OK,
                    "report": 0,
                    "write": b"\xC2" * needed,
                    "capture": "retry_buffer",
                    "capture_size": needed,
                },
            ],
            captured,
        )
        buffer = (app.CK_BYTE * 8)()
        with self.assertRaises(app.InvalidModuleLengthError) as ctx:
            app.encrypt_with_generated_key(
                1, funcs, 1, ALGORITHM,
                app.CK_BYTE_PTR(), app.CK_ULONG(4), buffer, make_operation(8),
            )
        message = str(ctx.exception)
        self.assertIn("некорректную длину шифротекста", message)
        self.assertIn("(ёмкость буфера 12)", message)
        # Resource cleanup: the retry buffer that received the ciphertext
        # must be zeroed on the new error path.
        self.assertEqual(bytes(captured["retry_buffer"]), b"\0" * needed)


class EncryptZeroLengthFileTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.file_path = Path(self.tmpdir.name) / "data.bin"
        self.file_path.write_bytes(b"PLAINTEXT-DATA" * 10)  # 140 bytes

    def tearDown(self):
        self.tmpdir.cleanup()

    def run_encrypt_file(self, count, warmup, zero_on_calls):
        calls = []
        state = {}
        funcs, memsets = encrypt_funcs(calls, [], state)
        decrypt_calls = []
        orig_decrypt = funcs["C_Decrypt"]

        def decrypt(*args):
            decrypt_calls.append(1)
            return orig_decrypt(*args)

        funcs["C_Decrypt"] = decrypt
        if zero_on_calls:
            zero_encrypt_lengths_on_call(funcs, zero_on_calls)

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

    def test_zero_length_not_masked_as_selfcheck_failure(self):
        # warmup(1) + measured(1): the second (measured) encryption reports
        # CKR_OK with length 0. encrypt_file must fail with
        # InvalidModuleLengthError (not SelfCheckError) BEFORE the decrypt
        # self-check is attempted.
        memsets, output, err, error, decrypt_calls = self.run_encrypt_file(
            1, 1, zero_on_calls={2},
        )
        self.assertIsInstance(error, app.InvalidModuleLengthError)
        self.assertNotIsInstance(error, app.SelfCheckError)
        self.assertIn("некорректную длину шифротекста", str(error))
        self.assertIn("(ёмкость буфера 172)", str(error))
        self.assertEqual(decrypt_calls, [], "C_Decrypt must not be called")
        # data buffer (140) and main ciphertext buffer (172) wiped in finally
        wiped_sizes = {size for _addr, size in memsets}
        self.assertIn(140, wiped_sizes)
        self.assertIn(172, wiped_sizes)

    def test_zero_length_after_good_ops_leaves_no_unwiped_buffers(self):
        # Multi-operation sequence: warmup ok, measured op1 ok, op2 zero.
        # Everything allocated so far must be wiped and no C_Decrypt call
        # must happen.
        memsets, output, err, error, decrypt_calls = self.run_encrypt_file(
            2, 1, zero_on_calls={3},
        )
        self.assertIsInstance(error, app.InvalidModuleLengthError)
        self.assertIn("некорректную длину шифротекста", str(error))
        self.assertEqual(decrypt_calls, [])
        wiped_sizes = {size for _addr, size in memsets}
        self.assertIn(140, wiped_sizes)
        self.assertIn(172, wiped_sizes)

    def test_normal_multi_op_flow_unaffected(self):
        # Control: without the zero-length fault the normal multi-operation
        # flow (warmup + 2 measured) still succeeds and self-check passes.
        memsets, output, err, error, decrypt_calls = self.run_encrypt_file(
            2, 1, zero_on_calls=set(),
        )
        self.assertIsNone(error)
        self.assertIn("Самопроверка расшифрованием: успешно", output)
        self.assertEqual(len(decrypt_calls), 1)


if __name__ == "__main__":
    unittest.main()
