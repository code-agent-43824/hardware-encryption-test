"""Regression tests: decrypt_and_check must not trust the pulPlaintextLen
reported by the (untrusted) PKCS#11 module.

Contract:
- If the module returns CKR_OK with a plaintext length greater than the
  capacity of the buffer that actually received the plaintext, decrypt_and_check
  must raise PKCS11Error with a diagnostic message BEFORE comparing plaintext
  contents: the comparison over a bogus length would mask a faulty module as a
  generic "self-check failed" error (same invariant already enforced for
  ulSignatureLen in sign_once and pulDigestLen in verify_signature).
- The plaintext buffer must still be wiped when the length check fails, and the
  caller's ciphertext copy is wiped as before (no leak of partially written
  sensitive data on the new error path).
- Normal flows are unaffected: a length equal to the buffer capacity is valid,
  and a multi-step sequence of decrypt self-checks keeps working.
"""
import ctypes
import unittest

import app


def decrypt_ok_funcs(plaintext_capacity, reported_length, captured):
    """Fake funcs: C_Decrypt writes reported_length bytes' worth of marker
    data and reports reported_length as the plaintext length."""

    def decrypt(_session, ciphertext, size, plaintext, length):
        written = min(reported_length, plaintext_capacity)
        if written:
            ctypes.memmove(plaintext, b"P" * written, written)
        ol = ctypes.cast(length, ctypes.POINTER(app.CK_ULONG))
        ol[0] = app.CK_ULONG(reported_length)
        captured["plaintext"] = ctypes.cast(
            plaintext, ctypes.POINTER(app.CK_BYTE * plaintext_capacity)
        ).contents
        return app.CKR_OK

    return {
        "C_DecryptInit": lambda *_args: app.CKR_OK,
        "C_Decrypt": decrypt,
    }


class DecryptLengthValidationTests(unittest.TestCase):
    def test_inflated_plaintext_length_raises_before_comparison(self):
        # Negative case: module returns CKR_OK with length > capacity.
        capacity = 6
        captured = {}
        funcs = decrypt_ok_funcs(capacity, reported_length=capacity + 8, captured=captured)
        with self.assertRaises(app.InvalidModuleLengthError) as ctx:
            app.decrypt_and_check(
                1, funcs, 1,
                {"name": "test", "encrypt_mechanism": 1},
                b"cipher", b"", b"PLAIN",
            )
        # Diagnostic must name the invalid length, not a generic self-check failure.
        message = str(ctx.exception)
        self.assertIn("некорректную длину открытого текста", message)
        self.assertIn(str(capacity + 8), message)
        self.assertIn(str(capacity), message)

    def test_inflated_length_plaintext_is_still_wiped(self):
        # Resource cleanup: the buffer that received the partial plaintext
        # must be wiped on the new error path too.
        capacity = 6
        captured = {}
        funcs = decrypt_ok_funcs(capacity, reported_length=capacity + 8, captured=captured)
        with self.assertRaises(app.InvalidModuleLengthError):
            app.decrypt_and_check(
                1, funcs, 1,
                {"name": "test", "encrypt_mechanism": 1},
                b"cipher", b"", b"PLAIN",
            )
        self.assertEqual(bytes(captured["plaintext"]), b"\0" * capacity)

    def test_valid_lengths_and_multi_step_sequence_still_work(self):
        # Positive case: exact-capacity length is valid, and a sequence of
        # several consecutive self-check operations keeps passing.
        capacity = 6
        for step in range(3):
            captured = {}
            funcs = decrypt_ok_funcs(capacity, reported_length=capacity, captured=captured)
            keepalive = app.decrypt_and_check(
                1, funcs, 1,
                {"name": "test", "encrypt_mechanism": 1},
                b"cipher", b"", b"PPPPPP",
            )
            # Empty params -> no keepalive buffer; the call must succeed
            # (no exception means the length check and plaintext comparison
            # both passed; the buffer is wiped by decrypt_and_check itself).
            self.assertIsNone(keepalive)


if __name__ == "__main__":
    unittest.main()
