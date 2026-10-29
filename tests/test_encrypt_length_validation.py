"""Regression tests: encrypt_with_generated_key must not trust the ciphertext
length reported by the (untrusted) PKCS#11 module.

Contract:
- If the module returns CKR_OK with a ciphertext length greater than the
  capacity of the buffer that actually received the ciphertext (both the main
  path and the CKR_BUFFER_TOO_SMALL retry path), encrypt_with_generated_key
  must raise PKCS11Error with a diagnostic message instead of returning a
  bogus length: the caller would otherwise silently operate on a clamped
  memoryview, mask the faulty module as a generic "self-check failed" error,
  and print an impossible ciphertext size (same invariant already enforced
  for ulSignatureLen, pulDigestLen and pulPlaintextLen).
- On the retry path the temporary buffer must still be wiped when the length
  check fails (no leak of partially written sensitive data).
- Normal flows are unaffected: a length equal to the buffer capacity is valid,
  and a multi-step sequence mixing main-path and retry-path operations keeps
  working.
"""
import ctypes
import unittest

import app


def _to_ulong_ptr(raw):
    return ctypes.cast(raw, ctypes.POINTER(app.CK_ULONG))


def encrypt_ok_funcs(steps, captured):
    """Fake PKCS#11 for encrypt_with_generated_key.

    steps: list of dicts consumed per C_Encrypt call (last entry repeats):
      {"rv": rv, "report": length_to_report, "write": bytes_to_write}
    Captures the buffer contents of the retry path (the C_Encrypt call that
    receives a fresh pointer) so the test can check the wipe.
    """

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
        ol = _to_ulong_ptr(output_length)
        ol[0] = app.CK_ULONG(step["report"])
        return step["rv"]

    return {
        "C_EncryptInit": lambda *_args: app.CKR_OK,
        "C_Encrypt": encrypt,
    }


def make_operation(capacity):
    return {
        "mechanism": app.CK_MECHANISM(1, None, app.CK_ULONG(0)),
        "output_length": app.CK_ULONG(capacity),
    }


ALGORITHM = {"name": "test", "encrypt_mechanism": 1}


class EncryptLengthValidationTests(unittest.TestCase):
    def test_main_path_inflated_length_raises(self):
        # Negative case: CKR_OK with reported length > buffer capacity.
        capacity = 8
        captured = {}
        funcs = encrypt_ok_funcs(
            [{"rv": app.CKR_OK, "report": capacity + 16, "write": b"\xC1" * capacity}],
            captured,
        )
        buffer = (app.CK_BYTE * capacity)()
        with self.assertRaises(app.InvalidModuleLengthError) as ctx:
            app.encrypt_with_generated_key(
                1, funcs, 1, ALGORITHM,
                app.CK_BYTE_PTR(), app.CK_ULONG(4), buffer, make_operation(capacity),
            )
        message = str(ctx.exception)
        self.assertIn("некорректную длину шифротекста", message)
        self.assertIn(str(capacity + 16), message)
        self.assertIn(str(capacity), message)

    def test_retry_path_inflated_length_raises_and_wipes_temporary_buffer(self):
        # Negative case on the retry path: the module first reports
        # CKR_BUFFER_TOO_SMALL with needed = 12, then succeeds but reports a
        # length greater than the retry buffer capacity. The call must raise
        # and the temporary retry buffer must be wiped before the exception
        # propagates.
        needed = 12
        captured = {}
        funcs = encrypt_ok_funcs(
            [
                {"rv": app.CKR_BUFFER_TOO_SMALL, "report": needed},
                {
                    "rv": app.CKR_OK,
                    "report": needed + 8,
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
        self.assertIn(str(needed + 8), message)
        self.assertIn(str(needed), message)
        # Resource cleanup: the retry buffer that received the ciphertext
        # must be zeroed on the new error path.
        self.assertEqual(bytes(captured["retry_buffer"]), b"\0" * needed)

    def test_valid_lengths_and_multi_step_sequence_still_work(self):
        # Positive case: exact-capacity lengths are valid on both paths, and
        # a sequence of several consecutive operations (main, retry, main)
        # keeps working.
        capacity = 8
        captured = {}
        funcs = encrypt_ok_funcs(
            [
                {"rv": app.CKR_OK, "report": capacity, "write": b"\xA1" * capacity},
                {"rv": app.CKR_BUFFER_TOO_SMALL, "report": 6},
                {"rv": app.CKR_OK, "report": 6, "write": b"\xA2" * 6},
                {"rv": app.CKR_OK, "report": capacity, "write": b"\xA3" * capacity},
            ],
            captured,
        )
        results = []
        for _ in range(3):
            buffer = (app.CK_BYTE * capacity)()
            length, _, out = app.encrypt_with_generated_key(
                1, funcs, 1, ALGORITHM,
                app.CK_BYTE_PTR(), app.CK_ULONG(4), buffer, make_operation(capacity),
            )
            results.append((length, out is not buffer))
        self.assertEqual(results, [(capacity, False), (6, True), (capacity, False)])


if __name__ == "__main__":
    unittest.main()
