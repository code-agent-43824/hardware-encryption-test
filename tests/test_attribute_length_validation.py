"""Regression tests: the attribute length reported by the (untrusted)
PKCS#11 module in C_GetAttributeValue's size-query call must be validated
BEFORE allocation in attr_bytes.

Contract:
- attr_bytes asks the module for the attribute length (pValue=NULL), then
  allocates create_string_buffer(size). A hostile or buggy module answering
  CKR_OK with an absurd ulValueLen (e.g. 3 GiB) previously sent that value
  straight into the allocation: MemoryError (unexpected exception with a
  traceback in run_menu) or swap thrash instead of a diagnosable module
  error. The size must be rejected with InvalidModuleLengthError BEFORE the
  buffer is allocated and BEFORE the second C_GetAttributeValue call — the
  same "untrusted length validated before use" contract as
  encrypt_with_generated_key / sign_once (retry sizes, 56a3c4f) and
  signature_buffer_length (CKA_MODULUS_BITS, 0408d86). The latter reads the
  attribute THROUGH attr_bytes, so without this guard its own capacity
  validation ran only after the unguarded allocation.
- CKR_ATTRIBUTE_TYPE_INVALID -> None, ATTR_UNAVAILABLE -> None, size 0 -> b""
  (existing behavior unchanged).
- Normal multi-step attribute sequences (several reads in a row, e.g. ID,
  label, modulus bits) are unaffected; a rejected read performs no
  allocation and exactly one module call (no half-built buffers left).
"""
import ctypes
import unittest
from unittest import mock

import app

# Portable "gigantic" value: greater than MAX_RETRY_OUTPUT_BYTES (1 GiB) but
# fits into a 32-bit CK_ULONG on Windows (same convention as
# test_retry_allocation_validation.HUGE_NEEDED).
HUGE_SIZE = 3 << 30


def make_attr_funcs(steps, call_log):
    """Fake C_GetAttributeValue scripted per call.

    steps: list of ('size', n) — size-query answer; ('data', payload) — data
    answer; ('type_invalid',) — CKR_ATTRIBUTE_TYPE_INVALID; ('rv', code) —
    raw return code. Extra calls repeat the last step.
    """
    state = {"n": 0}

    def get_attribute_value(session, handle, template, count):
        state["n"] += 1
        call_log.append(state["n"])
        idx = min(state["n"], len(steps)) - 1
        kind, payload = steps[idx][0], steps[idx][1] if len(steps[idx]) > 1 else None
        t = template[0]
        if kind == "type_invalid":
            return app.CKR_ATTRIBUTE_TYPE_INVALID
        if kind == "rv":
            return payload
        if kind == "size":
            t.ulValueLen = app.CK_ULONG(payload)
            return app.CKR_OK
        if kind == "data":
            t.ulValueLen = app.CK_ULONG(len(payload))
            if t.pValue:
                ctypes.memmove(t.pValue, payload, len(payload))
            return app.CKR_OK
        raise AssertionError(f"unknown step kind: {kind}")

    return {"C_GetAttributeValue": get_attribute_value}


class AttributeLengthValidationTests(unittest.TestCase):
    def test_hostile_size_rejected_before_allocation_and_second_call(self):
        call_log = []
        funcs = make_attr_funcs([("size", HUGE_SIZE)], call_log)
        # If the guarded allocation is attempted, the test must fail loudly
        # (the allocation itself would be a real MemoryError in production).
        with mock.patch.object(
            ctypes, "create_string_buffer",
            side_effect=AssertionError("allocation attempted with unvalidated size"),
        ):
            with self.assertRaises(app.InvalidModuleLengthError) as ctx:
                app.attr_bytes(1, funcs, 7, app.CKA_LABEL)
        # Exactly one module call: the size query. No data call, no allocation.
        self.assertEqual(call_log, [1])
        self.assertIn(f"0x{app.CKA_LABEL:08X}", str(ctx.exception))
        self.assertIn(str(HUGE_SIZE), str(ctx.exception))

    def test_normal_sequence_of_reads_unaffected(self):
        call_log = []
        funcs = make_attr_funcs(
            [
                ("size", 1), ("data", b"\x01"),        # CKA_ID read
                ("size", 5), ("data", b"KEY-1"),       # label read
                ("size", 8), ("data", bytes(app.CK_ULONG(2048))),  # modulus bits
            ],
            call_log,
        )
        self.assertEqual(app.attr_bytes(1, funcs, 7, app.CKA_ID), b"\x01")
        self.assertEqual(app.attr_bytes(1, funcs, 7, app.CKA_LABEL), b"KEY-1")
        self.assertEqual(app.attr_ulong(1, funcs, 7, app.CKA_MODULUS_BITS), 2048)
        # Resource discipline: every read is exactly two module calls
        # (size query + data), no hidden extra calls.
        self.assertEqual(call_log, [1, 2, 3, 4, 5, 6])

    def test_existing_special_cases_unchanged(self):
        call_log = []
        funcs = make_attr_funcs([("type_invalid",)], call_log)
        self.assertIsNone(app.attr_bytes(1, funcs, 7, app.CKA_LABEL))
        funcs = make_attr_funcs([("size", app.ATTR_UNAVAILABLE)], call_log)
        self.assertIsNone(app.attr_bytes(1, funcs, 7, app.CKA_LABEL))
        funcs = make_attr_funcs([("size", 0)], call_log)
        self.assertEqual(app.attr_bytes(1, funcs, 7, app.CKA_LABEL), b"")

    def test_signature_buffer_length_hostile_module_length_rejected(self):
        # End-to-end path: signature_buffer_length reads CKA_MODULUS_BITS via
        # attr_ulong -> attr_bytes. A module reporting a huge attribute length
        # must produce InvalidModuleLengthError ( diagnosable module failure),
        # not MemoryError — the guard must fire BEFORE the 0408d86 capacity
        # check, which runs only after the attribute has been read.
        call_log = []
        funcs = make_attr_funcs([("size", HUGE_SIZE)], call_log)
        pair = {"algorithm": app.CKK_RSA, "public": 7, "private": 8}
        with mock.patch.object(
            ctypes, "create_string_buffer",
            side_effect=AssertionError("allocation attempted with unvalidated size"),
        ):
            with self.assertRaises(app.InvalidModuleLengthError):
                app.signature_buffer_length(1, funcs, pair)
        self.assertEqual(call_log, [1])

    def test_hostile_read_then_valid_read_sequence(self):
        # Multi-operation sequence: first read raises, the caller may continue
        # (run_menu returns to menu), and a subsequent read on the same funcs
        # object still works correctly.
        call_log = []
        funcs = make_attr_funcs(
            [("size", HUGE_SIZE), ("size", 4), ("data", b"ABCD")],
            call_log,
        )
        with self.assertRaises(app.InvalidModuleLengthError):
            app.attr_bytes(1, funcs, 7, app.CKA_LABEL)
        self.assertEqual(app.attr_bytes(1, funcs, 7, app.CKA_LABEL), b"ABCD")
        self.assertEqual(call_log, [1, 2, 3])


if __name__ == "__main__":
    unittest.main()
