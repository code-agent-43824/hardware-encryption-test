"""Regression tests: element counts returned by the untrusted module for
C_GetMechanismList / C_GetSlotList must be validated BEFORE allocation, and
the count written back by the second (data) call must be validated against
the allocated capacity BEFORE indexing.

Contract:
- A module reporting an absurd element count (> app.MAX_MODULE_LIST_COUNT)
  on the sizing call causes InvalidModuleLengthError before the
  (type * count)() allocation is attempted: no second C_GetMechanismList /
  C_GetSlotList call happens (previously the value went straight into the
  allocation: MemoryError with a traceback in run_menu or swap thrash).
- A module answering the data call with CKR_OK but an inflated count (larger
  than the allocated capacity) causes InvalidModuleLengthError instead of an
  out-of-bounds read via mechanisms[index] / slots[index].
- Sane counts (including the boundary value == MAX_MODULE_LIST_COUNT) keep
  working, and repeated (multi-operation) calls on the same funcs keep
  working after a rejected attempt: no leaked state from the failure.
- get_token_slots keeps its existing behavior for count == 0
  ("Токен не найден" PKCS11Error).

HUGE_COUNT is portable: it exceeds MAX_MODULE_LIST_COUNT (1 << 16) but fits
into a 32-bit CK_ULONG on Windows (c_ulong = 4 bytes).
"""
import ctypes
import unittest

import app
from test_file_input_errors import _to_int

HUGE_COUNT = 1 << 20
BOUNDARY_COUNT = app.MAX_MODULE_LIST_COUNT


def count_pointer(pulCount):
    return ctypes.cast(pulCount, ctypes.POINTER(app.CK_ULONG))


class FakeModule:
    """Scripted fake for C_GetMechanismList / C_GetSlotList count flows."""

    def __init__(self, first_count, second_count, mechanism_types=(), slot_ids=()):
        self.first_count = first_count
        self.second_count = second_count
        self.mechanism_types = list(mechanism_types)
        self.slot_ids = list(slot_ids)
        self.mechanism_calls = []
        self.slot_calls = []

    def mechanism_list(self, slot_id, buffer, pulCount):
        self.mechanism_calls.append("data" if buffer else "count")
        out = count_pointer(pulCount)
        if len(self.mechanism_calls) == 1:
            out[0] = app.CK_ULONG(self.first_count)
            return app.CKR_OK
        out[0] = app.CK_ULONG(self.second_count)
        if buffer and self.second_count <= self.first_count:
            for index, value in enumerate(self.mechanism_types):
                buffer[index] = app.CK_MECHANISM_TYPE(value)
        return app.CKR_OK

    def slot_list(self, token_present, buffer, pulCount):
        self.slot_calls.append("data" if buffer else "count")
        out = count_pointer(pulCount)
        if len(self.slot_calls) == 1:
            out[0] = app.CK_ULONG(self.first_count)
            return app.CKR_OK
        out[0] = app.CK_ULONG(self.second_count)
        if buffer and self.second_count <= self.first_count:
            for index, value in enumerate(self.slot_ids):
                buffer[index] = app.CK_SLOT_ID(value)
        return app.CKR_OK

    def funcs(self):
        return {
            "C_GetMechanismList": self.mechanism_list,
            "C_GetSlotList": self.slot_list,
        }


class MechanismListCountValidationTests(unittest.TestCase):
    def test_huge_count_rejected_before_allocation(self):
        fake = FakeModule(first_count=HUGE_COUNT, second_count=0)
        with self.assertRaises(app.InvalidModuleLengthError) as ctx:
            app.get_mechanism_list(fake.funcs(), 1)
        # Отказ до аллокации: второго (data) вызова нет, гигантский буфер
        # не выделялся.
        self.assertEqual(fake.mechanism_calls, ["count"])
        self.assertIn(str(HUGE_COUNT), str(ctx.exception))
        self.assertIn(str(app.MAX_MODULE_LIST_COUNT), str(ctx.exception))

    def test_inflated_second_count_rejected_before_indexing(self):
        fake = FakeModule(first_count=3, second_count=5,
                          mechanism_types=[1, 2, 3])
        with self.assertRaises(app.InvalidModuleLengthError) as ctx:
            app.get_mechanism_list(fake.funcs(), 1)
        self.assertEqual(fake.mechanism_calls, ["count", "data"])
        self.assertIn("ёмкости буфера 3", str(ctx.exception))

    def test_sane_counts_return_list_and_repeatable_calls(self):
        fake = FakeModule(first_count=3, second_count=3,
                          mechanism_types=[0x11223344, 0x55667788, 2])
        funcs = fake.funcs()
        first = app.get_mechanism_list(funcs, 1)
        second = app.get_mechanism_list(funcs, 1)
        self.assertEqual(first, [0x11223344, 0x55667788, 2])
        self.assertEqual(second, first)
        self.assertEqual(fake.mechanism_calls, ["count", "data", "count", "data"])

    def test_boundary_count_still_accepted(self):
        fake = FakeModule(first_count=BOUNDARY_COUNT, second_count=1,
                          mechanism_types=[7])
        result = app.get_mechanism_list(fake.funcs(), 1)
        self.assertEqual(result, [7])

    def test_state_clean_after_rejected_attempt(self):
        huge = FakeModule(first_count=HUGE_COUNT, second_count=0)
        with self.assertRaises(app.InvalidModuleLengthError):
            app.get_mechanism_list(huge.funcs(), 1)
        sane = FakeModule(first_count=2, second_count=2,
                          mechanism_types=[9, 10])
        funcs = sane.funcs()
        self.assertEqual(app.get_mechanism_list(funcs, 1), [9, 10])
        self.assertEqual(app.get_mechanism_list(funcs, 1), [9, 10])


class TokenSlotsCountValidationTests(unittest.TestCase):
    def test_huge_count_rejected_before_allocation(self):
        fake = FakeModule(first_count=HUGE_COUNT, second_count=0)
        with self.assertRaises(app.InvalidModuleLengthError) as ctx:
            app.get_token_slots(fake.funcs())
        self.assertEqual(fake.slot_calls, ["count"])
        self.assertIn(str(HUGE_COUNT), str(ctx.exception))

    def test_inflated_second_count_rejected_before_indexing(self):
        fake = FakeModule(first_count=2, second_count=9, slot_ids=[4, 5])
        with self.assertRaises(app.InvalidModuleLengthError) as ctx:
            app.get_token_slots(fake.funcs())
        self.assertEqual(fake.slot_calls, ["count", "data"])
        self.assertIn("ёмкости буфера 2", str(ctx.exception))

    def test_sane_counts_return_slots(self):
        fake = FakeModule(first_count=2, second_count=2, slot_ids=[4, 5])
        self.assertEqual(app.get_token_slots(fake.funcs()), [4, 5])

    def test_zero_count_still_reports_no_token(self):
        fake = FakeModule(first_count=0, second_count=0)
        with self.assertRaises(app.PKCS11Error) as ctx:
            app.get_token_slots(fake.funcs())
        self.assertNotIsInstance(ctx.exception, app.InvalidModuleLengthError)
        self.assertIn("Токен не найден", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
