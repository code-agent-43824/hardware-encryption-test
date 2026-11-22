"""Regression tests: find_objects cleanup must survive a C_FindObjectsFinal
binding that RAISES instead of returning a CK_RV.

A broken binding / funcs wrapper may raise a plain Python exception instead
of returning an rv — the same failure class encrypt_file's finally already
defends against for C_DestroyObject (commit 237bd81) and run_with_session
for C_Logout/C_CloseSession (commit b42fe8d). find_objects' finally used to
call C_FindObjectsFinal unguarded, so such an exception:
  1. masked the original PKCS11Error from C_FindObjects on the operation-
     failure path (raw exception replaced the diagnosed error);
  2. surfaced on the success path as "Неожиданная ошибка" + traceback in
     run_menu instead of a clean PKCS11Error cleanup failure.

Contract:
- Any exception from the C_FindObjectsFinal binding is converted into a
  PKCS11Error mentioning C_FindObjectsFinal (same channel as nonzero rv).
- On the operation-failure path the ORIGINAL error propagates and the
  cleanup failure is reported as a stderr warning.
- C_FindObjectsFinal is attempted exactly once per find_objects call on
  every path (no skipped or repeated finalize of the find operation).
- Holds for multi-batch sequences (Init -> Find* -> Final).
"""
import ctypes
import io
import unittest
from contextlib import redirect_stderr
from unittest import mock

import app


def _to_int(value):
    if isinstance(value, int):
        return value
    if hasattr(value, "value"):
        return int(value.value)
    return int(value)


def find_funcs(events, batch_counts=(2, 0), find_rv=app.CKR_OK, final_impl=None,
               session=7):
    """Minimal fake PKCS#11 for app.find_objects with event logging.

    batch_counts: objects returned by successive C_FindObjects calls.
    find_rv: return code of C_FindObjects (may be an error code).
    final_impl: optional callable replacing the default C_FindObjectsFinal
    (may return a nonzero rv or raise an arbitrary Python exception).
    """

    def find_objects_init(session_, template, count):
        events.append(("init", _to_int(session_)))
        return app.CKR_OK

    remaining = list(batch_counts)

    def find_objects(session_, batch, max_count, found_ptr):
        events.append(("find", _to_int(session_)))
        if find_rv != app.CKR_OK:
            return find_rv
        count = remaining.pop(0) if remaining else 0
        max_objects = _to_int(max_count)
        for index in range(min(count, max_objects)):
            batch[index] = 100 + index
        found = ctypes.cast(found_ptr, ctypes.POINTER(app.CK_ULONG)).contents
        found.value = min(count, max_objects)
        return app.CKR_OK

    def find_objects_final(session_):
        events.append(("final", _to_int(session_)))
        if final_impl is not None:
            return final_impl(session_)
        return app.CKR_OK

    return {
        "C_FindObjectsInit": find_objects_init,
        "C_FindObjects": find_objects,
        "C_FindObjectsFinal": find_objects_final,
    }


def call_find_objects(funcs, session=7, limit=32):
    stderr = io.StringIO()
    with redirect_stderr(stderr):
        try:
            objects = app.find_objects(session, funcs, [(0, 1)], limit=limit)
            error = None
        except BaseException as raised:
            objects, error = None, raised
    return objects, error, stderr.getvalue()


class FindObjectsFinalBindingExceptionTests(unittest.TestCase):
    def test_raising_final_on_success_path_raises_pkcs11_error(self):
        # Two-batch success sequence; the final binding raises.
        events = []
        funcs = find_funcs(
            events,
            batch_counts=(2, 0),
            final_impl=lambda session: (_ for _ in ()).throw(RuntimeError("binding blew up")),
        )
        objects, error, err = call_find_objects(funcs)

        self.assertIsNone(objects)
        self.assertIsNotNone(error)
        # The raw RuntimeError must NOT surface: it is converted into a
        # PKCS11Error mentioning C_FindObjectsFinal.
        self.assertIsInstance(error, app.PKCS11Error)
        self.assertNotIsInstance(error, RuntimeError)
        self.assertIn("C_FindObjectsFinal", str(error))
        self.assertIn("binding blew up", str(error))
        # Finalize attempted exactly once (no retry loops, not skipped).
        self.assertEqual(events.count(("final", 7)), 1)

    def test_raising_final_does_not_mask_find_error(self):
        # C_FindObjects fails, then the final binding raises: the ORIGINAL
        # error must propagate, the cleanup failure goes to stderr.
        events = []
        funcs = find_funcs(
            events,
            find_rv=app.CKR_SESSION_HANDLE_INVALID,
            final_impl=lambda session: (_ for _ in ()).throw(RuntimeError("binding blew up")),
        )
        objects, error, err = call_find_objects(funcs)

        self.assertIsNone(objects)
        self.assertIsNotNone(error)
        self.assertIsInstance(error, app.PKCS11Error)
        self.assertIn("C_FindObjects", str(error))
        self.assertNotIn("C_FindObjectsFinal", str(error))
        self.assertIn("Предупреждение при очистке после исходной ошибки", err)
        self.assertIn("C_FindObjectsFinal", err)
        self.assertIn("binding blew up", err)
        # The finalize was still attempted exactly once.
        self.assertEqual(events.count(("final", 7)), 1)

    def test_nonzero_final_rv_does_not_mask_find_error(self):
        # Pre-existing contract kept: nonzero rv from the final call on the
        # operation-failure path is a stderr warning, original error raised.
        events = []
        funcs = find_funcs(
            events,
            find_rv=app.CKR_SESSION_HANDLE_INVALID,
            final_impl=lambda session: 0x00000006,  # CKR_FUNCTION_FAILED
        )
        objects, error, err = call_find_objects(funcs)

        self.assertIsNone(objects)
        self.assertIsInstance(error, app.PKCS11Error)
        self.assertIn("C_FindObjects", str(error))
        self.assertNotIn("C_FindObjectsFinal", str(error))
        self.assertIn("Предупреждение при очистке после исходной ошибки", err)
        self.assertIn("C_FindObjectsFinal", err)
        self.assertEqual(events.count(("final", 7)), 1)

    def test_nonzero_final_rv_on_success_path_raises(self):
        # Pre-existing contract kept: nonzero rv on the success path raises
        # a PKCS11Error mentioning C_FindObjectsFinal.
        events = []
        funcs = find_funcs(events, batch_counts=(1, 0), final_impl=lambda session: 0x00000006)
        objects, error, err = call_find_objects(funcs)

        self.assertIsNone(objects)
        self.assertIsInstance(error, app.PKCS11Error)
        self.assertIn("C_FindObjectsFinal", str(error))
        self.assertEqual(err, "")
        self.assertEqual(events.count(("final", 7)), 1)

    def test_success_sequence_returns_objects_and_finalizes_once(self):
        # Multi-batch sequence: Init -> Find(2) -> Find(0) -> Final(OK).
        # The collected handles are returned and the find operation is
        # finalized exactly once (no leaked find state).
        events = []
        funcs = find_funcs(events, batch_counts=(2, 0))
        objects, error, err = call_find_objects(funcs)

        self.assertIsNone(error)
        self.assertEqual(err, "")
        self.assertEqual(objects, [100, 101])
        self.assertEqual(
            events,
            [("init", 7), ("find", 7), ("find", 7), ("final", 7)],
        )

    def test_error_path_also_finalizes_exactly_once(self):
        # Operation failure path: Init -> Find(error) -> Final, once.
        events = []
        funcs = find_funcs(events, find_rv=app.CKR_SESSION_HANDLE_INVALID)
        objects, error, err = call_find_objects(funcs)

        self.assertIsNone(objects)
        self.assertIsInstance(error, app.PKCS11Error)
        self.assertIn("C_FindObjects", str(error))
        self.assertEqual(err, "")
        self.assertEqual(
            events,
            [("init", 7), ("find", 7), ("final", 7)],
        )

    def test_zero_batches_finalizes_once(self):
        # Empty result set: Find(0) immediately ends the loop, Final once.
        events = []
        funcs = find_funcs(events, batch_counts=(0,))
        objects, error, err = call_find_objects(funcs)

        self.assertIsNone(error)
        self.assertEqual(objects, [])
        self.assertEqual(
            events,
            [("init", 7), ("find", 7), ("final", 7)],
        )


if __name__ == "__main__":
    unittest.main()
