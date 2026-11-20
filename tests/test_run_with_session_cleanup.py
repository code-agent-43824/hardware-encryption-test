"""Regression tests: run_with_session cleanup must survive raw exceptions.

close_session/logout raise only PKCS11Error, and run_with_session guarded them
with `except PKCS11Error` only. A binding/с-обёртка that raises a plain Python
exception instead of returning an rv (the failure class encrypt_file's finally
already defends against with `except BaseException`) used to:
  1. skip C_CloseSession entirely when C_Logout raised — leaking the session;
  2. mask the original action error with the unhandled cleanup exception;
  3. surface as "Неожиданная ошибка" + traceback instead of the clean
     cleanup-diagnostics path ("Предупреждение при очистке после исходной
     ошибки" / raised PKCS11Error).

The fix converts any cleanup exception into PKCS11Error and routes it through
the existing cleanup_errors machinery, so C_CloseSession is always attempted.
"""
import ctypes
import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

import app


def _to_int(v):
    if isinstance(v, int):
        return v
    if hasattr(v, "value"):
        return int(v.value)
    return int(v)


def cleanup_funcs(events, logout_impl=None, close_impl=None):
    """Minimal fake PKCS#11 for run_with_session with event logging.

    events records ("open"/"login"/"logout"/"close"/("op", n), session).
    logout_impl/close_impl: optional callables replacing the default
    implementations (may raise arbitrary Python exceptions).
    """

    def open_session(slot, flags, p1, p2, ph):
        ctypes.cast(ph, ctypes.POINTER(app.CK_SESSION_HANDLE)).contents.value = 42
        events.append(("open", 42))
        return app.CKR_OK

    def login(session, user_type, pin, pin_len):
        events.append(("login", _to_int(session)))
        return app.CKR_OK

    def logout(session):
        events.append(("logout", _to_int(session)))
        if logout_impl is not None:
            return logout_impl(session)
        return app.CKR_OK

    def close_session(session):
        events.append(("close", _to_int(session)))
        if close_impl is not None:
            return close_impl(session)
        return app.CKR_OK

    return {
        "C_OpenSession": open_session,
        "C_Login": login,
        "C_Logout": logout,
        "C_CloseSession": close_session,
    }


class RunWithSessionCleanupTests(unittest.TestCase):
    def setUp(self):
        self.events = []

    def run_session(self, funcs, action):
        """Run run_with_session with mocked PIN input; capture streams.

        Returns (stdout, stderr, raised_exception_or_None).
        """
        inputs = iter(["1234"])
        out, err = io.StringIO(), io.StringIO()
        raised = None
        with mock.patch("builtins.input", lambda *a: next(inputs)), \
             redirect_stdout(out), redirect_stderr(err):
            try:
                app.run_with_session(
                    funcs, 7, action, rw=True, login_required=True,
                )
            except Exception as error:  # noqa: BLE001 - test observes it
                raised = error
        return out.getvalue(), err.getvalue(), raised

    def test_logout_raw_exception_keeps_original_error_and_closes_session(self):
        # Negative case: action fails with PKCS11Error AND the binding raises
        # a raw RuntimeError from C_Logout. The original error must win,
        # C_CloseSession must still run (no session leak), and the cleanup
        # problem must be reported as a warning, not replace the error.
        def broken_logout(session):
            raise RuntimeError("library crashed during C_Logout")

        ops = []

        def action(session, api):
            ops.append(session)
            raise app.PKCS11Error("C_Sign", 0x00000005)

        funcs = cleanup_funcs(self.events, logout_impl=broken_logout)
        out, err, raised = self.run_session(funcs, action)

        self.assertIsInstance(raised, app.PKCS11Error)
        self.assertIn("C_Sign: 0x00000005", str(raised))
        # Resource cleanup: the session was closed despite the logout failure.
        self.assertIn(("close", 42), self.events)
        self.assertIn("Предупреждение при очистке после исходной ошибки", err)
        self.assertIn("C_Logout: RuntimeError: library crashed", err)
        self.assertNotIn("Неожиданная ошибка", out)

    def test_logout_raw_exception_on_success_raises_clean_pkcs11_error(self):
        # Negative case: action succeeds, C_Logout raises a raw exception.
        # It must surface as PKCS11Error (run_menu prints it cleanly without
        # a traceback) instead of an unhandled RuntimeError.
        def broken_logout(session):
            raise RuntimeError("library crashed during C_Logout")

        funcs = cleanup_funcs(self.events, logout_impl=broken_logout)
        out, err, raised = self.run_session(funcs, lambda s, a: None)

        self.assertIsInstance(raised, app.PKCS11Error)
        self.assertIn("C_Logout: RuntimeError: library crashed", str(raised))
        self.assertIn(("close", 42), self.events)

    def test_logout_raw_and_close_pkcs11_both_reported(self):
        # Negative case: BOTH cleanup calls fail (raw + PKCS11Error) after a
        # successful action. The first error is raised, the second must still
        # be reported (and close must have been attempted).
        def broken_logout(session):
            raise RuntimeError("logout crashed")

        def broken_close(session):
            return 0x00000030  # CKR_DEVICE_ERROR

        funcs = cleanup_funcs(self.events, logout_impl=broken_logout, close_impl=broken_close)
        out, err, raised = self.run_session(funcs, lambda s, a: None)

        self.assertIsInstance(raised, app.PKCS11Error)
        self.assertIn("C_Logout: RuntimeError: logout crashed", str(raised))
        self.assertIn("Дополнительная ошибка очистки", err)
        self.assertIn("C_CloseSession: 0x", err)

    def test_multi_operation_action_failure_with_cleanup_failures(self):
        # Multi-step sequence: three operations, the third raises PKCS11Error,
        # then logout raises a raw exception and close a PKCS11Error. All three
        # operations must have run, the original error must propagate, both
        # cleanup problems must be warned about, and the session must be closed.
        def broken_logout(session):
            raise RuntimeError("logout crashed")

        def broken_close(session):
            return 0x00000030  # CKR_DEVICE_ERROR

        def action(session, api):
            for n in range(3):
                self.events.append(("op", n + 1))
                if n == 2:
                    raise app.PKCS11Error("C_Encrypt", 0x00000006)

        funcs = cleanup_funcs(self.events, logout_impl=broken_logout, close_impl=broken_close)
        out, err, raised = self.run_session(funcs, action)

        # The sequence really ran to its third operation before failing.
        self.assertIn(("op", 1), self.events)
        self.assertIn(("op", 2), self.events)
        self.assertIn(("op", 3), self.events)
        self.assertIsInstance(raised, app.PKCS11Error)
        self.assertIn("C_Encrypt: 0x00000006", str(raised))
        self.assertIn(("logout", 42), self.events)
        # Resource cleanup: close attempted despite both failures.
        self.assertIn(("close", 42), self.events)
        self.assertIn("Предупреждение при очистке после исходной ошибки", err)
        self.assertIn("C_Logout: RuntimeError", err)
        self.assertIn("C_CloseSession: 0x", err)

    def test_close_raw_exception_on_success_raises_clean_pkcs11_error(self):
        # Negative case: only C_CloseSession raises a raw exception after a
        # successful action — it must become PKCS11Error, not escape raw.
        def broken_close(session):
            raise OSError("device disappeared")

        funcs = cleanup_funcs(self.events, close_impl=broken_close)
        out, err, raised = self.run_session(funcs, lambda s, a: None)

        self.assertIsInstance(raised, app.PKCS11Error)
        self.assertIn("C_CloseSession: OSError: device disappeared", str(raised))

    def test_happy_path_unaffected(self):
        # Sanity: no failures → open, login, action, logout, close, no errors.
        done = []
        funcs = cleanup_funcs(self.events)
        out, err, raised = self.run_session(
            funcs, lambda s, a: done.append(_to_int(s)),
        )

        self.assertIsNone(raised)
        self.assertEqual(done, [42])
        self.assertEqual(
            self.events,
            [("open", 42), ("login", 42), ("logout", 42), ("close", 42)],
        )
        self.assertEqual(err, "")


if __name__ == "__main__":
    unittest.main()
