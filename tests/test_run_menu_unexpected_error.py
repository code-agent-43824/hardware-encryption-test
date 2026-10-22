"""Regression tests: run_menu must not swallow unexpected exceptions silently.

An unexpected exception (a bug in the tool itself, e.g. TypeError/AttributeError)
must leave a full traceback in stderr while keeping the user-facing message and
menu continuity. Expected PKCS11Error handling stays clean (no traceback), and
SelfCheckError must still propagate to main (exit code 1).
"""

import ctypes
import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

import app


class RunMenuUnexpectedErrorTests(unittest.TestCase):
    def run_menu_with_inputs(self, funcs, choices):
        inputs = iter(choices)
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("builtins.input", lambda *a: next(inputs)), \
             redirect_stdout(out), redirect_stderr(err):
            app.run_menu(funcs, 1)
        return out.getvalue(), err.getvalue()

    def test_unexpected_error_prints_traceback_to_stderr_and_menu_continues(self):
        # Multi-step sequence: first menu action raises an unexpected
        # exception, the menu must keep working afterwards ("0" exits).
        def broken_action(funcs, slot_id, action):
            raise RuntimeError("boom: unexpected bug")

        with mock.patch.object(app, "run_with_session", broken_action):
            out, err = self.run_menu_with_inputs({}, ["1", "0"])

        self.assertIn("Неожиданная ошибка: boom: unexpected bug", out)
        # The full stack trace must be preserved in stderr.
        self.assertIn("Traceback (most recent call last)", err)
        self.assertIn("RuntimeError: boom: unexpected bug", err)
        self.assertIn("broken_action", err)
        # The menu kept working: the exit option was processed (no error).
        self.assertNotIn("Неизвестный пункт меню", out)

    def test_pkcs11_error_stays_clean_without_traceback(self):
        # Negative case: expected PKCS11Error must NOT produce a traceback.
        def failing_action(funcs, slot_id, action):
            raise app.PKCS11Error("C_Sign", 0x00000005)

        with mock.patch.object(app, "run_with_session", failing_action):
            out, err = self.run_menu_with_inputs({}, ["1", "0"])

        self.assertIn("Ошибка: C_Sign: 0x00000005", out)
        self.assertNotIn("Traceback", err)
        self.assertNotIn("Неожиданная ошибка", out)

    def test_self_check_error_still_propagates(self):
        # Negative case: SelfCheckError must reach main (exit code 1),
        # not be swallowed as an unexpected error.
        def selfcheck_action(funcs, slot_id, action):
            raise app.SelfCheckError("Самопроверка не пройдена")

        with mock.patch.object(app, "run_with_session", selfcheck_action):
            with self.assertRaises(app.SelfCheckError):
                self.run_menu_with_inputs({}, ["1"])

        # No "unexpected error" handling may intercept it.
        # (assertRaises above already proves propagation; here we additionally
        # verify no retry/continue happened by the exception escaping run_menu.)


if __name__ == "__main__":
    unittest.main()
