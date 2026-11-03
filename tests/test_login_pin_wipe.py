"""Regression tests: the token PIN passed to C_Login must be wiped.

Contract: login() copies the PIN into a wipeable ctypes buffer, passes that
buffer to C_Login, and wipes it on every exit path — success (CKR_OK),
CKR_USER_ALREADY_LOGGED_IN, CKR_PIN_INCORRECT, an unknown CKR_ value, and an
exception raised after the call. Previously the PIN was passed as an immutable
bytes object (c_char_p), so the token credential — the most sensitive datum in
the process — stayed in the heap until GC, while every other sensitive buffer
(files, plaintexts, ciphertexts, signatures, digests) is wiped by this tool.

The captured C_Login buffer address must receive a ctypes.memset(addr, 0, len)
event: without the fix no memset ever touches the PIN buffer, so every test
below fails on the old code.
"""
import contextlib
import ctypes
import io
import unittest
from unittest import mock

import app

UNKNOWN_RV = 0x000006FF


def logging_memset_factory(events):
    orig_memset = ctypes.memset

    def logging_memset(addr, value, size):
        addr_value = addr if isinstance(addr, int) else ctypes.cast(addr, ctypes.c_void_p).value
        events.append((addr_value, size))
        return orig_memset(addr, value, size)

    return logging_memset


def login_funcs(script, calls):
    """Fake funcs: scripted C_Login results; each call records the PIN buffer
    address, its length and the PIN bytes visible at call time."""

    def c_login(session, user_type, pin, pin_length):
        addr = ctypes.cast(pin, ctypes.c_void_p).value
        length = app.native_int(pin_length)
        calls.append(
            {
                "addr": addr,
                "length": length,
                "pin_seen": ctypes.string_at(addr, length),
            }
        )
        return script[len(calls) - 1]

    def c_logout(session):
        return app.CKR_OK

    return {"C_Login": c_login, "C_Logout": c_logout}


class LoginPinWipeTests(unittest.TestCase):
    def run_login(self, pin_input, script):
        calls, events = [], []
        funcs = login_funcs(script, calls)
        error = None
        result = None
        inputs = iter([pin_input])
        with mock.patch.object(ctypes, "memset", logging_memset_factory(events)), \
             mock.patch("sys.stdin", mock.Mock(isatty=lambda: False)), \
             mock.patch("builtins.input", lambda *a: next(inputs)), \
             contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            try:
                result = app.login(funcs, 1)
            except app.PKCS11Error as exc:
                error = exc
        return result, error, calls, events

    def assert_pin_buffer_wiped(self, calls, events):
        self.assertEqual(len(calls), 1)
        self.assertIn((calls[0]["addr"], calls[0]["length"]), events)

    def test_successful_login_passes_pin_and_wipes_buffer(self):
        result, error, calls, events = self.run_login("2468", [app.CKR_OK])
        self.assertIs(error, None)
        self.assertTrue(result)
        self.assertEqual(calls[0]["pin_seen"], b"2468")
        self.assert_pin_buffer_wiped(calls, events)

    def test_default_pin_used_and_wiped_on_success(self):
        result, error, calls, events = self.run_login("", [app.CKR_OK])
        self.assertIs(error, None)
        self.assertTrue(result)
        self.assertEqual(calls[0]["pin_seen"], app.DEFAULT_PIN.encode("utf-8"))
        self.assert_pin_buffer_wiped(calls, events)

    def test_wrong_pin_error_still_wipes_buffer(self):
        result, error, calls, events = self.run_login("9999", [app.CKR_PIN_INCORRECT])
        self.assertIs(result, None)
        self.assertIsInstance(error, app.PKCS11Error)
        self.assertEqual(error.rv, app.CKR_PIN_INCORRECT)
        self.assertEqual(calls[0]["pin_seen"], b"9999")
        self.assert_pin_buffer_wiped(calls, events)

    def test_already_logged_in_returns_false_and_wipes_buffer(self):
        result, error, calls, events = self.run_login("1357", [app.CKR_USER_ALREADY_LOGGED_IN])
        self.assertIs(error, None)
        self.assertFalse(result)
        self.assertEqual(calls[0]["pin_seen"], b"1357")
        self.assert_pin_buffer_wiped(calls, events)

    def test_unknown_rv_raises_and_wipes_buffer(self):
        result, error, calls, events = self.run_login("1357", [UNKNOWN_RV])
        self.assertIs(result, None)
        self.assertIsInstance(error, app.PKCS11Error)
        self.assert_pin_buffer_wiped(calls, events)

    def test_consecutive_logins_use_distinct_wiped_buffers(self):
        # Многошаговая последовательность: логин -> logout -> логин с другим PIN.
        # Каждый PIN получает собственный буфер, и оба затираются после своих
        # вызовов C_Login.
        script = [app.CKR_OK, app.CKR_OK]
        calls, events = [], []
        funcs = login_funcs(script, calls)
        inputs = iter(["1111", "2222"])

        def fake_input(*_a):
            return next(inputs)

        with mock.patch.object(ctypes, "memset", logging_memset_factory(events)), \
             mock.patch("sys.stdin", mock.Mock(isatty=lambda: False)), \
             mock.patch("builtins.input", fake_input), \
             contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            self.assertTrue(app.login(funcs, 1))
            app.logout(funcs, 1)
            self.assertTrue(app.login(funcs, 1))

        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0]["pin_seen"], b"1111")
        self.assertEqual(calls[1]["pin_seen"], b"2222")
        self.assertNotEqual(calls[0]["addr"], calls[1]["addr"])
        self.assertIn((calls[0]["addr"], calls[0]["length"]), events)
        self.assertIn((calls[1]["addr"], calls[1]["length"]), events)


if __name__ == "__main__":
    unittest.main()
