"""Regression tests for the retry-buffer wipe ordering in sign_file.

sign_file must wipe the previous measured iteration's retry buffer (holding
the previous signature) BEFORE starting the next sign operation. Previously
the memset ran only after sign_once of the next operation returned (or in the
finally-block), so a failure inside the next operation (C_SignInit/C_Sign) or
a crash of the untrusted module left the previous retry buffer holding a
sensitive signature in memory until the finally-block ran (forever on a
crash). encrypt_file already enforces this order (see
test_encrypt_retry_wipe_order.py); the measured sign loop must match.
"""
import ctypes
import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import app
from test_file_input_errors import _to_int, sign_pair_funcs


def wrap_sign_init(funcs, events, init_results):
    """Replace C_SignInit with a version that logs ("signinit", n, rv) and
    returns scripted result codes (last entry repeats; None → always OK)."""
    state = {"n": 0}

    def sign_init(session, mechanism, key):
        state["n"] += 1
        if init_results is None:
            rv = app.CKR_OK
        else:
            idx = min(state["n"] - 1, len(init_results) - 1)
            rv = init_results[idx]
        events.append(("signinit", state["n"], rv))
        return rv

    funcs["C_SignInit"] = sign_init
    return funcs


def log_sign_calls(funcs, events):
    """Also log every C_Sign call as ("sign", output_addr) into `events`, so
    wipe (memset) events can be compared chronologically with sign calls."""

    orig_sign = funcs["C_Sign"]

    def sign(session, data, size, output, output_length):
        addr = ctypes.cast(output, ctypes.c_void_p).value
        events.append(("sign", addr))
        return orig_sign(session, data, size, output, output_length)

    funcs["C_Sign"] = sign
    return funcs


class SignRetryWipeOrderTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.file_path = Path(self.tmpdir.name) / "data.bin"
        self.file_path.write_bytes(b"PLAINTEXT-DATA" * 10)

    def tearDown(self):
        self.tmpdir.cleanup()

    def _memset_events(self, events):
        orig_memset = ctypes.memset

        def logging_memset(addr, value, size):
            events.append(("memset", ctypes.cast(addr, ctypes.c_void_p).value))
            return orig_memset(addr, value, size)

        return events, logging_memset

    def _run(self, funcs, warmup_count, count, expect_error=False):
        merged, logging_memset = self._memset_events(self.events)
        inputs = iter([str(self.file_path), ""])
        out, err = io.StringIO(), io.StringIO()
        error = None
        with mock.patch.object(ctypes, "memset", logging_memset), \
             mock.patch("builtins.input", lambda *a: next(inputs)), \
             mock.patch.object(app, "prompt_operation_count", lambda action: count), \
             mock.patch.object(app, "prompt_warmup_count", lambda: warmup_count), \
             redirect_stdout(out), redirect_stderr(err):
            try:
                app.sign_file(1, funcs)
            except app.PKCS11Error as exc:
                error = exc
                if not expect_error:
                    raise
        return out.getvalue(), err.getvalue(), error

    def test_success_sequence_wipes_previous_retry_buffer_before_next_sign(self):
        # warmup(1) + measured(2): ok; retry->ok; ok. The retry buffer of
        # measured op 1 must be wiped BEFORE the C_Sign call of measured op 2.
        self.events = []
        calls, verify_out = [], []
        funcs = sign_pair_funcs(
            [
                ("ok", b"W" * 256),            # warmup
                ("too_small", 300), ("ok", b"A" * 300),  # measured op 1 (retry)
                ("ok", b"B" * 256),            # measured op 2
            ],
            calls,
            verify_out,
        )
        log_sign_calls(funcs, self.events)
        out, _, _ = self._run(funcs, 1, 2)
        addrs = [addr for _, addr in calls]
        main_buffer, retry1 = addrs[0], addrs[2]
        self.assertNotEqual(retry1, main_buffer)
        sign_indices = [i for i, e in enumerate(self.events) if e[0] == "sign"]
        # 4 C_Sign calls: warmup, m1(too_small), m1(retry), m2
        self.assertEqual(len(sign_indices), 4)
        wipe1_index = self.events.index(("memset", retry1))
        self.assertLess(
            wipe1_index, sign_indices[3],
            "retry buffer of measured op 1 was not wiped before op 2 started",
        )
        # The last measured signature (no retry on op 2) is verified and shown.
        self.assertEqual(verify_out, [b"B" * 256])
        self.assertIn("Самопроверка подписи: успешно", out)
        # Cleanup: the retry buffer was wiped (at least once in total).
        wiped = {e[1] for e in self.events if e[0] == "memset"}
        self.assertIn(retry1, wiped)

    def test_sign_init_failure_after_retry_wipes_previous_buffer_before_failing_call(self):
        # warmup(1) + measured(2): ok; retry->ok; C_SignInit of op 2 fails.
        # The retry buffer of measured op 1 must be wiped BEFORE the failing
        # C_SignInit call; previously it stayed unwiped until finally.
        self.events = []
        calls, verify_out = [], []
        funcs = sign_pair_funcs(
            [
                ("ok", b"W" * 256),
                ("too_small", 300), ("ok", b"A" * 300),
            ],
            calls,
            verify_out,
        )
        wrap_sign_init(funcs, self.events, [app.CKR_OK, app.CKR_OK, 5])
        log_sign_calls(funcs, self.events)
        _, _, error = self._run(funcs, 1, 2, expect_error=True)
        self.assertIsInstance(error, app.PKCS11Error)
        self.assertNotIsInstance(error, app.SelfCheckError)
        addrs = [addr for _, addr in calls]
        retry1 = addrs[2]
        self.assertNotEqual(retry1, addrs[0])
        wipe1_index = self.events.index(("memset", retry1))
        failing_init_index = self.events.index(("signinit", 3, 5))
        self.assertLess(
            wipe1_index, failing_init_index,
            "previous retry buffer was not wiped before the failing C_SignInit",
        )
        self.assertEqual(verify_out, [], "C_Verify must not be called")
        # Cleanup: data (140), signature (256) and retry (300) buffers wiped.
        wiped = {e[1] for e in self.events if e[0] == "memset"}
        self.assertIn(retry1, wiped)

    def test_multi_retry_sequence_wipes_every_intermediate_retry_buffer(self):
        # warmup(1) + measured(3): retry; ok; retry. Intermediate retry buffer
        # of op 1 must be wiped before op 2; final signature comes from the
        # retry buffer of op 3 and is verified and printed.
        self.events = []
        calls, verify_out = [], []
        funcs = sign_pair_funcs(
            [
                ("ok", b"W" * 256),                      # warmup
                ("too_small", 300), ("ok", b"A" * 300),  # m1 (retry)
                ("ok", b"B" * 256),                      # m2
                ("too_small", 200), ("ok", b"C" * 200),  # m3 (retry)
            ],
            calls,
            verify_out,
        )
        log_sign_calls(funcs, self.events)
        out, _, _ = self._run(funcs, 1, 3)
        addrs = [addr for _, addr in calls]
        main_buffer = addrs[0]
        retry_addrs = [a for a in dict.fromkeys(addrs) if a != main_buffer]
        self.assertEqual(len(retry_addrs), 2)
        sign_indices = [i for i, e in enumerate(self.events) if e[0] == "sign"]
        # 6 C_Sign calls: warmup, m1a, m1b(retry), m2, m3a, m3b(retry)
        self.assertEqual(len(sign_indices), 6)
        wipe1_index = self.events.index(("memset", addrs[2]))
        self.assertLess(
            wipe1_index, sign_indices[3],
            "retry buffer of measured op 1 was not wiped before op 2 started",
        )
        # All retry buffers wiped at least once (the last one in finally).
        wiped = {e[1] for e in self.events if e[0] == "memset"}
        for addr in retry_addrs:
            self.assertIn(addr, wiped, f"retry buffer at {addr} was never wiped")
        # The last measured signature (from the op-3 retry buffer) is verified.
        self.assertEqual(verify_out, [b"C" * 200])
        self.assertIn("Самопроверка подписи: успешно", out)


if __name__ == "__main__":
    unittest.main()
