"""Regression tests: superseded retry buffers must be released promptly.

encrypt_file/sign_file wipe the previous iteration's retry buffer BEFORE the
next operation, but the buffer object stayed in sensitive_buffers until the
function exited: with a module answering CKR_BUFFER_TOO_SMALL on every
operation the list retained up to `count` ciphertext/signature buffers
(hundreds of MiB to GiB) until the finally-block. After the fix a wiped retry
buffer is removed from sensitive_buffers, so each superseded buffer is wiped
EXACTLY ONCE (a second wipe in the finally-block would mean it was still
registered, i.e. retained).
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


class _EventLog:
    """Merged chronological log of memset wipes and PKCS#11 output calls."""

    def __init__(self):
        self.events = []
        self._orig_memset = ctypes.memset

    def logging_memset(self, addr, value, size):
        self.events.append(("memset", ctypes.cast(addr, ctypes.c_void_p).value))
        return self._orig_memset(addr, value, size)

    def memset_counts(self, addr):
        return sum(1 for kind, a in self.events if kind == "memset" and a == addr)

    def call_indices(self, kind):
        return [i for i, (k, _) in enumerate(self.events) if k == kind]


class EncryptRetryReleaseTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tmpdir.name) / "data.bin"
        self.path.write_bytes(b"PLAINTEXT-DATA" * 10)

    def tearDown(self):
        self.tmpdir.cleanup()

    def _wrap_output_calls(self, funcs, log, name):
        original = funcs[name]

        def wrapper(session, data, size, output, output_length):
            log.events.append((name.lower(), ctypes.cast(output, ctypes.c_void_p).value))
            return original(session, data, size, output, output_length)

        funcs[name] = wrapper

    def test_success_sequence_releases_superseded_retry_buffers(self):
        # Multi-step sequence: warmup(1) + measured(3), EVERY operation retries
        # via CKR_BUFFER_TOO_SMALL. Each superseded retry buffer must be wiped
        # exactly once (before the next operation), never retained until the
        # finally-block.
        import test_encrypt_output_contract as harness

        log = _EventLog()
        calls, state = [], {}
        funcs = harness.encrypt_funcs(calls, [("too_small", 4096), ("ok", 0)] * 4, state)
        self._wrap_output_calls(funcs, log, "C_Encrypt")

        destroys = []
        real_destroy = funcs["C_DestroyObject"]

        def destroy(session, handle):
            destroys.append(_to_int(handle))
            return real_destroy(session, handle)

        funcs["C_DestroyObject"] = destroy

        inputs = iter([str(self.path), "3", "1", "0", "0"])  # path, count, warmup, mode, algorithm
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(ctypes, "memset", log.logging_memset), \
             mock.patch("builtins.input", lambda *a: next(inputs)), \
             redirect_stdout(out), redirect_stderr(err):
            app.encrypt_file(1, funcs, 1)

        self.assertIn("Самопроверка расшифрованием: успешно", out.getvalue())
        # 8 C_Encrypt calls: warmup (too_small, ok) + 3 measured ops x2.
        addrs = [addr for _, addr in calls]
        self.assertEqual(len(addrs), 8)
        main_buffer, retry_addrs = addrs[0], addrs[1::2]
        self.assertEqual(len(set(retry_addrs)), 4, "each retry must use a fresh buffer")
        # Every output buffer (main + 4 retry buffers) wiped exactly once.
        for addr in set(addrs):
            self.assertEqual(
                log.memset_counts(addr), 1,
                f"buffer {addr} wiped {log.memset_counts(addr)} times: "
                f"a superseded buffer must be released, not retained",
            )
        # The retry buffer of measured op 2 must be wiped BEFORE the first
        # C_Encrypt call of measured op 3 (pre-emptive wipe, not finally).
        encrypt_idx = log.call_indices("c_encrypt")
        self.assertEqual(len(encrypt_idx), 8)
        wipe_w3 = log.events.index(("memset", retry_addrs[2]))
        self.assertLess(wipe_w3, encrypt_idx[6])
        self.assertEqual(len(destroys), 1)

    def test_error_mid_sequence_still_wipes_previous_retry_once(self):
        # Negative case: measured op 1 retries successfully (retry buffer with
        # ciphertext exists), measured op 2 fails inside C_Encrypt. The
        # previous retry buffer must already be wiped (exactly once — released,
        # not retained for the finally-block), the key destroyed, and the
        # PKCS11Error must propagate.
        import test_encrypt_output_contract as harness

        log = _EventLog()
        calls, state = [], {}
        funcs = harness.encrypt_funcs(calls, [("too_small", 4096), ("ok", 0)], state)
        self._wrap_output_calls(funcs, log, "C_Encrypt")

        real_encrypt = funcs["C_Encrypt"]
        counter = {"n": 0}

        def failing_encrypt(session, data, size, output, output_length):
            counter["n"] += 1
            if counter["n"] == 3:
                return 0x00000005  # CKR_FUNCTION_FAILED
            return real_encrypt(session, data, size, output, output_length)

        funcs["C_Encrypt"] = failing_encrypt

        destroys = []
        real_destroy = funcs["C_DestroyObject"]

        def destroy(session, handle):
            destroys.append(_to_int(handle))
            return real_destroy(session, handle)

        funcs["C_DestroyObject"] = destroy

        inputs = iter([str(self.path), "2", "0", "0", "0"])  # path, count, warmup, mode, algorithm
        with mock.patch.object(ctypes, "memset", log.logging_memset), \
             mock.patch("builtins.input", lambda *a: next(inputs)), \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            with self.assertRaises(app.PKCS11Error):
                app.encrypt_file(1, funcs, 1)

        addrs = [addr for _, addr in calls]
        retry_w1 = addrs[1]
        # The superseded retry buffer was wiped before the failing operation
        # and released: exactly one wipe, no second pass in the finally-block.
        self.assertEqual(log.memset_counts(retry_w1), 1)
        # Nothing sensitive stayed unwiped: every written output buffer wiped.
        for addr in set(addrs):
            self.assertGreaterEqual(log.memset_counts(addr), 1)
        self.assertEqual(len(destroys), 1)


class SignRetryReleaseTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tmpdir.name) / "data.bin"
        self.path.write_bytes(b"PLAINTEXT-DATA" * 10)

    def tearDown(self):
        self.tmpdir.cleanup()

    def _wrap_sign_calls(self, funcs, log):
        original = funcs["C_Sign"]

        def wrapper(session, data, size, output, output_length):
            log.events.append(("c_sign", ctypes.cast(output, ctypes.c_void_p).value))
            return original(session, data, size, output, output_length)

        funcs["C_Sign"] = wrapper

    def _run(self, funcs, count, warmup, log):
        inputs = iter([str(self.path), ""])
        out, err = io.StringIO(), io.StringIO()
        error = None
        with mock.patch.object(ctypes, "memset", log.logging_memset), \
             mock.patch("builtins.input", lambda *a: next(inputs)), \
             mock.patch.object(app, "prompt_operation_count", lambda action: count), \
             mock.patch.object(app, "prompt_warmup_count", lambda: warmup), \
             redirect_stdout(out), redirect_stderr(err):
            try:
                app.sign_file(1, funcs)
            except app.PKCS11Error as exc:
                error = exc
        return log, out.getvalue(), err.getvalue(), error

    def test_success_sequence_releases_superseded_retry_buffers(self):
        # Multi-step sequence: warmup(1) + measured(3), every operation retries.
        calls, verify_out = [], []
        funcs = sign_pair_funcs(
            [("too_small", 300), ("ok", b"W" * 300)] * 4,
            calls,
            verify_out,
        )
        log = _EventLog()
        self._wrap_sign_calls(funcs, log)

        log, out, err, error = self._run(funcs, 3, 1, log)
        self.assertIsNone(error)
        self.assertIn("Самопроверка подписи: успешно", out)
        # Self-check verified the actual last signature (from the last retry).
        self.assertEqual(verify_out, [b"W" * 300])
        # 8 C_Sign calls: warmup (too_small, ok) + 3 measured ops x2.
        addrs = [addr for _, addr in calls]
        self.assertEqual(len(addrs), 8)
        main_buffer, retry_addrs = addrs[0], addrs[1::2]
        self.assertEqual(len(set(retry_addrs)), 4, "each retry must use a fresh buffer")
        # Every output buffer wiped exactly once: superseded buffers released,
        # only the live last retry buffer is wiped in the finally-block.
        for addr in set(addrs):
            self.assertEqual(
                log.memset_counts(addr), 1,
                f"buffer {addr} wiped {log.memset_counts(addr)} times: "
                f"a superseded buffer must be released, not retained",
            )
        # Pre-emptive wipe ordering: retry of measured op 2 wiped before the
        # first C_Sign call of measured op 3.
        sign_idx = log.call_indices("c_sign")
        self.assertEqual(len(sign_idx), 8)
        wipe_w3 = log.events.index(("memset", retry_addrs[2]))
        self.assertLess(wipe_w3, sign_idx[6])

    def test_error_mid_sequence_still_wipes_previous_retry_once(self):
        # Negative case: measured op 1 retries successfully, measured op 2
        # fails in C_SignInit. Previous retry buffer wiped exactly once
        # (released), PKCS11Error propagates.
        calls, verify_out = [], []
        funcs = sign_pair_funcs([("too_small", 300), ("ok", b"W" * 300)], calls, verify_out)

        log = _EventLog()
        self._wrap_sign_calls(funcs, log)

        init_counter = {"n": 0}
        real_sign_init = funcs["C_SignInit"]

        def failing_sign_init(session, mechanism, key):
            init_counter["n"] += 1
            if init_counter["n"] == 2:
                return 0x00000005  # CKR_FUNCTION_FAILED
            return real_sign_init(session, mechanism, key)

        funcs["C_SignInit"] = failing_sign_init

        log, out, err, error = self._run(funcs, 2, 0, log)
        self.assertIsInstance(error, app.PKCS11Error)
        addrs = [addr for _, addr in calls]
        retry_w1 = addrs[1]
        self.assertEqual(log.memset_counts(retry_w1), 1)
        for addr in set(addrs):
            self.assertGreaterEqual(log.memset_counts(addr), 1)
        self.assertEqual(verify_out, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
