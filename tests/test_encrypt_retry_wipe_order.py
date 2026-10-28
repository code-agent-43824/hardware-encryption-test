"""Regression tests for the retry-buffer wipe ordering in encrypt_file.

encrypt_file must wipe the previous measured iteration's retry buffer BEFORE
starting the next encryption operation. Previously the memset ran only after
encrypt_with_generated_key returned (or in the finally-block), so a failure
inside the next operation (C_EncryptInit/C_Encrypt) left the previous retry
buffer holding sensitive ciphertext in memory until the finally-block ran.
The warmup loop and sign_file already wiped earlier buffers before/at the
start of the next operation; the measured encrypt loop must match.
"""
import base64
import ctypes
import io
import pathlib
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

import app


def _to_int(v):
    if isinstance(v, int):
        return v
    if hasattr(v, "value"):
        return int(v.value)
    return int.from_bytes(bytes(v), "little")


def encrypt_funcs(events, encrypt_steps, state, init_results=None):
    """Fake PKCS#11 for encrypt_file (Magma, software mode) with event logging.

    Every C_Encrypt call appends ("encrypt", output_addr) to events; every
    C_EncryptInit appends ("init", call_index, rv). ctypes.memset calls are
    logged by the test itself via a patched ctypes.memset.
    encrypt_steps: list of ("ok", 0) / ("too_small", needed) per C_Encrypt call
    (last entry repeats). init_results: return codes per C_EncryptInit call
    (last one repeats); None → always CKR_OK.
    """
    def generate_random(session, buf, size):
        n = _to_int(size)
        ctypes.memmove(buf, b"\x42" * n, n)
        return app.CKR_OK

    def generate_key(session, mechanism, template, tlen, phandle):
        state["keys"] = state.get("keys", 0) + 1
        h = ctypes.cast(phandle, ctypes.POINTER(app.CK_OBJECT_HANDLE))
        h[0] = app.CK_OBJECT_HANDLE(state["keys"])
        return app.CKR_OK

    def encrypt_init(session, mechanism, key_handle):
        state["inits"] = state.get("inits", 0) + 1
        if init_results is None:
            rv = app.CKR_OK
        else:
            idx = min(state["inits"] - 1, len(init_results) - 1)
            rv = init_results[idx]
        events.append(("init", state["inits"], rv))
        return rv

    def encrypt(session, data, size, output, output_length):
        if "plaintext" not in state:
            state["plaintext"] = ctypes.string_at(data, _to_int(size))
        addr = ctypes.cast(output, ctypes.c_void_p).value
        events.append(("encrypt", addr))
        state["addrs"] = state.get("addrs", [])
        state["addrs"].append(addr)
        step = encrypt_steps[state.get("step", 0)] if state.get("step", 0) < len(encrypt_steps) else ("ok", 0)
        state["step"] = state.get("step", 0) + 1
        ol = ctypes.cast(output_length, ctypes.POINTER(app.CK_ULONG))
        if step[0] == "too_small":
            ol[0] = app.CK_ULONG(step[1])
            return app.CKR_BUFFER_TOO_SMALL
        cipher_len = len(state["plaintext"]) + 8
        ctypes.memmove(output, b"\xC1" * cipher_len, cipher_len)
        ol[0] = app.CK_ULONG(cipher_len)
        return app.CKR_OK

    def decrypt(session, ct, ct_len, pt, pt_len):
        plain = state["plaintext"]
        ctypes.memmove(pt, plain, len(plain))
        pl = ctypes.cast(pt_len, ctypes.POINTER(app.CK_ULONG))
        pl[0] = app.CK_ULONG(len(plain))
        return app.CKR_OK

    def mechanism_list(slot, ptr, pcount):
        pc = ctypes.cast(pcount, ctypes.POINTER(app.CK_ULONG))
        mechs = [app.CKM_MAGMA_KEY_GEN, app.CKM_MAGMA_CTR_ACPKM]
        if ptr:
            arr = ctypes.cast(ptr, ctypes.POINTER(app.CK_MECHANISM_TYPE * len(mechs))).contents
            for i, m in enumerate(mechs):
                arr[i] = app.CK_MECHANISM_TYPE(m)
        pc[0] = app.CK_ULONG(len(mechs))
        return app.CKR_OK

    def destroy(session, handle):
        state["destroys"] = state.get("destroys", 0) + 1
        return app.CKR_OK

    return {
        "C_GenerateRandom": generate_random,
        "C_GenerateKey": generate_key,
        "C_EncryptInit": encrypt_init,
        "C_Encrypt": encrypt,
        "C_DecryptInit": lambda *_: app.CKR_OK,
        "C_Decrypt": decrypt,
        "C_DestroyObject": destroy,
        "C_GetMechanismList": mechanism_list,
    }


class EncryptRetryWipeOrderTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.tmpdir.name) / "data.bin"
        self.path.write_bytes(b"PLAINTEXT-DATA" * 10)
        self.plaintext_len = 140

    def tearDown(self):
        self.tmpdir.cleanup()

    def _memset_events(self, events):
        """Log memset calls into the same events list for chronological order."""
        orig_memset = ctypes.memset

        def logging_memset(addr, value, size):
            events.append(("memset", ctypes.cast(addr, ctypes.c_void_p).value))
            return orig_memset(addr, value, size)

        return events, logging_memset

    def test_success_sequence_wipes_previous_retry_buffer_before_next_operation(self):
        # warmup(1) + measured(2): ok; retry->ok; retry->ok. The retry buffer
        # of measured op 1 must be wiped BEFORE the first C_Encrypt call of
        # measured op 2, not only after op 2 returns / in the finally-block.
        events = []
        state = {}
        funcs = encrypt_funcs(
            events,
            [("ok", 0), ("too_small", 4096), ("ok", 0), ("too_small", 2048), ("ok", 0)],
            state,
        )
        merged, logging_memset = self._memset_events(events)
        with mock.patch.object(ctypes, "memset", logging_memset):
            out = self._run_with_patch(funcs)
        addrs = state["addrs"]
        main_buffer = addrs[0]
        retry1 = addrs[2]
        retry2 = addrs[4]
        self.assertNotEqual(retry1, main_buffer)
        self.assertNotEqual(retry2, main_buffer)
        encrypt_indices = [i for i, e in enumerate(merged) if e[0] == "encrypt"]
        # 5 encrypt calls: warmup, m1(too_small), m1(retry), m2(too_small), m2(retry)
        self.assertEqual(len(encrypt_indices), 5)
        wipe1_index = merged.index(("memset", retry1))
        # The 4th encrypt call is the first C_Encrypt of measured op 2.
        self.assertLess(
            wipe1_index, encrypt_indices[3],
            "retry buffer of measured op 1 was not wiped before op 2 started",
        )
        self.assertIn("Самопроверка расшифрованием: успешно", out)
        self.assertEqual(state.get("destroys"), 1)
        cipher_len = self.plaintext_len + 8
        preview_line = out.split("Последний шифротекст (Base64, первые 256 символов):\n")[1].split("\n")[0]
        self.assertEqual(base64.b64decode(preview_line), b"\xC1" * cipher_len)
        # Cleanup: every retry buffer was wiped at least once.
        wiped = {e[1] for e in merged if e[0] == "memset"}
        self.assertIn(retry1, wiped)
        self.assertIn(retry2, wiped)

    def _run_with_patch(self, funcs, inputs=None):
        seq = iter(inputs or [str(self.path), "2", "1", "0", "0"])
        out = io.StringIO()
        with mock.patch("builtins.input", lambda *a: next(seq)), redirect_stdout(out):
            app.encrypt_file(1, funcs, 1)
        return out.getvalue()

    def test_init_failure_after_retry_wipes_previous_buffer_before_failing_call(self):
        # warmup(1) + measured(2): ok; retry->ok; C_EncryptInit of op 2 fails.
        # The retry buffer of measured op 1 must be wiped BEFORE the failing
        # C_EncryptInit call; previously it stayed un wiped until finally.
        events = []
        state = {}
        funcs = encrypt_funcs(
            events,
            [("ok", 0), ("too_small", 4096), ("ok", 0)],
            state,
            init_results=[app.CKR_OK, app.CKR_OK, 5],
        )
        merged, logging_memset = self._memset_events(events)
        with mock.patch.object(ctypes, "memset", logging_memset):
            seq = iter([str(self.path), "2", "1", "0", "0"])
            with mock.patch("builtins.input", lambda *a: next(seq)):
                with self.assertRaises(app.PKCS11Error), redirect_stdout(io.StringIO()):
                    app.encrypt_file(1, funcs, 1)
        addrs = state["addrs"]
        retry1 = addrs[2]
        self.assertNotEqual(retry1, addrs[0])
        wipe1_index = merged.index(("memset", retry1))
        failing_init_index = merged.index(("init", 3, 5))
        self.assertLess(
            wipe1_index, failing_init_index,
            "previous retry buffer was not wiped before the failing C_EncryptInit",
        )
        # Error path cleanup: key destroyed exactly once, retry buffer wiped.
        self.assertEqual(state.get("destroys"), 1)
        wiped = {e[1] for e in merged if e[0] == "memset"}
        self.assertIn(retry1, wiped)

    def test_multi_retry_sequence_wipes_every_retry_buffer_and_destroys_key_once(self):
        # warmup(1) + measured(3), retry on every measured operation: success
        # path with the maximal number of intermediate retry buffers.
        events = []
        state = {}
        funcs = encrypt_funcs(
            events,
            [
                ("ok", 0),
                ("too_small", 4096), ("ok", 0),
                ("too_small", 2048), ("ok", 0),
                ("too_small", 1024), ("ok", 0),
            ],
            state,
        )
        merged, logging_memset = self._memset_events(events)
        with mock.patch.object(ctypes, "memset", logging_memset):
            seq = iter([str(self.path), "3", "1", "0", "0"])
            with mock.patch("builtins.input", lambda *a: next(seq)):
                out = io.StringIO()
                with redirect_stdout(out):
                    app.encrypt_file(1, funcs, 1)
        addrs = state["addrs"]
        main_buffer = addrs[0]
        retry_addrs = [a for a in set(addrs) if a != main_buffer]
        self.assertEqual(len(retry_addrs), 3)
        wiped = {e[1] for e in merged if e[0] == "memset"}
        for addr in retry_addrs:
            self.assertIn(addr, wiped, f"retry buffer at {addr} was never wiped")
        self.assertEqual(state.get("destroys"), 1)
        self.assertIn("Самопроверка расшифрованием: успешно", out.getvalue())
        # Every retry buffer of an intermediate iteration was wiped before the
        # next measured operation started (wipe precedes the following encrypt
        # call for all but the last retry buffer).
        encrypt_indices = [i for i, e in enumerate(merged) if e[0] == "encrypt"]
        self.assertEqual(len(encrypt_indices), 7)
        for k, retry_addr in enumerate([addrs[2], addrs[4]]):
            wipe_index = merged.index(("memset", retry_addr))
            self.assertLess(wipe_index, encrypt_indices[2 * k + 3])


if __name__ == "__main__":
    unittest.main()
