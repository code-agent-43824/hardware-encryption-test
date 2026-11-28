"""Regression tests: the user-controlled input file size must be validated
BEFORE any allocation or open().

Contract:
- read_file_into_wipeable_buffer raises PKCS11Error for a file larger than
  app.MAX_INPUT_FILE_BYTES, before opening the file and before allocating
  the file-sized buffer (no MemoryError, no partially read plaintext).
- encrypt_file and sign_file report the limit as a clean user-facing error
  ("Не удалось прочитать файл: ...") and return to the caller without
  touching the token (no C_GenerateKey / C_Sign / C_Encrypt calls).
- A file exactly at the limit is still processed successfully (boundary),
  across a full multi-operation sequence (warmup + measured operations).
- After an oversized-file rejection the caller state stays clean: a follow-up
  operation on a normal file succeeds (multi-operation sequence, no leaked
  buffers or state from the failed attempt).
"""
import ctypes
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import app
from test_file_input_errors import encrypt_funcs, sign_pair_funcs


LIMIT = 4096


def to_int(v):
    if isinstance(v, int):
        return v
    if hasattr(v, "value"):
        return int(v.value)
    return int.from_bytes(bytes(v), "little")


class InputFileSizeLimitTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.directory = Path(self.tmpdir.name)
        self.limiter = mock.patch.object(app, "MAX_INPUT_FILE_BYTES", LIMIT)
        self.limiter.start()
        self.addCleanup(self.limiter.stop)

    def tearDown(self):
        self.tmpdir.cleanup()

    # --- unit level -----------------------------------------------------

    def test_oversized_file_rejected_before_open_and_allocation(self):
        # Negative case: the error must be raised before open() is ever
        # called and before the file-sized buffer is allocated.
        big_file = self.directory / "big.bin"
        big_file.write_bytes(b"\x00" * (LIMIT + 1))
        with mock.patch("builtins.open", side_effect=AssertionError("open() must not be called")):
            with self.assertRaises(app.PKCS11Error) as ctx:
                app.read_file_into_wipeable_buffer(big_file)
        self.assertIn("Файл слишком большой", str(ctx.exception))
        self.assertIn(str(big_file), str(ctx.exception))

    def test_boundary_file_exactly_at_limit_is_read(self):
        # Boundary: exactly LIMIT bytes is legitimate and must be read.
        edge_file = self.directory / "edge.bin"
        payload = bytes(range(256)) * (LIMIT // 256)
        edge_file.write_bytes(payload)
        buffer, size = app.read_file_into_wipeable_buffer(edge_file)
        self.assertEqual(size, LIMIT)
        self.assertEqual(bytes(buffer), payload)
        # The caller wipes the buffer; simulate that and confirm it zeroes.
        ctypes.memset(buffer, 0, len(buffer))
        self.assertEqual(bytes(buffer), b"\x00" * LIMIT)

    # --- encrypt_file end to end -----------------------------------------

    def run_encrypt_file(self, path, count="2", warmup="1"):
        calls = []
        state = {}
        funcs, memsets = encrypt_funcs(calls, [("ok", 0)], state)
        inputs = iter([str(path), count, warmup, "0", "0"])  # path, count, warmup, mode, algorithm
        out = io.StringIO()
        with mock.patch("builtins.input", lambda *a: next(inputs)), redirect_stdout(out):
            app.encrypt_file(1, funcs, 1)
        return out.getvalue(), calls, memsets

    def test_encrypt_file_oversized_reports_clean_error_without_token_ops(self):
        big_file = self.directory / "big.bin"
        big_file.write_bytes(b"\x00" * (LIMIT + 1))
        with mock.patch("builtins.open", side_effect=AssertionError("open() must not be called")):
            out, calls, _ = self.run_encrypt_file(big_file)
        self.assertIn("Не удалось прочитать файл", out)
        self.assertIn("Файл слишком большой", out)
        self.assertNotIn("Неожиданная ошибка", out)
        # The token must not be touched: no key generation, no encryption.
        self.assertEqual(calls, [])

    def test_encrypt_file_boundary_succeeds_across_sequence(self):
        # Boundary file, warmup=1 + count=2: a full multi-operation sequence.
        edge_file = self.directory / "edge.bin"
        edge_file.write_bytes(b"EDGE" * (LIMIT // 4))
        out, calls, _ = self.run_encrypt_file(edge_file)
        self.assertIn("Самопроверка расшифрованием: успешно", out)
        self.assertIn("Количество шифрований: 2", out)
        # 1 warmup + 2 measured C_Encrypt calls happened.
        self.assertEqual([c for c in calls if c[0] == "encrypt"].__len__(), 3)

    def test_encrypt_file_recovers_after_oversized_rejection(self):
        # Multi-operation sequence: oversized rejection first, then a normal
        # operation must still succeed (no leaked state from the failure).
        big_file = self.directory / "big.bin"
        big_file.write_bytes(b"\x00" * (LIMIT + 1))
        out1, calls1, _ = self.run_encrypt_file(big_file)
        self.assertIn("Файл слишком большой", out1)
        self.assertEqual(calls1, [])

        normal_file = self.directory / "normal.bin"
        normal_file.write_bytes(b"PLAINTEXT" * 8)
        out2, calls2, _ = self.run_encrypt_file(normal_file)
        self.assertIn("Самопроверка расшифрованием: успешно", out2)
        self.assertTrue(calls2)

    # --- sign_file end to end ---------------------------------------------

    def run_sign_file(self, path):
        calls = []
        verify_out = []
        funcs = sign_pair_funcs([("ok", b"S" * 256)], calls, verify_out)
        inputs = iter([str(path), "2", "1", ""])  # path, count, warmup, pair choice
        out = io.StringIO()
        with mock.patch("builtins.input", lambda *a: next(inputs)), redirect_stdout(out):
            app.sign_file(1, funcs, 1)
        return out.getvalue(), calls

    def test_sign_file_oversized_reports_clean_error_without_token_ops(self):
        big_file = self.directory / "big.bin"
        big_file.write_bytes(b"\x00" * (LIMIT + 1))
        with mock.patch("builtins.open", side_effect=AssertionError("open() must not be called")):
            out, calls = self.run_sign_file(big_file)
        self.assertIn("Не удалось прочитать файл", out)
        self.assertIn("Файл слишком большой", out)
        self.assertNotIn("Неожиданная ошибка", out)
        self.assertEqual([c for c in calls if c[0] == "sign"], [])

    def test_sign_file_boundary_succeeds(self):
        edge_file = self.directory / "edge.bin"
        edge_file.write_bytes(b"EDGE" * (LIMIT // 4))
        out, calls = self.run_sign_file(edge_file)
        self.assertIn("Самопроверка подписи: успешно", out)
        self.assertEqual([c for c in calls if c[0] == "sign"].__len__(), 3)


if __name__ == "__main__":
    unittest.main()
