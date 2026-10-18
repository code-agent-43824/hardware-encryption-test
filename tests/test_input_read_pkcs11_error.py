"""Regression tests: read failures reported as PKCS11Error (file size changed
during reading, special files with st_size == 0) must follow the same clean
user-facing path as OSError in encrypt_file/sign_file: a printed message,
no exception escaping, no crypto calls, and wiped plaintext buffers.
"""
import builtins
import ctypes
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import app
from test_file_input_errors import encrypt_funcs, sign_pair_funcs


class GrowingFileHandle:
    """Fake read-only binary handle: hands out exactly the file's stat() size,
    then extra bytes, which read_file_into_wipeable_buffer must treat as a
    size change (PKCS11Error) after wiping the partial plaintext buffer."""

    def __init__(self, data, extra):
        self.data = data
        self.extra = extra
        self.pos = 0

    def readinto(self, mv):
        writable = memoryview(mv).cast("B")
        if self.pos < len(self.data):
            n = min(len(writable), len(self.data) - self.pos)
            writable[:n] = self.data[self.pos:self.pos + n]
            self.pos += n
            return n
        n = min(len(writable), len(self.extra))
        if n == 0:
            return 0
        writable[:n] = self.extra[:n]
        self.extra = self.extra[n:]
        return n

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class InputReadPkcs11ErrorTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.directory = Path(self.tmpdir.name)
        self.regular_file = self.directory / "data.bin"
        self.regular_file.write_bytes(b"PLAINTEXT-DATA" * 10)

    def tearDown(self):
        self.tmpdir.cleanup()

    def run_encrypt_file(self, funcs, open_override, wipes):
        inputs = iter([str(self.regular_file), "1", "0", "0", "0"])
        out = io.StringIO()
        real_memset = ctypes.memset

        def logging_memset(addr, value, size):
            wipes.append(size)
            return real_memset(addr, value, size)

        with mock.patch("builtins.input", lambda *a: next(inputs)), \
                redirect_stdout(out):
            if open_override is None:
                app.encrypt_file(1, funcs, 1)
            else:
                with mock.patch("builtins.open", open_override), \
                        mock.patch("ctypes.memset", logging_memset):
                    app.encrypt_file(1, funcs, 1)
        return out.getvalue()

    def run_sign_file(self, funcs, open_override, wipes):
        inputs = iter([str(self.regular_file), "1", "0", ""])
        out = io.StringIO()
        real_memset = ctypes.memset

        def logging_memset(addr, value, size):
            wipes.append(size)
            return real_memset(addr, value, size)

        with mock.patch("builtins.input", lambda *a: next(inputs)), \
                redirect_stdout(out):
            if open_override is None:
                app.sign_file(1, funcs)
            else:
                with mock.patch("builtins.open", open_override), \
                        mock.patch("ctypes.memset", logging_memset):
                    app.sign_file(1, funcs)
        return out.getvalue()

    def growing_open(self, data):
        opened = []

        def fake_open(path, mode="r", *args, **kwargs):
            if not opened:
                opened.append(path)
                return GrowingFileHandle(data, b"EXTRA-BYTE")
            return builtins.open(path, mode, *args, **kwargs)

        return fake_open

    def test_encrypt_file_growing_file_prints_clean_error_and_wipes(self):
        data = self.regular_file.read_bytes()
        calls = []
        funcs, _ = encrypt_funcs(calls, [], {})
        wipes = []
        out = self.run_encrypt_file(funcs, self.growing_open(data), wipes)
        self.assertIn("Не удалось прочитать файл", out)
        self.assertIn("Размер файла изменился при чтении", out)
        self.assertNotIn("Неожиданная ошибка", out)
        # Токен вообще не должен использоваться: чтение падает до генерации ключа.
        self.assertEqual(calls, [])
        # Очистка ресурсов: буфер с частичным открытым текстом затёрт.
        self.assertIn(len(data), wipes)

    def test_sign_file_growing_file_prints_clean_error_and_wipes(self):
        data = self.regular_file.read_bytes()
        calls = []
        funcs = sign_pair_funcs([], calls, [])
        wipes = []
        out = self.run_sign_file(funcs, self.growing_open(data), wipes)
        self.assertIn("Не удалось прочитать файл", out)
        self.assertIn("Размер файла изменился при чтении", out)
        self.assertNotIn("Неожиданная ошибка", out)
        self.assertEqual(calls, [])
        self.assertIn(len(data), wipes)

    def test_encrypt_file_recovers_after_read_error_in_same_session(self):
        data = self.regular_file.read_bytes()
        calls = []
        funcs, _ = encrypt_funcs(calls, [], {})
        wipes = []
        out1 = self.run_encrypt_file(funcs, self.growing_open(data), wipes)
        self.assertIn("Не удалось прочитать файл", out1)
        # Вторая операция в той же сессии с обычным файлом должна пройти штатно.
        out2 = self.run_encrypt_file(funcs, None, [])
        self.assertIn("Самопроверка расшифрованием: успешно", out2)
        self.assertGreater(len(calls), 0)

    def test_sign_file_recovers_after_read_error_in_same_session(self):
        data = self.regular_file.read_bytes()
        calls = []
        funcs = sign_pair_funcs([], calls, [])
        wipes = []
        out1 = self.run_sign_file(funcs, self.growing_open(data), wipes)
        self.assertIn("Не удалось прочитать файл", out1)
        out2 = self.run_sign_file(funcs, None, [])
        self.assertIn("Самопроверка подписи: успешно", out2)
        self.assertGreater(len(calls), 0)


if __name__ == "__main__":
    unittest.main()
