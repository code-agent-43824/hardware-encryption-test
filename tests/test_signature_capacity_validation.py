"""Regression tests: the signature buffer capacity for RSA comes from
CKA_MODULUS_BITS reported by the UNTRUSTED module and must be validated
BEFORE allocation.

Contract: signature_buffer_length must reject a modulus size that yields
capacity == 0 (contradicts "RSA signature") or capacity > MAX_RETRY_OUTPUT_BYTES
(e.g. a hostile 64-bit module reporting ~2^34 bits) with
InvalidModuleLengthError BEFORE sign_file executes (CK_BYTE * capacity)().
Previously the raw value went straight into the allocation: a hostile or buggy
module triggered MemoryError (unexpected exception with a traceback in
run_menu) or swap thrash. The retry-size validation
(test_retry_allocation_validation) covers only the size reported on
CKR_BUFFER_TOO_SMALL and cannot catch this.

Normal flows are unaffected: a sane modulus (e.g. 2048 bits) still resolves
to capacity 256 and a full warmup + measured + retry + self-check sequence
succeeds. On rejection the caller's finally still wipes the already-read
plaintext buffer, so nothing sensitive stays in memory.

Platform note: with a 32-bit CK_ULONG (Windows) a module cannot report a
modulus above 2^32-1 bits, so the maximum reachable capacity is ~2^29 bytes,
which is below MAX_RETRY_OUTPUT_BYTES — the huge-capacity branch is
unreachable there and the corresponding test is skipped.
"""
import ctypes
import io
import pathlib
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

import app
from test_file_input_errors import _to_int, sign_pair_funcs, ulong_bytes

# «Гигантское» значение в битах: ёмкость (1<<34)//8 = 2^31 байт больше
# MAX_RETRY_OUTPUT_BYTES (1<<30). Помещается только в 64-битный CK_ULONG.
HUGE_MODULUS_BITS = 1 << 34


def wrap_with_modulus_bits(funcs, modulus_bits):
    """Расширяем fake-модуль ответом CKA_MODULUS_BITS (двухфазное чтение
    attr_bytes: сначала размер, затем значение)."""
    base_get = funcs["C_GetAttributeValue"]
    mod = ulong_bytes(modulus_bits)

    def get_attr_value(session, handle, template, count):
        for i in range(_to_int(count)):
            if _to_int(template[i].type) == app.CKA_MODULUS_BITS:
                template[i].ulValueLen = app.CK_ULONG(len(mod))
                if template[i].pValue:
                    ctypes.memmove(template[i].pValue, mod, len(mod))
                return app.CKR_OK
        return base_get(session, handle, template, count)

    funcs["C_GetAttributeValue"] = get_attr_value
    return funcs


def run_sign_file(file_path, count, warmup, funcs, memsets):
    inputs = iter([str(file_path), str(count), str(warmup), ""])
    out = io.StringIO()
    err = io.StringIO()

    orig_memset = ctypes.memset

    def logging_memset(addr, value, size):
        memsets.append(
            (ctypes.cast(addr, ctypes.c_void_p).value if not isinstance(addr, int) else addr, int(size))
        )
        return orig_memset(addr, value, size)

    with mock.patch("builtins.input", lambda *a: next(inputs)), \
            mock.patch("ctypes.memset", logging_memset), \
            redirect_stdout(out), redirect_stderr(err):
        app.sign_file(1, funcs)
    return out.getvalue()


class SignatureCapacityValidationTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.file_path = pathlib.Path(self.tmpdir.name) / "data.bin"
        self.payload = b"PLAINTEXT-DATA" * 10
        self.file_path.write_bytes(self.payload)

    def tearDown(self):
        self.tmpdir.cleanup()

    @unittest.skipIf(
        ctypes.sizeof(app.CK_ULONG) < 8,
        "32-битный CK_ULONG не позволяет модулю сообщить ёмкость выше порога",
    )
    def test_sign_rejects_huge_modulus_bits_before_allocation(self):
        # Раньше — безусловная аллокация (CK_BYTE * (2^31))() и MemoryError.
        memsets = []
        calls = []
        funcs = wrap_with_modulus_bits(sign_pair_funcs([], calls, []), HUGE_MODULUS_BITS)
        with self.assertRaises(app.InvalidModuleLengthError) as ctx:
            run_sign_file(self.file_path, 1, 1, funcs, memsets)
        self.assertIn("некорректный размер модуля подписи", str(ctx.exception))
        self.assertIn(str(HUGE_MODULUS_BITS), str(ctx.exception))
        # Ошибка должна произойти ДО любых C_Sign вызовов и аллокаций.
        self.assertEqual(calls, [])
        # Уже прочитанный открытый текст затёрт в finally: ничего не течёт.
        self.assertIn(len(self.payload), [size for _, size in memsets])

    def test_sign_rejects_zero_capacity_modulus(self):
        # Модуль сообщает 4 бита: ёмкость 0 байт противоречит смыслу RSA-подписи,
        # тот же контракт, что у retry-размера (needed == 0 отклоняется).
        memsets = []
        calls = []
        funcs = wrap_with_modulus_bits(sign_pair_funcs([], calls, []), 4)
        with self.assertRaises(app.InvalidModuleLengthError) as ctx:
            run_sign_file(self.file_path, 1, 1, funcs, memsets)
        self.assertIn("ёмкость буфера 0", str(ctx.exception))
        self.assertEqual(calls, [])
        self.assertIn(len(self.payload), [size for _, size in memsets])

    def test_sign_sane_modulus_full_sequence_with_retry(self):
        # Нормальный поток не затронут: 2048 бит -> ёмкость 256, полная
        # последовательность прогрев + измеряемые (включая CKR_BUFFER_TOO_SMALL
        # с разумным needed и повтором) + самопроверка проходит.
        memsets = []
        calls = []
        verify_out = []
        steps = [("ok", b"S" * 256), ("too_small", 512), ("ok", b"T" * 512)]
        funcs = wrap_with_modulus_bits(sign_pair_funcs(steps, calls, verify_out), 2048)
        out = run_sign_file(self.file_path, 2, 1, funcs, memsets)
        self.assertIn("Самопроверка подписи: успешно", out)
        self.assertEqual(len(calls), 4)  # прогрев, изм.1, retry-попытка, повтор
        # Последняя измеряемая операция (после шагов скрипта) вернула подпись
        # в основной буфер: самопроверка проверяет именно её.
        self.assertEqual(verify_out, [b"X" * 256])
        # После успеха в finally затёрты data-буфер (140), retry-буфер (512,
        # затирается дважды: упреждающе перед следующей операцией и в finally),
        # основной буфер подписи и копия последней подписи (256).
        sizes = sorted(size for _, size in memsets)
        self.assertEqual(sizes, [140, 256, 256, 512, 512])


if __name__ == "__main__":
    unittest.main()
