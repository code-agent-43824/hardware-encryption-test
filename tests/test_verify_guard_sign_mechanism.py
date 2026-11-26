"""Regression tests: the verify_signature guard must check the table key the
function actually uses ("sign_mechanism", the combined hash+sign mechanism),
not the leftover "verify_mechanism" from the removed digest+verify path.

History: the guard checked "verify_mechanism" in KEY_TYPES info, while the
function reads info["sign_mechanism"]. All current KEY_TYPES entries happen
to have both, so the mismatch was latent: adding a key type with
verify_mechanism but without sign_mechanism (or removing sign_mechanism)
would make verify_signature crash with a raw KeyError instead of the
diagnosable PKCS11Error, before and regardless of any PKCS#11 calls.

Contract:
- an algorithm without "sign_mechanism" in KEY_TYPES raises PKCS11Error
  ("Неподдерживаемый тип ключа...") and never calls C_VerifyInit/C_Verify;
- RSA, GOST-256 and GOST-512 self-checks keep working (sequences of several
  verifications in a row);
- the temporary signature copy (bytes input path) is still wiped when
  C_Verify fails.
"""
import ctypes
import unittest

import app


def make_funcs(captured=None, *, verify_init_result=app.CKR_OK, verify_result=app.CKR_OK):
    def verify_init(_session, mech, _key):
        if captured is not None:
            captured["verify_inits"] = captured.get("verify_inits", 0) + 1
        return verify_init_result

    def verify(_session, data, data_len, sig, sig_len):
        if captured is not None:
            captured["verifies"] = captured.get("verifies", 0) + 1
        return verify_result

    return {
        "C_VerifyInit": verify_init,
        "C_Verify": verify,
    }


def signature_buffer(size, filler):
    return (app.CK_BYTE * size).from_buffer_copy(bytes([filler]) * size)


class VerifyGuardSignMechanismTests(unittest.TestCase):
    def test_algorithm_without_sign_mechanism_raises_pkcs11_error(self):
        captured = {}
        data = (app.CK_BYTE * 8)(*b"testdata")
        with self.assertRaises(app.PKCS11Error) as ctx:
            app.verify_signature(
                1, make_funcs(captured), {"algorithm": app.CKK_MAGMA, "public": 9},
                data, 8, signature_buffer(16, 0x5A),
            )
        self.assertIn("Неподдерживаемый тип ключа", str(ctx.exception))
        # До любых PKCS#11-вызовов: ни C_VerifyInit, ни C_Verify.
        self.assertNotIn("verify_inits", captured)
        self.assertNotIn("verifies", captured)

    def test_unsupported_algorithm_never_touches_pkcs11_even_in_sequence(self):
        captured = {}
        data = (app.CK_BYTE * 8)(*b"testdata")
        # Сначала успешная проверка RSA, затем unsupported-тип: первый вызов
        # не должен оставить состояние, позволяющее второму пройти мимо стража.
        app.verify_signature(
            1, make_funcs(captured), {"algorithm": app.CKK_RSA, "public": 9},
            data, 8, signature_buffer(256, 0x5A),
        )
        with self.assertRaises(app.PKCS11Error):
            app.verify_signature(
                1, make_funcs(captured), {"algorithm": app.CKK_KUZNECHIK, "public": 9},
                data, 8, signature_buffer(16, 0x5A),
            )
        self.assertEqual(captured.get("verify_inits", 0), 1)
        self.assertEqual(captured.get("verifies", 0), 1)

    def test_supported_algorithms_still_verify_in_sequence(self):
        captured = {}
        data = (app.CK_BYTE * 8)(*b"testdata")
        for algorithm, sig_size in (
            (app.CKK_RSA, 256),
            (app.CKK_GOSTR3410, 64),
            (app.CKK_GOSTR3410_512, 128),
        ):
            app.verify_signature(
                1, make_funcs(captured), {"algorithm": algorithm, "public": 9},
                data, 8, signature_buffer(sig_size, 0x5A),
            )
        self.assertEqual(captured.get("verify_inits", 0), 3)
        self.assertEqual(captured.get("verifies", 0), 3)

    def test_entry_with_verify_mechanism_but_no_sign_mechanism(self):
        # Точный regression-кейс: запись таблицы имеет "verify_mechanism"
        # (мимо которого проходит старый страж), но не имеет "sign_mechanism"
        # (который функция реально использует). Ожидание — диагностируемая
        # PKCS11Error; до исправления здесь был сырой KeyError.
        captured = {}
        saved = dict(app.KEY_TYPES)
        try:
            app.KEY_TYPES[app.CKK_RSA] = {
                "constant": "CKK_RSA",
                "name": "RSA-2048",
                "verify_mechanism": app.CKM_SHA256_RSA_PKCS,
            }
            data = (app.CK_BYTE * 8)(*b"testdata")
            with self.assertRaises(app.PKCS11Error) as ctx:
                app.verify_signature(
                    1, make_funcs(captured), {"algorithm": app.CKK_RSA, "public": 9},
                    data, 8, signature_buffer(256, 0x5A),
                )
            self.assertIn("Неподдерживаемый тип ключа", str(ctx.exception))
        finally:
            app.KEY_TYPES.clear()
            app.KEY_TYPES.update(saved)
        self.assertNotIn("verify_inits", captured)
        self.assertNotIn("verifies", captured)

    def test_signature_copy_still_wiped_on_verify_failure(self):
        # bytes-вход создаёт копию внутри verify_signature: при провале
        # C_Verify она обязана затираться в finally.
        seen = {}
        funcs = make_funcs(verify_result=app.CKR_SIGNATURE_INVALID)

        orig_memset = ctypes.memset

        def tracking_memset(dst, value, count):
            addr = ctypes.cast(dst, ctypes.c_void_p).value
            seen[addr] = seen.get(addr, 0) + count
            return orig_memset(dst, value, count)

        data = (app.CK_BYTE * 8)(*b"testdata")
        with mock_memset(tracking_memset):
            with self.assertRaises(app.PKCS11Error):
                app.verify_signature(
                    1, funcs, {"algorithm": app.CKK_RSA, "public": 9},
                    data, 8, bytes([0x5A]) * 256,
                )
        self.assertTrue(any(count == 256 for count in seen.values()),
                        "копия подписи (256 байт) не затёрта при провале C_Verify")


import contextlib


@contextlib.contextmanager
def mock_memset(replacement):
    original = ctypes.memset
    ctypes.memset = replacement
    try:
        yield
    finally:
        ctypes.memset = original


if __name__ == "__main__":
    unittest.main()
