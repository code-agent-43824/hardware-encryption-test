import ctypes
import unittest
from unittest import mock

import app


class MechanismParameterTests(unittest.TestCase):
    def test_magma_ctr_acpkm_params(self):
        iv = bytes.fromhex("01020304")
        params = app.build_ctr_acpkm_params(4, 32768, iv)
        self.assertEqual(params, bytes.fromhex("0000800001020304"))

    def test_kuznechik_ctr_acpkm_params(self):
        iv = bytes.fromhex("0102030405060708")
        params = app.build_ctr_acpkm_params(8, 32768, iv)
        self.assertEqual(params, bytes.fromhex("000080000102030405060708"))

    def test_gost28147_uses_eight_byte_iv(self):
        algorithm = {"encrypt_mechanism": app.CKM_GOST28147, "iv_size": 8}
        with mock.patch.object(app.secrets, "token_bytes", return_value=b"\xA5" * 8):
            self.assertEqual(app.build_encryption_params(algorithm), b"\xA5" * 8)

    def test_gost_signature_mechanism_always_contains_hash_oid(self):
        mechanism, keepalive, _ = app.signing_mechanism_for_pair({"algorithm": app.CKK_GOSTR3410})
        self.assertEqual(int(mechanism.ulParameterLen), len(app.GOST_3411_2012_256_PARAMS))
        self.assertEqual(
            ctypes.string_at(mechanism.pParameter, int(mechanism.ulParameterLen)),
            app.GOST_3411_2012_256_PARAMS,
        )
        self.assertIsNotNone(keepalive)


if __name__ == "__main__":
    unittest.main()
