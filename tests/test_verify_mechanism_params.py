"""Regression tests: verify_signature must pass the same OID parameter to
C_VerifyInit that the signing path uses. Modules that validate mechanism
parameters (real Rutoken ECP) reject a parameterless CKM_GOSTR3410 /
CKM_GOSTR3410_512 with CKR_MECHANISM_PARAM_INVALID, which made the mandatory
signature self-check fail for a perfectly valid GOST signature.

Contract:
- GOST-256 verify: C_VerifyInit receives CKM_GOSTR3410 with
  pParameter == GOST_3411_2012_256_PARAMS (and 512 variant accordingly);
  the parameter buffer must still be readable at init time (keepalive).
- RSA verify: C_VerifyInit receives CKM_SHA256_RSA_PKCS without a parameter.
- error paths: C_VerifyInit failure propagates, C_Verify is never called,
  the digest buffer is still wiped by the finally block.
- sequences: several verifications in a row (RSA/GOST-256/GOST-512) each
  receive their own mechanism with the correct parameter.
"""
import ctypes
import unittest

import app


def read_mechanism(mech_ref):
    mech = ctypes.cast(mech_ref, ctypes.POINTER(app.CK_MECHANISM)).contents
    param = None
    if mech.pParameter and int(mech.ulParameterLen):
        param = ctypes.string_at(mech.pParameter, int(mech.ulParameterLen))
    return int(mech.mechanism), param


def make_funcs(captured=None, *, verify_init_result=app.CKR_OK, verify_result=app.CKR_OK):
    """Fake PKCS#11 with recording C_DigestInit/C_Digest/C_VerifyInit/C_Verify."""

    def digest_init(_session, mech):
        mechanism_type, param = read_mechanism(mech)
        if captured is not None:
            captured.setdefault("digest_inits", []).append((mechanism_type, param))
        return app.CKR_OK

    def digest(_session, _data, _size, output, length):
        n = int(ctypes.cast(length, ctypes.POINTER(app.CK_ULONG)).contents.value)
        if captured is not None:
            captured["digest_buffer"] = ctypes.cast(output, ctypes.POINTER(app.CK_BYTE * n)).contents
        ctypes.memmove(output, b"D" * n, n)
        return app.CKR_OK

    def verify_init(_session, mech, _key):
        mechanism_type, param = read_mechanism(mech)
        if captured is not None:
            captured.setdefault("verify_inits", []).append((mechanism_type, param))
        return verify_init_result

    def verify(_session, _data, _data_len, _sig, _sig_len):
        if captured is not None:
            captured.setdefault("verifies", []).append(True)
        return verify_result

    return {
        "C_DigestInit": digest_init,
        "C_Digest": digest,
        "C_VerifyInit": verify_init,
        "C_Verify": verify,
    }


def signature_buffer(size, filler):
    return (app.CK_BYTE * size).from_buffer_copy(bytes([filler]) * size)


class VerifyMechanismParamsTests(unittest.TestCase):
    def test_gost256_verify_mechanism_carries_oid(self):
        captured = {}
        data = (app.CK_BYTE * 8)(*b"testdata")
        app.verify_signature(
            1, make_funcs(captured), {"algorithm": app.CKK_GOSTR3410, "public": 9},
            data, 8, signature_buffer(64, 0x5A),
        )
        self.assertEqual(len(captured["verify_inits"]), 1)
        mechanism_type, param = captured["verify_inits"][0]
        self.assertEqual(mechanism_type, app.CKM_GOSTR3410)
        self.assertEqual(
            param, app.GOST_3411_2012_256_PARAMS,
            "C_VerifyInit must receive the same OID parameter as the signing mechanism",
        )

    def test_gost512_verify_mechanism_carries_oid(self):
        captured = {}
        data = (app.CK_BYTE * 8)(*b"testdata")
        app.verify_signature(
            1, make_funcs(captured), {"algorithm": app.CKK_GOSTR3410_512, "public": 9},
            data, 8, signature_buffer(128, 0x5A),
        )
        mechanism_type, param = captured["verify_inits"][0]
        self.assertEqual(mechanism_type, app.CKM_GOSTR3410_512)
        self.assertEqual(param, app.GOST_3411_2012_512_PARAMS)

    def test_rsa_verify_mechanism_has_no_parameter(self):
        captured = {}
        data = (app.CK_BYTE * 8)(*b"testdata")
        app.verify_signature(
            1, make_funcs(captured), {"algorithm": app.CKK_RSA, "public": 9},
            data, 8, signature_buffer(256, 0x5A),
        )
        mechanism_type, param = captured["verify_inits"][0]
        self.assertEqual(mechanism_type, app.CKM_SHA256_RSA_PKCS)
        self.assertIsNone(param, "RSA verify mechanism must stay parameterless")

    def test_verify_init_failure_propagates_and_digest_wiped(self):
        captured = {}
        with self.assertRaises(app.PKCS11Error):
            app.verify_signature(
                1, make_funcs(captured, verify_init_result=5),
                {"algorithm": app.CKK_GOSTR3410, "public": 9},
                (app.CK_BYTE * 4)(*b"data"), 4, signature_buffer(64, 0x5A),
            )
        self.assertNotIn("verifies", captured, "C_Verify must not run after C_VerifyInit failure")
        self.assertEqual(
            bytes(captured["digest_buffer"]), b"\0" * 32,
            "digest buffer must be wiped even when C_VerifyInit fails",
        )

    def test_sequence_rsa_gost256_gost512_each_gets_own_params(self):
        captured = {}
        funcs = make_funcs(captured)
        pairs = [
            ({"algorithm": app.CKK_RSA, "public": 9}, 256, app.CKM_SHA256_RSA_PKCS, None),
            ({"algorithm": app.CKK_GOSTR3410, "public": 10}, 64, app.CKM_GOSTR3410, app.GOST_3411_2012_256_PARAMS),
            ({"algorithm": app.CKK_GOSTR3410_512, "public": 11}, 128, app.CKM_GOSTR3410_512, app.GOST_3411_2012_512_PARAMS),
        ]
        for index, (pair, sig_size, verify_mech, verify_oid) in enumerate(pairs):
            app.verify_signature(
                1, funcs, pair, (app.CK_BYTE * 4)(*b"data"), 4, signature_buffer(sig_size, 0x5A + index),
            )
            self.assertEqual(captured["verify_inits"][index][0], verify_mech)
            self.assertEqual(captured["verify_inits"][index][1], verify_oid)
        self.assertEqual(len(captured["verifies"]), 3)


if __name__ == "__main__":
    unittest.main()
