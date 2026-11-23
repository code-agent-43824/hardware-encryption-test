"""Regression tests: verify_signature must check the signature with the SAME
combined hash+sign mechanism (with the GOST hash OID parameter) that the
signing path uses (signing_mechanism_for_pair), over the raw data — without a
separate C_Digest step.

History: C_VerifyInit with a parameterized CKM_GOSTR3410/CKM_GOSTR3410_512 is
rejected by the SoftHSM fork used in e2e (CKR_MECHANISM_INVALID, see revert
b698efc), while parameterless CKM_GOSTR3410/CKM_GOSTR3410_512 fails on modules
that validate mechanism parameters (real Rutoken ECP), breaking the mandatory
self-check of a perfectly valid GOST signature. The combined mechanism with
the OID parameter is the single path proven by both the fork e2e (signing
uses it) and the Rutoken ECP documentation.

Contract:
- GOST verify: C_VerifyInit receives CKM_GOSTR3410_WITH_GOSTR3411_12_256 with
  pParameter == GOST_3411_2012_256_PARAMS (and the 512 variant accordingly);
  the parameter buffer must still be readable at init time (keepalive);
  C_Verify receives the RAW data (full length), no C_DigestInit/C_Digest.
- RSA verify: CKM_SHA256_RSA_PKCS without a parameter, as before.
- error paths: C_VerifyInit failure propagates, C_Verify is never called,
  the caller's signature buffer stays untouched; C_Verify failure propagates.
- sequences: several verifications in a row (RSA/GOST-256/GOST-512) each
  receive the correct mechanism and OID.
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
    """Fake PKCS#11 with recording C_VerifyInit/C_Verify (no digest)."""

    def verify_init(_session, mech, _key):
        mechanism_type, param = read_mechanism(mech)
        if captured is not None:
            captured.setdefault("verify_inits", []).append((mechanism_type, param))
        return verify_init_result

    def verify(_session, data, data_len, sig, sig_len):
        if captured is not None:
            captured.setdefault("verifies", []).append(
                (app.native_int(data_len), app.native_int(sig_len))
            )
        return verify_result

    return {
        "C_VerifyInit": verify_init,
        "C_Verify": verify,
    }


def signature_buffer(size, filler):
    return (app.CK_BYTE * size).from_buffer_copy(bytes([filler]) * size)


class VerifyMechanismParamsTests(unittest.TestCase):
    def test_gost256_verify_mechanism_is_combined_with_hash_oid(self):
        captured = {}
        data = (app.CK_BYTE * 8)(*b"testdata")
        app.verify_signature(
            1, make_funcs(captured), {"algorithm": app.CKK_GOSTR3410, "public": 9},
            data, 8, signature_buffer(64, 0x5A),
        )
        self.assertEqual(len(captured["verify_inits"]), 1)
        mechanism_type, param = captured["verify_inits"][0]
        self.assertEqual(mechanism_type, app.CKM_GOSTR3410_WITH_GOSTR3411_12_256)
        self.assertEqual(param, app.GOST_3411_2012_256_PARAMS)
        # Raw data over the combined mechanism: no digest step anywhere.
        self.assertNotIn("digest_inits", captured)
        self.assertEqual(captured["verifies"][0][0], 8)
        self.assertEqual(captured["verifies"][0][1], 64)

    def test_gost512_verify_mechanism_is_combined_with_hash_oid(self):
        captured = {}
        data = (app.CK_BYTE * 8)(*b"testdata")
        app.verify_signature(
            1, make_funcs(captured), {"algorithm": app.CKK_GOSTR3410_512, "public": 9},
            data, 8, signature_buffer(128, 0x5A),
        )
        mechanism_type, param = captured["verify_inits"][0]
        self.assertEqual(mechanism_type, app.CKM_GOSTR3410_WITH_GOSTR3411_12_512)
        self.assertEqual(param, app.GOST_3411_2012_512_PARAMS)

    def test_rsa_verify_has_no_parameter(self):
        captured = {}
        data = (app.CK_BYTE * 8)(*b"testdata")
        app.verify_signature(
            1, make_funcs(captured), {"algorithm": app.CKK_RSA, "public": 9},
            data, 8, signature_buffer(256, 0x5A),
        )
        mechanism_type, param = captured["verify_inits"][0]
        self.assertEqual(mechanism_type, app.CKM_SHA256_RSA_PKCS)
        self.assertIsNone(param)
        self.assertEqual(captured["verifies"][0], (8, 256))

    def test_verify_init_failure_propagates_and_verify_skipped(self):
        captured = {}
        signature = signature_buffer(64, 0x5A)
        with self.assertRaises(app.PKCS11Error):
            app.verify_signature(
                1, make_funcs(captured, verify_init_result=5),
                {"algorithm": app.CKK_GOSTR3410, "public": 9},
                (app.CK_BYTE * 4)(*b"data"), 4, signature,
            )
        self.assertNotIn("verifies", captured)
        self.assertEqual(bytes(signature), b"\x5A" * 64, "caller's buffer must stay untouched")

    def test_verify_failure_propagates(self):
        captured = {}
        with self.assertRaises(app.PKCS11Error):
            app.verify_signature(
                1, make_funcs(captured, verify_result=app.CKR_SIGNATURE_INVALID),
                {"algorithm": app.CKK_GOSTR3410, "public": 9},
                (app.CK_BYTE * 4)(*b"data"), 4, signature_buffer(64, 0x5A),
            )
        self.assertEqual(len(captured["verifies"]), 1)

    def test_sequence_rsa_gost256_gost512(self):
        captured = {}
        funcs = make_funcs(captured)
        pairs = [
            ({"algorithm": app.CKK_RSA, "public": 9}, 256, app.CKM_SHA256_RSA_PKCS, None),
            (
                {"algorithm": app.CKK_GOSTR3410, "public": 10}, 64,
                app.CKM_GOSTR3410_WITH_GOSTR3411_12_256, app.GOST_3411_2012_256_PARAMS,
            ),
            (
                {"algorithm": app.CKK_GOSTR3410_512, "public": 11}, 128,
                app.CKM_GOSTR3410_WITH_GOSTR3411_12_512, app.GOST_3411_2012_512_PARAMS,
            ),
        ]
        for index, (pair, sig_size, verify_mech, oid) in enumerate(pairs):
            app.verify_signature(
                1, funcs, pair, (app.CK_BYTE * 4)(*b"data"), 4, signature_buffer(sig_size, 0x5A + index),
            )
            mechanism_type, param = captured["verify_inits"][index]
            self.assertEqual(mechanism_type, verify_mech)
            self.assertEqual(param, oid)
        self.assertEqual(len(captured["verifies"]), 3)


if __name__ == "__main__":
    unittest.main()
