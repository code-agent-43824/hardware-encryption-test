"""Regression tests: verify_signature must pass the GOST hash OID parameter
to C_DigestInit (the same OID the signing path uses for the combined
mechanism). Modules that validate mechanism parameters (real Rutoken ECP)
reject a parameterless CKM_GOSTR3411_12_256, which made the signature
self-check fail for a perfectly valid signature.

Contract:
- GOST verify: C_DigestInit receives mechanism CKM_GOSTR3411_12_256 with
  pParameter == GOST_3411_2012_256_PARAMS (and 512 variant accordingly);
  the parameter buffer must still be readable at init time (keepalive).
- RSA verify: no digest call at all.
- error paths: C_DigestInit failure propagates, C_Verify is never called,
  the caller's signature buffer stays untouched;
  C_Digest failure propagates and the digest buffer is wiped.
- sequences: several verifications in a row (RSA/GOST-256/GOST-512) each
  receive the correct mechanism and OID.
"""
import ctypes
import unittest
from unittest import mock

import app


def read_mechanism(mech_ref):
    mech = ctypes.cast(mech_ref, ctypes.POINTER(app.CK_MECHANISM)).contents
    param = None
    if mech.pParameter and int(mech.ulParameterLen):
        param = ctypes.string_at(mech.pParameter, int(mech.ulParameterLen))
    return int(mech.mechanism), param


def make_funcs(captured=None, *, digest_init_result=app.CKR_OK, digest_result=app.CKR_OK,
               verify_result=app.CKR_OK):
    """Fake PKCS#11 with recording C_DigestInit/C_Digest/C_VerifyInit/C_Verify."""

    def digest_init(_session, mech):
        mechanism_type, param = read_mechanism(mech)
        if captured is not None:
            captured.setdefault("digest_inits", []).append((mechanism_type, param))
        return digest_init_result

    def digest(_session, _data, _size, output, length):
        n = int(ctypes.cast(length, ctypes.POINTER(app.CK_ULONG)).contents.value)
        if captured is not None:
            captured["digest_buffer"] = ctypes.cast(output, ctypes.POINTER(app.CK_BYTE * n)).contents
        ctypes.memmove(output, b"D" * n, n)
        return digest_result

    def verify_init(_session, mech, _key):
        mechanism_type, param = read_mechanism(mech)
        if captured is not None:
            captured.setdefault("verify_inits", []).append((mechanism_type, param))
        return app.CKR_OK

    def verify(_session, data, data_len, sig, sig_len):
        if captured is not None:
            captured.setdefault("verifies", []).append(
                (app.native_int(data_len), app.native_int(sig_len))
            )
        return verify_result

    return {
        "C_DigestInit": digest_init,
        "C_Digest": digest,
        "C_VerifyInit": verify_init,
        "C_Verify": verify,
    }


def signature_buffer(size, filler):
    return (app.CK_BYTE * size).from_buffer_copy(bytes([filler]) * size)


class VerifyDigestParamsTests(unittest.TestCase):
    def test_gost256_digest_mechanism_carries_hash_oid(self):
        captured = {}
        data = (app.CK_BYTE * 8)(*b"testdata")
        app.verify_signature(
            1, make_funcs(captured), {"algorithm": app.CKK_GOSTR3410, "public": 9},
            data, 8, signature_buffer(64, 0x5A),
        )
        self.assertEqual(len(captured["digest_inits"]), 1)
        mechanism_type, param = captured["digest_inits"][0]
        self.assertEqual(mechanism_type, app.CKM_GOSTR3411_12_256)
        self.assertEqual(param, app.GOST_3411_2012_256_PARAMS)

    def test_gost512_digest_mechanism_carries_hash_oid(self):
        captured = {}
        data = (app.CK_BYTE * 8)(*b"testdata")
        app.verify_signature(
            1, make_funcs(captured), {"algorithm": app.CKK_GOSTR3410_512, "public": 9},
            data, 8, signature_buffer(128, 0x5A),
        )
        mechanism_type, param = captured["digest_inits"][0]
        self.assertEqual(mechanism_type, app.CKM_GOSTR3411_12_512)
        self.assertEqual(param, app.GOST_3411_2012_512_PARAMS)

    def test_rsa_verify_does_not_digest(self):
        captured = {}
        data = (app.CK_BYTE * 8)(*b"testdata")
        app.verify_signature(
            1, make_funcs(captured), {"algorithm": app.CKK_RSA, "public": 9},
            data, 8, signature_buffer(256, 0x5A),
        )
        self.assertNotIn("digest_inits", captured)
        self.assertEqual(captured["verify_inits"][0][0], app.CKM_SHA256_RSA_PKCS)

    def test_digest_init_failure_propagates_and_verify_skipped(self):
        captured = {}
        signature = signature_buffer(64, 0x5A)
        with self.assertRaises(app.PKCS11Error):
            app.verify_signature(
                1, make_funcs(captured, digest_init_result=5),
                {"algorithm": app.CKK_GOSTR3410, "public": 9},
                (app.CK_BYTE * 4)(*b"data"), 4, signature,
            )
        self.assertNotIn("verifies", captured)
        self.assertNotIn("digest_buffer", captured)
        self.assertEqual(bytes(signature), b"\x5A" * 64, "caller's buffer must stay untouched")

    def test_digest_failure_wipes_digest_buffer(self):
        captured = {}
        with self.assertRaises(app.PKCS11Error):
            app.verify_signature(
                1, make_funcs(captured, digest_result=5),
                {"algorithm": app.CKK_GOSTR3410, "public": 9},
                (app.CK_BYTE * 4)(*b"data"), 4, signature_buffer(64, 0x5A),
            )
        self.assertEqual(bytes(captured["digest_buffer"]), b"\0" * 32, "digest must be wiped")

    def test_sequence_rsa_gost256_gost512(self):
        captured = {}
        funcs = make_funcs(captured)
        pairs = [
            ({"algorithm": app.CKK_RSA, "public": 9}, 256, app.CKM_SHA256_RSA_PKCS, None),
            ({"algorithm": app.CKK_GOSTR3410, "public": 10}, 64, app.CKM_GOSTR3410, app.GOST_3411_2012_256_PARAMS),
            ({"algorithm": app.CKK_GOSTR3410_512, "public": 11}, 128, app.CKM_GOSTR3410_512, app.GOST_3411_2012_512_PARAMS),
        ]
        for index, (pair, sig_size, verify_mech, digest_oid) in enumerate(pairs):
            app.verify_signature(
                1, funcs, pair, (app.CK_BYTE * 4)(*b"data"), 4, signature_buffer(sig_size, 0x5A + index),
            )
            self.assertEqual(captured["verify_inits"][index][0], verify_mech)
            if digest_oid is None:
                self.assertNotIn("digest_inits", captured) if index == 0 else None
        self.assertEqual(len(captured["verifies"]), 3)
        self.assertEqual(
            [init[1] for init in captured["digest_inits"]],
            [app.GOST_3411_2012_256_PARAMS, app.GOST_3411_2012_512_PARAMS],
        )


if __name__ == "__main__":
    unittest.main()
