"""Regression tests: KEY_TYPES must contain only keys consumed by the code.

History: after the GOST digest+verify self-check path was removed (822d6f2),
the table kept the leftover entries "verify_mechanism", "digest_mechanism"
and "digest_size". Nothing reads them; worse, the same leftover once produced
a real bug — the verify_signature guard checked "verify_mechanism" while the
function used "sign_mechanism" (fixed in ed8cc91). Dead table keys invite the
same class of drift: a future reader can "fix" the self-check back to
"verify_mechanism", or a new key type can copy the dead fields instead of the
live contract.

Contract:
- every KEY_TYPES entry contains only keys the code actually consumes, and
  every signing-capable entry carries the full live set (no leftover
  digest+verify keys anywhere);
- the self-check mechanism captured at C_VerifyInit (type and OID parameter)
  is identical to the signing mechanism for every signing-capable algorithm —
  verified for several algorithms in a row (sequence);
- every temporary signature copy created by verify_signature on the bytes
  input path is wiped, including a sequence that ends with a failing
  C_Verify (error handling + resource cleanup).
"""
import ctypes
import unittest

import app


# The exact set of KEY_TYPES keys the code consumes:
# constant/name — display helpers; sign_mechanism/sign_params — signing and
# self-check mechanism; hash_mode — sign_file output; signature_size —
# signature_buffer_length.
CONSUMED_KEYS = {
    "constant",
    "name",
    "sign_mechanism",
    "sign_params",
    "hash_mode",
    "signature_size",
}

# Leftovers of the removed digest+verify self-check path: nothing in app.py
# may read them, and they must not reappear in the table.
FORBIDDEN_KEYS = {"verify_mechanism", "digest_mechanism", "digest_size"}


def make_funcs(captured=None, *, verify_init_result=app.CKR_OK, verify_result=app.CKR_OK):
    def verify_init(_session, mech, _key):
        if captured is not None:
            mechanism_type, param = read_mechanism(mech)
            captured.setdefault("verify_inits", []).append((mechanism_type, param))
        return verify_init_result

    def verify(_session, _data, _data_len, _sig, _sig_len):
        if captured is not None:
            captured["verifies"] = captured.get("verifies", 0) + 1
        return verify_result

    return {
        "C_VerifyInit": verify_init,
        "C_Verify": verify,
    }


def read_mechanism(mech_ref):
    mech = ctypes.cast(mech_ref, ctypes.POINTER(app.CK_MECHANISM)).contents
    param = None
    if mech.pParameter and int(mech.ulParameterLen):
        param = ctypes.string_at(mech.pParameter, int(mech.ulParameterLen))
    return int(mech.mechanism), param


class KeyTypesContractTests(unittest.TestCase):
    def test_table_contains_no_dead_digest_verify_keys(self):
        # Negative case this test must catch: any reappearance of the
        # digest+verify leftovers (the exact drift that caused the guard bug).
        for algorithm, info in app.KEY_TYPES.items():
            extra = set(info) & FORBIDDEN_KEYS
            self.assertFalse(
                extra,
                f"KEY_TYPES[{app.key_type_constant_name(algorithm)}] carries dead "
                f"keys {sorted(extra)} left from the removed digest+verify path",
            )

    def test_signing_entries_carry_exactly_the_consumed_keys(self):
        signing_algorithms = [
            algorithm for algorithm, info in app.KEY_TYPES.items()
            if "sign_mechanism" in info
        ]
        self.assertEqual(
            len(signing_algorithms), 3,
            "RSA, GOST-256 and GOST-512 must stay signing-capable",
        )
        for algorithm in signing_algorithms:
            info = app.KEY_TYPES[algorithm]
            # "sign_params" is mandatory for the GOST entries and absent for
            # RSA; everything else must match the consumed set exactly.
            self.assertLessEqual(set(info), CONSUMED_KEYS,
                                 f"unexpected keys in KEY_TYPES[{algorithm:08X}]")
            self.assertEqual(
                set(info) | {"sign_params"}, CONSUMED_KEYS,
                f"KEY_TYPES[{app.key_type_constant_name(algorithm)}] key set "
                f"drifted: {sorted((set(info) | {'sign_params'}) ^ CONSUMED_KEYS)}",
            )

    def test_selfcheck_mechanism_matches_signing_mechanism_for_all_algorithms(self):
        # Sequence over every signing-capable algorithm: the mechanism captured
        # at C_VerifyInit must equal the one signing_mechanism_for_pair builds
        # (same type, same OID parameter) — the invariant the digest+verify
        # leftovers violated.
        data = (app.CK_BYTE * 8)(*b"testdata")
        captured = {}
        funcs = make_funcs(captured)
        for algorithm, info in app.KEY_TYPES.items():
            if "sign_mechanism" not in info:
                continue
            signature_size = info["signature_size"]
            signature = (app.CK_BYTE * signature_size).from_buffer_copy(
                bytes([0x5A]) * signature_size
            )
            app.verify_signature(
                1, funcs, {"algorithm": algorithm, "public": 9},
                data, 8, signature,
            )
            sign_mechanism, _keepalive, _hash_mode = app.signing_mechanism_for_pair(
                {"algorithm": algorithm}
            )
            verify_mechanism_type, verify_param = captured["verify_inits"][-1]
            self.assertEqual(verify_mechanism_type, int(sign_mechanism.mechanism))
            expected_param = info.get("sign_params")
            self.assertEqual(verify_param, expected_param)
        self.assertEqual(len(captured["verify_inits"]), 3)
        self.assertEqual(captured["verifies"], 3)


class VerifySequenceCleanupTests(unittest.TestCase):
    def test_consecutive_copies_wiped_including_failing_final_verify(self):
        # Three verifications in a row via the bytes input path (each creates
        # a temporary copy inside verify_signature); the final C_Verify fails.
        # Every copy must still be wiped (finally), and the failure must
        # propagate as PKCS11Error.
        signature = bytes([0x5A]) * 64
        memsets = []
        orig_memset = ctypes.memset

        def logging_memset(addr, value, size):
            memsets.append((ctypes.cast(addr, ctypes.c_void_p).value,
                            app.native_int(size)))
            return orig_memset(addr, value, size)

        calls = []

        def verify(_session, _data, _data_len, _sig, _sig_len):
            calls.append("verify")
            return app.CKR_SIGNATURE_INVALID if len(calls) == 3 else app.CKR_OK

        funcs = {
            "C_VerifyInit": lambda *_: app.CKR_OK,
            "C_Verify": verify,
        }
        data = (app.CK_BYTE * 8)(*b"testdata")
        pair = {"algorithm": app.CKK_GOSTR3410, "public": 9}
        with mock_memset(logging_memset):
            app.verify_signature(1, funcs, pair, data, 8, signature)
            app.verify_signature(1, funcs, pair, data, 8, signature)
            with self.assertRaises(app.PKCS11Error):
                app.verify_signature(1, funcs, pair, data, 8, signature)
        # One temporary copy per call, each wiped exactly at signature size.
        wipes = [size for _addr, size in memsets if size == len(signature)]
        self.assertEqual(len(wipes), 3)
        self.assertEqual(len(calls), 3)


class mock_memset:
    """Context manager patching ctypes.memset for the duration of a block."""

    def __init__(self, replacement):
        self.replacement = replacement
        self.original = None

    def __enter__(self):
        self.original = ctypes.memset
        ctypes.memset = self.replacement
        return self

    def __exit__(self, *exc_info):
        ctypes.memset = self.original
        return False


if __name__ == "__main__":
    unittest.main(verbosity=2)
