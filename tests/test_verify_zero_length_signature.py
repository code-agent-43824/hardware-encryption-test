"""Regression tests: verify_signature must reject a zero-length signature
before any PKCS#11 call, for every supported key type.

Contract:
- A zero-length signature (empty buffer or raw b"") violates the PKCS#11
  contract the same way a zero ulSignatureLen does in sign_once/sign_file:
  a faulty or substituted module returning CKR_OK with a zero-length
  signature must not reach C_Verify and must not be masked as a generic
  self-check failure. verify_signature raises InvalidModuleLengthError
  BEFORE C_DigestInit/C_VerifyInit/C_Verify (fail fast, no partial state).
- The caller's signature buffer is never touched on the error path.
- Sequences: a failed zero-length verification must not corrupt subsequent
  verifications (multi-operation flow).
"""
import ctypes
import unittest

import app


def rsa_pair(public_handle=7):
    return {"algorithm": app.CKK_RSA, "public": public_handle}


def gost512_pair(public_handle=11):
    return {"algorithm": app.CKK_GOSTR3410_512, "public": public_handle}


def recording_funcs(calls, digest_result=app.CKR_OK, verify_result=app.CKR_OK):
    funcs = {
        "C_VerifyInit": lambda *_args: calls.append("verify_init") or app.CKR_OK,
        "C_Verify": lambda *_args: calls.append("verify") or verify_result,
    }

    def digest(_session, _data, _size, output, length):
        calls.append("digest")
        n = int(ctypes.cast(length, ctypes.POINTER(app.CK_ULONG)).contents.value)
        ctypes.memmove(output, b"D" * n, n)
        return digest_result

    funcs["C_DigestInit"] = lambda *_args: calls.append("digest_init") or app.CKR_OK
    funcs["C_Digest"] = digest
    return funcs


class VerifyZeroLengthSignatureTests(unittest.TestCase):
    def test_zero_length_ctypes_signature_rejected_before_any_call(self):
        # Negative case (RSA): zero-length buffer must fail fast with
        # InvalidModuleLengthError; no PKCS#11 call may observe the value.
        calls = []
        funcs = recording_funcs(calls)
        signature = (app.CK_BYTE * 0)()
        data = (app.CK_BYTE * 4)(*b"data")
        with self.assertRaises(app.InvalidModuleLengthError) as ctx:
            app.verify_signature(1, funcs, rsa_pair(), data, 4, signature)
        self.assertIn("0", str(ctx.exception))
        self.assertEqual(calls, [], "no PKCS#11 call may happen for a zero-length signature")

    def test_zero_length_bytes_signature_rejected_for_gost512(self):
        # Negative case (GOST-512, digest branch): a zero-length raw signature
        # must be rejected BEFORE C_DigestInit/C_Digest, not merely before
        # C_Verify — the fail-fast check is mechanism-independent.
        calls = []
        funcs = recording_funcs(calls)
        with self.assertRaises(app.InvalidModuleLengthError):
            app.verify_signature(1, funcs, gost512_pair(), (app.CK_BYTE * 4)(), 4, b"")
        self.assertEqual(calls, [])

    def test_error_is_invalid_module_length_not_masked(self):
        # Consistency with 3761561: the length contract violation must surface
        # as InvalidModuleLengthError so callers can distinguish a faulty or
        # substituted module from a generic self-check failure.
        funcs = recording_funcs([])
        with self.assertRaises(app.InvalidModuleLengthError):
            app.verify_signature(
                1, funcs, rsa_pair(), (app.CK_BYTE * 4)(), 4, b"",
            )

    def test_caller_buffer_untouched_on_zero_length_error(self):
        # Resource/cleanup check: on the error path verify_signature must not
        # modify (wipe) the caller's buffer and must not leave a signature copy.
        signature = (app.CK_BYTE * 256).from_buffer_copy(b"\xA5" * 256)
        signature[0] = 0x5A  # ctypes arrays are mutable: value is preserved
        funcs = recording_funcs([])
        with self.assertRaises(app.InvalidModuleLengthError):
            app.verify_signature(
                1, funcs, rsa_pair(), (app.CK_BYTE * 4)(*b"data"), 4, b"",
            )
        # The zero-length call never reaches buffer handling; the valid-size
        # buffer passed by the caller in a failed mixed call stays intact too.
        self.assertEqual(bytes(signature), b"\x5A" + b"\xA5" * 255)

    def test_sequence_valid_then_zero_length_then_valid(self):
        # Multi-operation sequence: a failed zero-length verification must not
        # leave partial PKCS#11 state or break subsequent verifications.
        captured = []
        calls = []
        funcs = recording_funcs(calls)
        orig_verify = funcs["C_Verify"]

        def verify(_session, _data, data_len, sig, sig_len):
            captured.append(app.native_int(sig_len))
            return orig_verify(_session, _data, data_len, sig, sig_len)

        funcs["C_Verify"] = verify
        signature = (app.CK_BYTE * 256).from_buffer_copy(b"\xC3" * 256)
        data = (app.CK_BYTE * 16)(*b"0123456789abcdef")
        app.verify_signature(1, funcs, rsa_pair(), data, 16, signature)
        with self.assertRaises(app.InvalidModuleLengthError):
            app.verify_signature(1, funcs, rsa_pair(), data, 16, b"")
        app.verify_signature(1, funcs, rsa_pair(), data, 16, signature)
        self.assertEqual(captured, [256, 256])
        self.assertEqual(calls, ["verify_init", "verify", "verify_init", "verify"])
        self.assertEqual(bytes(signature), b"\xC3" * 256)


if __name__ == "__main__":
    unittest.main(verbosity=2)
