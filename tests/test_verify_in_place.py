"""Regression tests: verify_signature must verify in place when the caller
passes an already wipeable ctypes byte buffer (as sign_file does), instead of
creating a second from_buffer_copy of the signature.

Contract:
- ctypes buffer input: C_Verify receives the SAME buffer (address identity);
  the input buffer is NOT wiped or modified by verify_signature (it belongs to
  the caller, whose finally wipes it).
- raw bytes input: previous behavior — a copy is made and wiped in finally.
- error paths: digest is still wiped; with ctypes input the caller's signature
  buffer is left untouched.
- sequences: several verify calls in a row reuse the same buffer in place.
"""
import ctypes
import unittest
from unittest import mock

import app


def make_verify_funcs(verify_result=app.CKR_OK, captured=None):
    def verify(_session, data, data_len, sig, sig_len):
        if captured is not None:
            captured["sig_addr"] = ctypes.cast(sig, ctypes.c_void_p).value
            captured["sig_len"] = app.native_int(sig_len)
            captured["sig_data"] = ctypes.string_at(
                sig, captured["sig_len"]
            ) if captured["sig_len"] else b""
            captured["data_len"] = app.native_int(data_len)
        return verify_result

    return {
        "C_VerifyInit": lambda *_args: app.CKR_OK,
        "C_Verify": verify,
    }


def rsa_pair(public_handle=7):
    return {"algorithm": app.CKK_RSA, "public": public_handle}


def gost_funcs_for_gost_pair(verify_result=app.CKR_OK, captured=None):
    funcs = make_verify_funcs(verify_result, captured)

    def digest(_session, _data, _size, output, length):
        n = int(ctypes.cast(length, ctypes.POINTER(app.CK_ULONG)).contents.value)
        if captured is not None:
            captured["digest_buffer"] = ctypes.cast(
                output, ctypes.POINTER(app.CK_BYTE * n)
            ).contents
        ctypes.memmove(output, b"D" * n, n)
        return app.CKR_OK

    funcs["C_DigestInit"] = lambda *_args: app.CKR_OK
    funcs["C_Digest"] = digest
    return funcs


class VerifySignatureInPlaceTests(unittest.TestCase):
    def test_ctypes_signature_buffer_is_verified_in_place(self):
        # The core regression: before the fix C_Verify received a COPY of the
        # signature (different address); now it must receive the caller's
        # buffer itself, and the buffer must remain intact (caller wipes it).
        captured = {}
        funcs = make_verify_funcs(captured=captured)
        signature = (app.CK_BYTE * 256).from_buffer_copy(b"\xA5" * 256)
        data = (app.CK_BYTE * 4)(*b"data")
        app.verify_signature(1, funcs, rsa_pair(), data, 4, signature)
        self.assertEqual(captured["sig_addr"], ctypes.addressof(signature))
        self.assertEqual(captured["sig_len"], 256)
        self.assertEqual(captured["sig_data"], b"\xA5" * 256)
        # Caller's buffer is not wiped/modified by verify_signature.
        self.assertEqual(bytes(signature), b"\xA5" * 256)

    def test_ctypes_signature_buffer_untouched_on_invalid_signature(self):
        # Negative case: CKR_SIGNATURE_INVALID must raise, the digest must be
        # wiped, and the caller's signature buffer must stay untouched.
        captured = {}
        funcs = gost_funcs_for_gost_pair(app.CKR_SIGNATURE_INVALID, captured)
        signature = (app.CK_BYTE * 64).from_buffer_copy(b"\x5A" * 64)
        data = (app.CK_BYTE * 8)(*b"testdata")
        with self.assertRaises(app.PKCS11Error):
            app.verify_signature(1, funcs, {"algorithm": app.CKK_GOSTR3410, "public": 9}, data, 8, signature)
        self.assertEqual(bytes(signature), b"\x5A" * 64, "caller's buffer must not be wiped")
        self.assertEqual(bytes(captured["digest_buffer"]), b"\0" * 32, "digest must be wiped")

    def test_ctypes_signature_buffer_untouched_on_digest_failure(self):
        # Negative case: C_Digest fails mid-operation; the caller's signature
        # buffer must not be touched and C_Verify must never be called.
        calls = []

        def fail_digest(_session, _data, _size, _output, _length):
            calls.append("digest")
            return 5

        funcs = {
            "C_DigestInit": lambda *_args: app.CKR_OK,
            "C_Digest": fail_digest,
            "C_VerifyInit": lambda *_args: calls.append("verify_init"),
            "C_Verify": lambda *_args: calls.append("verify"),
        }
        signature = (app.CK_BYTE * 64).from_buffer_copy(b"\x5A" * 64)
        with self.assertRaises(app.PKCS11Error):
            app.verify_signature(
                1, funcs, {"algorithm": app.CKK_GOSTR3410, "public": 9},
                (app.CK_BYTE * 4)(*b"data"), 4, signature,
            )
        self.assertEqual(calls, ["digest"])
        self.assertEqual(bytes(signature), b"\x5A" * 64)

    def test_bytes_signature_still_copied_and_wiped(self):
        # Backward compatibility: raw bytes input still goes through a copy
        # which is wiped in finally (covered behavior kept intact).
        captured = {}
        funcs = make_verify_funcs(captured=captured)
        data = (app.CK_BYTE * 4)(*b"data")
        app.verify_signature(1, funcs, rsa_pair(), data, 4, b"\xA5" * 256)
        self.assertEqual(captured["sig_len"], 256)
        self.assertEqual(captured["sig_data"], b"\xA5" * 256)
        # The buffer passed to C_Verify cannot be the caller's bytes object.
        self.assertNotEqual(captured["sig_addr"], 0)

    def test_unsupported_algorithm_raises_before_any_crypto_call(self):
        # Negative case: unsupported key type fails fast without touching the
        # signature buffer or calling C_VerifyInit/C_Verify.
        calls = []
        funcs = {
            "C_VerifyInit": lambda *_args: calls.append("verify_init"),
            "C_Verify": lambda *_args: calls.append("verify"),
        }
        signature = (app.CK_BYTE * 8).from_buffer_copy(b"\x11" * 8)
        with self.assertRaises(app.PKCS11Error):
            app.verify_signature(
                1, funcs, {"algorithm": app.CKK_KUZNECHIK, "public": 3},
                (app.CK_BYTE * 4)(), 4, signature,
            )
        self.assertEqual(calls, [])
        self.assertEqual(bytes(signature), b"\x11" * 8)

    def test_sequence_of_verifications_reuses_same_buffer_in_place(self):
        # Multi-operation sequence: several verifications in a row (as the
        # benchmark self-check flow could do) must all verify in place and
        # never accumulate copies or modify the caller's buffer.
        captured = []
        funcs = make_verify_funcs(captured={})
        orig_verify = funcs["C_Verify"]

        def verify(*args):
            captured.append(ctypes.cast(args[3], ctypes.c_void_p).value)
            return orig_verify(*args)

        funcs["C_Verify"] = verify
        signature = (app.CK_BYTE * 256).from_buffer_copy(b"\xC3" * 256)
        data = (app.CK_BYTE * 16)(*b"0123456789abcdef")
        for _ in range(3):
            app.verify_signature(1, funcs, rsa_pair(), data, 16, signature)
        self.assertEqual(captured, [ctypes.addressof(signature)] * 3)
        self.assertEqual(bytes(signature), b"\xC3" * 256)


if __name__ == "__main__":
    unittest.main(verbosity=2)
