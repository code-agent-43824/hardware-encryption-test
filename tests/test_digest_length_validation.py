"""Regression tests: verify_signature must not trust the pulDigestLen
reported by the (untrusted) PKCS#11 module after C_Digest.

Contract:
- If the module returns CKR_OK with a digest length greater than the capacity
  of the digest buffer (info["digest_size"]), verify_signature must raise
  PKCS11Error with a diagnostic message BEFORE C_VerifyInit/C_Verify:
  otherwise C_Verify is invoked with an oversized data length, causing a
  native out-of-bounds read past the digest buffer inside the module.
- The digest buffer must be wiped even when the length check fails (finally).
- Normal flows are unaffected: a length equal to the buffer capacity is valid
  and C_Verify receives exactly the digest capacity as the data length.
- Sequences: several verifications in a row keep working; a failing second
  verification must not invoke C_Verify and must leave nothing unwiped.
"""
import ctypes
import unittest
from unittest import mock

import app
from test_verify_digest_params import make_funcs, signature_buffer


def inflate_digest_lengths(base_funcs, extra):
    """Wrap C_Digest so a successful call reports a length inflated by
    `extra` bytes (simulating a faulty or hostile module)."""
    orig_digest = base_funcs["C_Digest"]

    def inflating_digest(session, data, size, output, length):
        rv = orig_digest(session, data, size, output, length)
        if rv == app.CKR_OK:
            dl = ctypes.cast(length, ctypes.POINTER(app.CK_ULONG))
            dl[0] = app.CK_ULONG(app.native_int(dl[0]) + extra)
        return rv

    base_funcs["C_Digest"] = inflating_digest
    return base_funcs


class DigestLengthValidationTests(unittest.TestCase):
    def run_verify(self, wrap=None, signature_size=64):
        """Run verify_signature with a GOST-256 pair. Returns (captured,
        memsets, error)."""
        captured = {}
        wrapped = make_funcs(captured)
        if wrap is not None:
            wrap(wrapped)

        orig_memset = ctypes.memset
        memsets = []

        def logging_memset(addr, value, size):
            memsets.append(app.native_int(size))
            return orig_memset(addr, value, size)

        error = None
        with mock.patch.object(ctypes, "memset", logging_memset):
            try:
                app.verify_signature(
                    1, wrapped, {"algorithm": app.CKK_GOSTR3410, "public": 9},
                    (app.CK_BYTE * 4)(*b"data"), 4, signature_buffer(signature_size, 0x5A),
                )
            except app.PKCS11Error as exc:
                error = exc
        return captured, memsets, error

    def test_inflated_digest_length_raises_before_verify(self):
        # Digest capacity is 32; the module reports 32 + 8. Must fail with a
        # diagnostic PKCS11Error, C_VerifyInit/C_Verify must not be called and
        # the digest buffer must be wiped in finally.
        captured, memsets, error = self.run_verify(
            wrap=lambda f: inflate_digest_lengths(f, 8),
        )
        self.assertIsNotNone(error)
        self.assertIn("некорректную длину дайджеста", str(error))
        self.assertIn("40 > ёмкости буфера 32", str(error))
        self.assertNotIn("verify_inits", captured, "C_VerifyInit must not be called")
        self.assertNotIn("verifies", captured, "C_Verify must not be called")
        self.assertIn(32, memsets, "digest buffer must be wiped")

    def test_inflated_digest_in_sequence_leaves_no_unwiped_state(self):
        # First verification succeeds; the second one reports an inflated
        # digest length. The first C_Verify must have happened, the second
        # must not, and the digest of the failed call must be wiped.
        captured = {}
        wrapped = make_funcs(captured)
        orig_digest = wrapped["C_Digest"]
        calls = []

        def inflating_on_second_call(session, data, size, output, length):
            calls.append("digest")
            rv = orig_digest(session, data, size, output, length)
            if rv == app.CKR_OK and len(calls) > 1:
                dl = ctypes.cast(length, ctypes.POINTER(app.CK_ULONG))
                dl[0] = app.CK_ULONG(app.native_int(dl[0]) + 1)
            return rv

        wrapped["C_Digest"] = inflating_on_second_call

        orig_memset = ctypes.memset
        memsets = []

        def logging_memset(addr, value, size):
            memsets.append(app.native_int(size))
            return orig_memset(addr, value, size)

        with mock.patch.object(ctypes, "memset", logging_memset):
            app.verify_signature(
                1, wrapped, {"algorithm": app.CKK_GOSTR3410, "public": 9},
                (app.CK_BYTE * 4)(*b"data"), 4, signature_buffer(64, 0x5A),
            )
            with self.assertRaises(app.PKCS11Error) as ctx:
                app.verify_signature(
                    1, wrapped, {"algorithm": app.CKK_GOSTR3410, "public": 9},
                    (app.CK_BYTE * 4)(*b"data"), 4, signature_buffer(64, 0x5A),
                )
        self.assertIn("33 > ёмкости буфера 32", str(ctx.exception))
        self.assertEqual(len(captured["verifies"]), 1, "only the first verify must run")
        self.assertEqual(captured["verifies"][0][0], 32)
        self.assertIn(32, memsets, "digest of the failed call must be wiped")

    def test_digest_length_equal_to_capacity_succeeds(self):
        # A length exactly equal to the buffer capacity is valid: C_Verify
        # must receive the digest capacity as the data length.
        captured, memsets, error = self.run_verify()
        self.assertIsNone(error)
        self.assertEqual(len(captured["verifies"]), 1)
        self.assertEqual(captured["verifies"][0][0], 32)
        self.assertEqual(len(captured["digest_inits"]), 1)

    def test_inflated_digest_rsa_path_unaffected(self):
        # RSA has no digest stage: the inflated C_Digest wrapper must never be
        # called and verification must succeed.
        calls = []

        def digest(*_args):
            calls.append("digest")
            return app.CKR_OK

        captured = {}
        wrapped = make_funcs(captured)
        wrapped["C_Digest"] = digest
        app.verify_signature(
            1, wrapped, {"algorithm": app.CKK_RSA, "public": 9},
            (app.CK_BYTE * 4)(*b"data"), 4, signature_buffer(256, 0x5A),
        )
        self.assertEqual(calls, [], "RSA path must not call C_Digest")
        self.assertEqual(len(captured["verifies"]), 1)
        self.assertEqual(captured["verifies"][0][0], 4)


if __name__ == "__main__":
    unittest.main()
