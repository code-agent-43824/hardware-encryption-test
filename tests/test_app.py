import ctypes
import io
import tempfile
import unittest
from pathlib import Path
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

    def test_encryption_operation_is_prepared_before_measurement(self):
        params = bytes.fromhex("0000800001020304")
        algorithm = {"encrypt_mechanism": app.CKM_MAGMA_CTR_ACPKM}
        operation = app.prepare_encryption_operation(algorithm, params, 512000)
        self.assertEqual(operation["params"], params)
        self.assertEqual(int(operation["mechanism"].ulParameterLen), len(params))
        self.assertEqual(
            ctypes.string_at(operation["mechanism"].pParameter, int(operation["mechanism"].ulParameterLen)),
            params,
        )
        self.assertEqual(int(operation["output_length"].value), 512000)
        self.assertIsNotNone(operation["mechanism_keepalive"])


class BenchmarkMetricTests(unittest.TestCase):
    def test_metrics_separate_pkcs11_time_from_total_wall_time(self):
        metrics = app.calculate_benchmark_metrics(
            data_size=1024 * 1024,
            count=2,
            operation_times=[0.4, 0.6],
            total_elapsed=1.25,
        )
        self.assertAlmostEqual(metrics["operation_elapsed"], 1.0)
        self.assertAlmostEqual(metrics["average_operation"], 0.5)
        self.assertAlmostEqual(metrics["minimum_operation"], 0.4)
        self.assertAlmostEqual(metrics["maximum_operation"], 0.6)
        self.assertAlmostEqual(metrics["operation_throughput_mib_s"], 2.0)
        self.assertAlmostEqual(metrics["total_throughput_mib_s"], 1.6)

    def test_warmup_default_is_configurable_and_zero_is_allowed(self):
        with mock.patch("builtins.input", return_value=""):
            self.assertEqual(app.prompt_warmup_count(), app.DEFAULT_WARMUP_COUNT)
        with mock.patch("builtins.input", return_value="0"):
            self.assertEqual(app.prompt_warmup_count(), 0)


class ReliabilityTests(unittest.TestCase):
    def test_verify_signature_wipes_digest_and_signature_after_verification(self):
        for verify_result in (app.CKR_OK, app.CKR_SIGNATURE_INVALID):
            with self.subTest(verify_result=verify_result):
                captured = {}

                def digest(_session, _data, _size, output, _length):
                    captured["digest"] = ctypes.cast(output, ctypes.POINTER(app.CK_BYTE * 32)).contents
                    ctypes.memmove(output, b"D" * 32, 32)
                    return app.CKR_OK

                def verify(_session, digest_data, _digest_size, signature, _signature_size):
                    self.assertEqual(bytes(ctypes.cast(digest_data, ctypes.POINTER(app.CK_BYTE * 32)).contents), b"D" * 32)
                    captured["signature"] = ctypes.cast(signature, ctypes.POINTER(app.CK_BYTE * 3)).contents
                    self.assertEqual(bytes(captured["signature"]), b"SIG")
                    return verify_result

                funcs = {
                    "C_DigestInit": lambda *_args: app.CKR_OK,
                    "C_Digest": digest,
                    "C_VerifyInit": lambda *_args: app.CKR_OK,
                    "C_Verify": verify,
                }
                data = (app.CK_BYTE * 4)(*b"data")
                if verify_result == app.CKR_OK:
                    app.verify_signature(1, funcs, {"algorithm": app.CKK_GOSTR3410, "public": 1}, data, 4, b"SIG")
                else:
                    with self.assertRaises(app.PKCS11Error):
                        app.verify_signature(1, funcs, {"algorithm": app.CKK_GOSTR3410, "public": 1}, data, 4, b"SIG")
                self.assertEqual(bytes(captured["digest"]), b"\0" * 32)
                self.assertEqual(bytes(captured["signature"]), b"\0" * 3)

    def test_verify_signature_wipes_partially_written_digest_on_error(self):
        captured = {}

        def fail_digest(_session, _data, _size, output, _length):
            captured["digest"] = ctypes.cast(output, ctypes.POINTER(app.CK_BYTE * 32)).contents
            ctypes.memmove(output, b"D" * 32, 32)
            return 5

        funcs = {"C_DigestInit": lambda *_args: app.CKR_OK, "C_Digest": fail_digest}
        with self.assertRaises(app.PKCS11Error):
            app.verify_signature(
                1, funcs, {"algorithm": app.CKK_GOSTR3410, "public": 1},
                (app.CK_BYTE * 4)(*b"data"), 4, b"SIG",
            )
        self.assertEqual(bytes(captured["digest"]), b"\0" * 32)

    def test_file_is_read_into_wipeable_buffer_without_read_bytes(self):
        class ReadIntoOnly(io.BytesIO):
            def read(self, *_args):
                raise AssertionError("an immutable bytes chunk was requested")

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample"
            path.write_bytes(b"sample data")
            with mock.patch("builtins.open", return_value=ReadIntoOnly(b"sample data")):
                buffer, size = app.read_file_into_wipeable_buffer(path)
        self.assertEqual(size, 11)
        self.assertEqual(bytes(buffer), b"sample data")

    def test_decrypt_error_wipes_partially_written_plaintext(self):
        captured = {}

        def fail_decrypt(_session, ciphertext, size, plaintext, _length):
            length = int(size.value)
            captured["ciphertext"] = ctypes.cast(ciphertext, ctypes.POINTER(app.CK_BYTE * length)).contents
            captured["plaintext"] = ctypes.cast(plaintext, ctypes.POINTER(app.CK_BYTE * length)).contents
            ctypes.memmove(plaintext, b"SECRET", length)
            return 5

        funcs = {"C_DecryptInit": lambda *_args: app.CKR_OK, "C_Decrypt": fail_decrypt}
        with self.assertRaises(app.PKCS11Error):
            app.decrypt_and_check(
                1, funcs, 1, {"name": "test", "encrypt_mechanism": 1}, b"cipher", b"", b"SECRET"
            )
        self.assertEqual(bytes(captured["plaintext"]), b"\0" * 6)
        self.assertEqual(bytes(captured["ciphertext"]), b"\0" * 6)

    def test_encrypt_retry_returns_wipeable_buffer(self):
        payload = b"abc"
        source = (app.CK_BYTE * len(payload)).from_buffer_copy(payload)
        destination = (app.CK_BYTE * 5)()
        calls = []

        def encrypt(_session, _data, _size, output, output_length):
            calls.append(1)
            length = ctypes.cast(output_length, ctypes.POINTER(app.CK_ULONG))
            if len(calls) == 1:
                length[0] = 5
                return app.CKR_BUFFER_TOO_SMALL
            ctypes.memmove(output, b"abcXY", 5)
            length[0] = 5
            return app.CKR_OK

        funcs = {"C_EncryptInit": lambda *_args: app.CKR_OK, "C_Encrypt": encrypt}
        operation = app.prepare_encryption_operation({"encrypt_mechanism": 1}, b"", 3)
        output_length, _, output = app.encrypt_with_generated_key(
            1, funcs, 1, {"name": "test"}, source, app.CK_ULONG(3), destination, operation
        )
        self.assertEqual(output_length, 5)
        self.assertEqual(len(calls), 2)
        self.assertIsInstance(output, ctypes.Array)
        self.assertEqual(bytes(output), b"abcXY")

    def test_encrypt_retry_failure_wipes_temporary_output(self):
        captured = {}
        calls = []

        def encrypt(_session, _data, _size, output, output_length):
            calls.append(1)
            length = ctypes.cast(output_length, ctypes.POINTER(app.CK_ULONG))
            if len(calls) == 1:
                length[0] = 6
                return app.CKR_BUFFER_TOO_SMALL
            captured["output"] = ctypes.cast(output, ctypes.POINTER(app.CK_BYTE * 6)).contents
            ctypes.memmove(output, b"SECRET", 6)
            return 5

        funcs = {"C_EncryptInit": lambda *_args: app.CKR_OK, "C_Encrypt": encrypt}
        operation = app.prepare_encryption_operation({"encrypt_mechanism": 1}, b"", 3)
        with self.assertRaises(app.PKCS11Error):
            app.encrypt_with_generated_key(
                1, funcs, 1, {"name": "test"}, (app.CK_BYTE * 3)(), app.CK_ULONG(3),
                (app.CK_BYTE * 3)(), operation,
            )
        self.assertEqual(bytes(captured["output"]), b"\0" * 6)

    def test_macos_default_library_uses_installed_system_path(self):
        with mock.patch.object(app.platform, "system", return_value="Darwin"):
            self.assertEqual(app.default_library_path(), Path("/usr/local/lib/librtpkcs11ecp.dylib"))
            self.assertEqual(app.resolve_library_path(""), Path("/usr/local/lib/librtpkcs11ecp.dylib"))

    def test_key_type_is_printed_as_pkcs11_constant(self):
        pair = {
            "id": "rsa",
            "label": "rsa",
            "algorithm": app.CKK_RSA,
            "duplicate_count": 1,
        }
        output = io.StringIO()
        with mock.patch("sys.stdout", output):
            app.print_pair("0", pair)
        self.assertIn("algorithm=CKK_RSA (RSA-2048)", output.getvalue())
        self.assertNotIn("algorithm=0x00000000", output.getvalue())

    def test_pairing_uses_raw_id_and_keeps_duplicates(self):
        records = [
            {"kind": "public", "handle": app.CK_OBJECT_HANDLE(1), "id_raw": b"same", "label": "A", "algorithm": app.CKK_RSA},
            {"kind": "private", "handle": 2, "id_raw": b"same", "label": "A", "algorithm": app.CKK_RSA},
            {"kind": "public", "handle": 3, "id_raw": b"same", "label": "B", "algorithm": app.CKK_RSA},
            {"kind": "private", "handle": 4, "id_raw": b"same", "label": "B", "algorithm": app.CKK_RSA},
            # These IDs render alike after whitespace trimming, but are not the same bytes.
            {"kind": "public", "handle": 5, "id_raw": b"shown", "label": "C", "algorithm": app.CKK_GOSTR3410},
            {"kind": "private", "handle": 6, "id_raw": b" shown ", "label": "C", "algorithm": app.CKK_GOSTR3410},
        ]
        pairs = app.pair_key_records(records)
        rsa_pairs = [pair for pair in pairs if pair["algorithm"] == app.CKK_RSA]
        gost_pairs = [pair for pair in pairs if pair["algorithm"] == app.CKK_GOSTR3410]
        self.assertEqual(
            [(app.native_int(pair["public"]), app.native_int(pair["private"])) for pair in rsa_pairs],
            [(1, 2), (3, 4)],
        )
        self.assertEqual([pair["duplicate_count"] for pair in rsa_pairs], [2, 2])
        self.assertEqual(len(gost_pairs), 2)
        self.assertTrue(all(not (pair["public"] and pair["private"]) for pair in gost_pairs))

    def test_cleanup_error_does_not_hide_action_error(self):
        funcs = {}
        original_error = app.PKCS11Error("исходная ошибка", 0x55)
        with (
            mock.patch.object(app, "open_session", return_value=7),
            mock.patch.object(app, "login", return_value=True),
            mock.patch.object(app, "logout", side_effect=app.PKCS11Error("ошибка logout", 0x66)),
            mock.patch.object(app, "close_session", side_effect=app.PKCS11Error("ошибка close", 0x77)),
            mock.patch("sys.stderr", io.StringIO()) as stderr,
        ):
            with self.assertRaises(app.PKCS11Error) as caught:
                app.run_with_session(
                    funcs,
                    1,
                    lambda _session, _funcs: (_ for _ in ()).throw(original_error),
                    login_required=True,
                )
        self.assertIs(caught.exception, original_error)
        self.assertIn("ошибка logout", stderr.getvalue())
        self.assertIn("ошибка close", stderr.getvalue())

    def test_initialize_ownership_is_explicit(self):
        self.assertTrue(app.initialize_pkcs11({"C_Initialize": mock.Mock(return_value=app.CKR_OK)}))
        self.assertFalse(
            app.initialize_pkcs11(
                {"C_Initialize": mock.Mock(return_value=app.CKR_CRYPTOKI_ALREADY_INITIALIZED)}
            )
        )

    def test_blank_pin_uses_documented_demo_pin(self):
        login_call = mock.Mock(return_value=app.CKR_OK)
        with mock.patch.object(app.getpass, "getpass", return_value=""):
            self.assertTrue(app.login({"C_Login": login_call}, 1))
        login_call.assert_called_once()
        session, user_type, pin, pin_length = login_call.call_args.args
        self.assertEqual(session, 1)
        self.assertEqual(app.native_int(user_type), app.CKU_USER)
        self.assertEqual(pin, app.DEFAULT_PIN.encode("utf-8"))
        self.assertEqual(app.native_int(pin_length), len(app.DEFAULT_PIN))

    def test_stale_application_temp_keys_are_removed(self):
        destroy = mock.Mock(return_value=app.CKR_OK)
        funcs = {"C_DestroyObject": destroy}
        with (
            mock.patch.object(app, "find_objects", return_value=[11, 12, 13]),
            mock.patch.object(
                app,
                "attr_text",
                side_effect=[
                    f"{app.TEMP_KEY_LABEL_PREFIX}old-a",
                    "user-secret-key",
                    f"{app.TEMP_KEY_LABEL_PREFIX}old-b",
                ],
            ),
            mock.patch("sys.stdout", io.StringIO()),
        ):
            self.assertEqual(app.cleanup_stale_temp_keys(1, funcs), 2)
        self.assertEqual([call.args[1] for call in destroy.call_args_list], [11, 13])


if __name__ == "__main__":
    unittest.main()
