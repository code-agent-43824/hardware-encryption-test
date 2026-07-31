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


if __name__ == "__main__":
    unittest.main()
