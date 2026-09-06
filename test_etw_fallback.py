# test_etw_fallback.py
import unittest
from sentinel_core.etw_live_consumer import ETWLiveConsumer
from sentinel_core.native_etw_sensor import NativeETWSensor


class TestETWFallbackAndStatus(unittest.TestCase):

    def test_etw_live_consumer_status_schema(self):
        consumer = ETWLiveConsumer()
        st = consumer.get_status()
        self.assertIn("telemetry_mode", st)
        self.assertIn("privilege_status", st)
        self.assertIn("is_degraded", st)
        self.assertIn("fallback_reasons", st)
        self.assertIn("fallback_channels", st)
        self.assertIn(st["telemetry_mode"], ["KERNEL_RING0_ETW", "USERSPACE_EVENTLOG_FALLBACK"])
        self.assertIn(st["privilege_status"], ["ELEVATED_ADMIN", "STANDARD_USER"])

    def test_native_etw_sensor_status_enrichment(self):
        sensor = NativeETWSensor()
        st = sensor.get_status()
        self.assertIn("telemetry_mode", st)
        self.assertIn("privilege_status", st)
        self.assertIn("is_degraded", st)
        self.assertIn("consumer_details", st)

    def test_graceful_degradation_ingestion(self):
        sensor = NativeETWSensor()
        # Ingestão de evento benigno
        res_benign = sensor.ingest_kernel_event(
            provider_name="Microsoft-Windows-Kernel-Process",
            event_type="ProcessStart",
            pid=4000,
            details={"image_name": "notepad.exe", "parent_image": "explorer.exe"}
        )
        self.assertFalse(res_benign["is_suspicious"])

        # Ingestão de evento suspeito (Office gerando cmd)
        res_threat = sensor.ingest_kernel_event(
            provider_name="Microsoft-Windows-Kernel-Process",
            event_type="ProcessStart",
            pid=4001,
            details={"image_name": "cmd.exe", "parent_image": "winword.exe", "parent_pid": 1200}
        )
        self.assertTrue(res_threat["is_suspicious"])
        self.assertIn("Office", res_threat["reason"])


if __name__ == "__main__":
    unittest.main()
