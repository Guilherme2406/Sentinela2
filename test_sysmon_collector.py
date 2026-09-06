# test_sysmon_collector.py
"""
Testes do coletor de telemetria Sysmon (funcionam em qualquer plataforma,
sem exigir o Sysmon instalado):

  1. Parsing de XML bruto do Event Log (EventRecordID + TimeCreated + EventData).
  2. Normalização e correlação dos Event IDs 1, 8, 10 (LSASS), 13 (autorun), 22 (DNS).
  3. Deduplicação por EventRecordID.
  4. Status estendido.
  5. Config hardened do Sysmon é XML bem-formado.

Executar:  python test_sysmon_collector.py
"""
import os
import sys
import unittest
import xml.etree.ElementTree as ET

from sentinel_core.sysmon_collector import SysmonCollector, INTERESTING_EVENT_IDS

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "configs", "sysmon", "sysmon-config-hardened.xml")

SAMPLE_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"/>
    <EventID>1</EventID>
    <Version>5</Version>
    <Level>4</Level>
    <EventRecordID>110001</EventRecordID>
    <TimeCreated SystemTime="2026-09-05T12:34:56.123Z"/>
  </System>
  <EventData>
    <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
    <Data Name="CommandLine">cmd.exe /c whoami</Data>
    <Data Name="User">DOMAIN\\user</Data>
    <Data Name="Hashes">SHA256=abc123</Data>
  </EventData>
</Event>"""


class TestSysmonCollector(unittest.TestCase):

    def setUp(self):
        self.collector = SysmonCollector(logger_instance=None, sigma_engine=None)

    def test_01_parse_xml_basic(self):
        parsed = self.collector._parse_sysmon_xml(SAMPLE_XML)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["EventID"], "1")
        self.assertEqual(parsed["RecordID"], "110001")
        self.assertIn("TimeCreated", parsed)
        self.assertEqual(parsed["Image"], "C:\\Windows\\System32\\cmd.exe")

    def test_02_normalize_event_id_1(self):
        parsed = self.collector.process_raw_event({
            "EventID": 1,
            "Image": "C:\\Windows\\System32\\notepad.exe",
            "CommandLine": "notepad.exe report.txt",
        })
        self.assertEqual(parsed["event_id"], 1)
        self.assertEqual(parsed["image"], "C:\\Windows\\System32\\notepad.exe")
        self.assertEqual(parsed["source"], "SYSMON")
        self.assertEqual(self.collector.events_collected_count, 1)

    def test_03_correlation_injection_and_lsass(self):
        inj = self.collector.process_raw_event({
            "EventID": 8,
            "SourceImage": "C:\\Temp\\evil.exe",
            "TargetImage": "C:\\Windows\\System32\\explorer.exe",
        })
        self.assertEqual(inj["event_id"], 8)

        lsass = self.collector.process_raw_event({
            "EventID": 10,
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "SourceImage": "C:\\temp\\dump.exe",
        })
        self.assertEqual(lsass["event_id"], 10)

    def test_04_correlation_registry_autorun(self):
        ev = self.collector.process_raw_event({
            "EventID": 13,
            "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor",
        })
        self.assertEqual(ev["event_id"], 13)
        self.assertTrue(ev["target_object"].lower().startswith("hklm"))

    def test_05_correlation_dns_suspicious_tld(self):
        ev = self.collector.process_raw_event({
            "EventID": 22,
            "QueryName": "update.payload-cdn.top",
        })
        self.assertEqual(ev["query_name"], "update.payload-cdn.top")

    def test_06_deduplication_by_record_id(self):
        first = self.collector.process_raw_event({"EventID": 1, "RecordID": 9999, "Image": "a.exe"})
        self.assertFalse(first.get("duplicate", False))
        dup = self.collector.process_raw_event({"EventID": 1, "RecordID": 9999, "Image": "a.exe"})
        self.assertTrue(dup.get("duplicate", False))
        # Contagem não duplica
        self.assertEqual(self.collector.events_collected_count, 1)

    def test_07_status_extended_fields(self):
        status = self.collector.get_status()
        self.assertIn("polling_active", status)
        self.assertIn("listening_event_ids", status)
        self.assertIn("event_id_counts", status)
        self.assertIn(1, status["listening_event_ids"])

    def test_08_interesting_event_ids_surface(self):
        self.assertIn(1, INTERESTING_EVENT_IDS)
        self.assertIn(8, INTERESTING_EVENT_IDS)
        self.assertIn(10, INTERESTING_EVENT_IDS)
        self.assertIn(13, INTERESTING_EVENT_IDS)
        self.assertIn(22, INTERESTING_EVENT_IDS)

    def test_09_hardened_config_xml_is_well_formed(self):
        self.assertTrue(os.path.exists(CONFIG_PATH), "config hardened do Sysmon não encontrado")
        ET.parse(CONFIG_PATH)  # levanta se XML for malformado

    def test_10_poll_returns_empty_without_sysmon(self):
        # Ambiente sem Sysmon: poll deve retornar lista vazia, sem exceções.
        self.collector.sysmon_available = False
        self.assertEqual(self.collector.poll_events(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)