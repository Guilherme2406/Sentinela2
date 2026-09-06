# test_cti_feeds.py
"""
Testes do Cyber Threat Intelligence com feeds reais + cache offline.

Valida:
  1. Reputação de rede interna (SAFE) e de IPs da seed (MALICIOUS).
  2. Ingestão de feeds a partir de payloads sintéticos (blocklist.de + URLhaus).
  3. Persistência de cache local e leitura em modo offline.
  4. Degradação graciosa quando os feeds estão indisponíveis (nunca levanta).

Executar:  python test_cti_feeds.py
"""
import os
import sys
import json
import tempfile
import unittest
import urllib.error

import sentinel_core.threat_intel as ti_mod
from sentinel_core.threat_intel import ThreatIntelFeed

json_file = tempfile.NamedTemporaryFile(suffix=".json", delete=False)


class FakeFeedResponder:
    """Simula a camada HTTP retornando conteúdo controlado."""

    BLOCKLIST_TEXT = (
        "1.2.3.4\n"
        "8.8.4.4\n"
        "10.0.0.5\n"          # privado — deve ser ignorado
        "not-an-ip\n"
        "2001:db8::1\n"       # documentação — não global
    )
    URLHAUS_CSV = (
        "#id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
        '1,2026-09-01,"http://5.6.7.8/payload.exe",online,2026-09-01,emotet,part1,url,rep\n'
        '2,2026-09-01,"http://evil.example.com/a",online,2026-09-01,emu,part2,url,rep\n'
    )

    def __init__(self, fail: bool = False):
        self.fail = fail

    def get(self, url: str, timeout: int = 20) -> str:
        if self.fail:
            raise urllib.error.URLError("offline simulado")
        if "blocklist.de" in url:
            return self.BLOCKLIST_TEXT
        if "urlhaus" in url:
            return self.URLHAUS_CSV
        raise ValueError(f"url inesperada: {url}")


class TestThreatIntelFeeds(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.original_http_get = ti_mod.ThreatIntelFeed._http_get

    def tearDown(self):
        # restaura o método HTTP original para não vazar mocks entre testes
        ti_mod.ThreatIntelFeed._http_get = self.original_http_get

    def _feed(self, fail=False):
        f = ThreatIntelFeed(cache_dir=self.tmpdir)
        responder = FakeFeedResponder(fail=fail)
        ti_mod.ThreatIntelFeed._http_get = lambda self, url, timeout=20: responder.get(url, timeout)
        return f, responder

    def test_01_reputation_internal_and_seed(self):
        f, _ = self._feed()
        # Rede interna -> SAFE
        rep = f.check_ip_reputation("192.168.1.10")
        self.assertEqual(rep["status"], "SAFE")
        # IP da seed -> MALICIOUS
        rep2 = f.check_ip_reputation("185.220.101.5")
        self.assertEqual(rep2["status"], "MALICIOUS")
        self.assertTrue(f.is_ip_blacklisted("185.220.101.5"))
        # IP desconhecido -> CLEAN
        self.assertFalse(f.is_ip_blacklisted("8.8.4.4"))

    def test_02_ingest_synthetic_feeds(self):
        f, _ = self._feed()
        total = f.sync_global_feeds()
        # 5 seeds + 1.2.3.4 + 203.0.113.10 + 5.6.7.8 = 8 (IPv6 doc/privados ignorados)
        self.assertGreaterEqual(total, 8)
        self.assertEqual(f.check_ip_reputation("1.2.3.4")["status"], "MALICIOUS")
        self.assertEqual(f.check_ip_reputation("5.6.7.8")["status"], "MALICIOUS")
        self.assertEqual(f.check_ip_reputation("10.0.0.5")["status"], "SAFE")
        self.assertEqual(f.check_ip_reputation("2001:db8::1")["status"], "CLEAN")

    def test_03_cache_persistence_offline(self):
        f, _ = self._feed()
        f.sync_global_feeds()
        self.assertGreater(len(f.known_malicious_ips), 5)
        self.assertTrue(os.path.exists(f.cache_path))

        # Nova instância em modo OFFLINE (http falha) carrega da cache
        offline, _ = self._feed(fail=True)
        self.assertGreaterEqual(len(offline.known_malicious_ips), len(f.known_malicious_ips))
        self.assertEqual(offline.check_ip_reputation("1.2.3.4")["status"], "MALICIOUS")
        # e sync não levanta exceção
        n = offline.sync_global_feeds()
        self.assertGreaterEqual(n, len(f.known_malicious_ips))

    def test_04_status_fields_preserved(self):
        f, _ = self._feed()
        status = f.get_status()
        self.assertIn("feeds_count", status)
        self.assertIn("threat_database", status)
        self.assertIn("malicious_samples", status)
        self.assertEqual(status["threat_database"], "CTI_LIVE_FEEDS_AND_LOCAL_CACHE")


if __name__ == "__main__":
    unittest.main(verbosity=2)