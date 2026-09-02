# sentinela_service.py
import os
import sys
import time
import json
import socket
import logging
import threading
import subprocess
from typing import Optional

# Configuração de encoding UTF-8 no Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "sentinel_daemon.log")
RUNTIME_FILE = os.path.join(BASE_DIR, "sentinel_runtime.json")

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] [SENTINEL-SERVICE] %(message)s'
)

from sentinel_api import app as flask_app, find_available_port, init_api
from sentinel_core.logger import SecurityEventLogger
from sentinel_core.crypto_vault import CryptoVault
from sentinel_core.threat_detector import ThreatDetector
from sentinel_core.auto_response import AutoResponseEngine
from sentinel_core.fim import FileIntegrityMonitor
from sentinel_core.process_monitor import ProcessMonitor
from sentinel_core.network_monitor import NetworkMonitor
from sentinel_core.ai_anomaly_detector import AIAnomalyDetector
from sentinel_core.honeypot import Honeypot
from sentinel_core.network_ids import NetworkIDS
from sentinel_core.active_shield import ActiveShield
from sentinel_core.honeyfiles import HoneyfileManager
from sentinel_core.threat_intel import GlobalThreatIntel
from sentinel_core.firewall_manager import OSFirewallManager
from sentinel_core.tarpit_engine import TarpitEngine
from sentinel_core.process_guard import EDRProcessGuard
from sentinel_core.kernel_monitor import SystemKernelMonitor
from sentinel_core.ip_geolocator import IPGeolocator
from sentinel_core.ztna_engine import ZTNACARTAEngine
from sentinel_core.identity_credential_guard import IdentityCredentialGuard
from sentinel_core.dlp_exfiltration_guard import DLPExfiltrationGuard
from sentinel_core.execution_anti_exploit_guard import ExecutionAntiExploitGuard
from sentinel_core.network_perimeter_guard import NetworkPerimeterGuard
from sentinel_core.posture_persistence_guard import PosturePersistenceGuard

class SentinelBackgroundDaemon:
    """Gerenciador do Ciclo de Vida do Serviço em Segundo Plano do Sentinela XDR."""

    def __init__(self):
        self.is_running = False
        self.api_thread = None
        self.monitor_thread = None
        self.port = 5000
        self._lock_socket = None
        self.honeypot = None
        self.nids = None
        self.tarpit_engine = None

    def acquire_single_instance_lock(self, port: int = 59998) -> bool:
        """Garante que apenas uma instância do serviço Sentinela rode por vez."""
        try:
            self._lock_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._lock_socket.bind(("127.0.0.1", port))
            return True
        except OSError:
            logging.warning("[SERVICE] Outra instância do Sentinela já está em execução na porta de trava.")
            return False

    def _save_runtime_state(self, status: str = "running"):
        """Salva metadados do processo ativo para consumo da bandeja e UI."""
        try:
            state = {
                "status": status,
                "port": self.port,
                "pid": os.getpid(),
                "timestamp": time.time(),
                "url": f"http://localhost:{self.port}"
            }
            with open(RUNTIME_FILE, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            logging.warning(f"[SERVICE] Falha ao salvar runtime state: {e}")

    def start_service(self, blocking: bool = True):
        if not self.acquire_single_instance_lock():
            print("[INFO] Sentinela já está rodando em segundo plano.")
            logging.info("[SERVICE] Instância já ativa. Finalizando inicialização duplicada.")
            return

        self.is_running = True
        logging.info("=" * 60)
        logging.info("INICIANDO SERVIÇO EM SEGUNDO PLANO SENTINEL XDR")
        logging.info("=" * 60)

        # 1. Inicializa Motores de Defesa
        db_path = os.path.join(BASE_DIR, "sentinel_events.db")
        logger = SecurityEventLogger(db_path=db_path)
        key_path = os.path.join(BASE_DIR, "sentinel.key")
        vault = CryptoVault(key_path=key_path)
        threat_detector = ThreatDetector(logger=logger)
        quarantine_dir = os.path.join(BASE_DIR, "quarantine")
        soar = AutoResponseEngine(logger=logger, vault=vault, quarantine_dir=quarantine_dir)
        active_shield = ActiveShield(logger=logger, threat_detector=threat_detector, soar=soar)
        
        fim = FileIntegrityMonitor(
            watch_paths=[BASE_DIR], 
            logger=logger, 
            threat_detector=threat_detector, 
            auto_response=soar,
            auto_isolate=True
        )
        proc_monitor = ProcessMonitor(logger=logger)
        net_monitor = NetworkMonitor(logger=logger)
        ai_detector = AIAnomalyDetector(logger=logger)
        try:
            ai_detector.train_baseline()
        except Exception as e:
            logging.warning(f"[AI BASELINE] Aviso no treinamento inicial: {e}")

        geolocator = IPGeolocator()
        firewall_mgr = OSFirewallManager(logger=logger)
        
        try:
            self.tarpit_engine = TarpitEngine(port=8888, logger=logger)
            self.tarpit_engine.start()
        except Exception as e:
            logging.warning(f"[TARPIT] Aviso ao iniciar tarpit: {e}")

        def on_threat(ip: str, attack_type: str, severity: str = "CRITICAL"):
            logger.log_event(severity, "CYBER_DEFENSE", attack_type, f"Ameaça detectada de {ip}. Contramedidas ativas.")
            try:
                geolocator.locate_ip(ip)
                firewall_mgr.block_ip(ip, reason=f"{attack_type} ({severity})")
            except Exception as ex:
                logging.error(f"[THREAT CALLBACK ERROR] {ex}")

        honeypot_dir = os.path.join(BASE_DIR, "honeypots")
        try:
            self.honeypot = Honeypot(logger=logger, honeypot_dir=honeypot_dir, alert_callback=on_threat)
            self.honeypot.start()
        except Exception as e:
            logging.warning(f"[HONEYPOT] Aviso ao iniciar honeypot: {e}")

        try:
            self.nids = NetworkIDS(logger=logger, alert_callback=on_threat)
            self.nids.start()
        except Exception as e:
            logging.warning(f"[NIDS] Aviso ao iniciar NIDS: {e}")

        honeyfiles = HoneyfileManager(base_dir=BASE_DIR, logger=logger, auto_response_engine=soar)
        try:
            honeyfiles.deploy_canaries()
        except Exception as e:
            logging.warning(f"[HONEYFILES] Aviso no deploy de canários: {e}")

        threat_intel = GlobalThreatIntel(logger=logger)
        try:
            threat_intel.sync_global_feeds()
        except Exception as e:
            logging.warning(f"[THREAT INTEL] Aviso no sync de feeds: {e}")

        edr_guard = EDRProcessGuard(logger=logger)
        kernel_monitor = SystemKernelMonitor(logger=logger)
        ztna_engine = ZTNACARTAEngine(logger_instance=logger)

        # Inicializa 5 Motores Soberanos Especializados
        identity_guard = IdentityCredentialGuard(logger=logger, soar=soar)
        dlp_guard = DLPExfiltrationGuard(logger=logger, soar=soar)
        anti_exploit_guard = ExecutionAntiExploitGuard(logger=logger, soar=soar)
        perimeter_guard = NetworkPerimeterGuard(logger=logger, soar=soar)
        posture_guard = PosturePersistenceGuard(logger=logger, soar=soar)

        # 2. Inicializa API Web
        self.port = find_available_port(5000)
        init_api(
            logger=logger,
            vault=vault,
            threat_detector=threat_detector,
            soar=soar,
            active_shield=active_shield,
            fim=fim,
            proc_monitor=proc_monitor,
            net_monitor=net_monitor,
            geolocator=geolocator,
            firewall=firewall_mgr,
            ai_detector=ai_detector,
            honeypot=self.honeypot,
            nids=self.nids,
            canary=honeyfiles,
            threat_intel=threat_intel,
            edr_guard=edr_guard,
            kernel_monitor=kernel_monitor,
            ztna_engine=ztna_engine,
            identity_guard=identity_guard,
            dlp_guard=dlp_guard,
            anti_exploit_guard=anti_exploit_guard,
            perimeter_guard=perimeter_guard,
            posture_guard=posture_guard
        )

        self._save_runtime_state("running")

        def run_api():
            werkzeug_logger = logging.getLogger('werkzeug')
            werkzeug_logger.setLevel(logging.ERROR)
            try:
                flask_app.run(host="0.0.0.0", port=self.port, debug=False, use_reloader=False)
            except Exception as e:
                logging.error(f"[SERVICE FLASK ERROR] {e}")

        self.api_thread = threading.Thread(target=run_api, daemon=True)
        self.api_thread.start()
        logging.info(f"[SERVICE] API e Dashboard prontos em http://localhost:{self.port} (20 Camadas Soberanas Ativas)")

        # 3. Loop contínuo de varreduras de segurança em segundo plano
        def run_defense_scans():
            logging.info("[SERVICE] Loop contínuo de varredura ativo (20 Camadas Ativas).")
            cycle = 0
            while self.is_running:
                cycle += 1
                try:
                    fim.scan()
                except Exception as e:
                    logging.debug(f"[FIM SCAN ERROR] {e}")
                try:
                    proc_monitor.scan_processes()
                except Exception as e:
                    logging.debug(f"[PROC SCAN ERROR] {e}")
                try:
                    net_monitor.scan_network_connections()
                except Exception as e:
                    logging.debug(f"[NET SCAN ERROR] {e}")
                try:
                    ai_detector.scan_anomalies()
                except Exception as e:
                    logging.debug(f"[AI SCAN ERROR] {e}")
                try:
                    honeyfiles.check_integrity()
                except Exception as e:
                    logging.debug(f"[HONEYFILES SCAN ERROR] {e}")
                try:
                    edr_guard.auto_remediate()
                except Exception as e:
                    logging.debug(f"[EDR AUTO-REMEDIATE ERROR] {e}")
                try:
                    kernel_monitor.inspect_system_integrity()
                except Exception as e:
                    logging.debug(f"[KERNEL SCAN ERROR] {e}")
                try:
                    ztna_engine.decay_risk_score()
                except Exception as e:
                    logging.debug(f"[ZTNA DECAY ERROR] {e}")

                # Varreduras periódicas dos motores de identidade, exploit, perímetro e postura
                if cycle % 3 == 0:
                    try:
                        identity_guard.scan_running_processes_and_cmdlines()
                        anti_exploit_guard.inspect_process_tree()
                    except Exception as e:
                        logging.debug(f"[IDENTITY/EXPLOIT SCAN ERROR] {e}")

                if cycle % 6 == 0:
                    try:
                        perimeter_guard.audit_arp_table()
                        posture_guard.scan_asep_registry_and_files()
                    except Exception as e:
                        logging.debug(f"[PERIMETER/POSTURE SCAN ERROR] {e}")

                time.sleep(5)

        self.monitor_thread = threading.Thread(target=run_defense_scans, daemon=True)
        self.monitor_thread.start()

        if blocking:
            try:
                while self.is_running:
                    time.sleep(2)
            except (KeyboardInterrupt, SystemExit):
                self.stop_service()

    def stop_service(self):
        self.is_running = False
        logging.info("[SERVICE] Encerrando Serviço do Sentinela...")
        self._save_runtime_state("stopped")
        
        if self.honeypot:
            try:
                self.honeypot.stop()
            except Exception:
                pass
        if self.nids:
            try:
                self.nids.stop()
            except Exception:
                pass
        if self._lock_socket:
            try:
                self._lock_socket.close()
            except Exception:
                pass

if __name__ == "__main__":
    daemon = SentinelBackgroundDaemon()
    daemon.start_service(blocking=True)
