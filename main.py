# main.py
import os
import sys
import time
import logging
import threading
import webbrowser

# Ensure UTF-8 output on Windows consoles to prevent UnicodeEncodeError with emojis
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
from sentinel_core.process_monitor import ProcessMonitor
from sentinel_core.network_monitor import NetworkMonitor

# Subsistemas Next-Gen (IA, Honeypot, NIDS, Active Shield, Honeyfiles, CTI & Firewall)
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
from sentinel_core.identity_credential_guard import IdentityCredentialGuard
from sentinel_core.dlp_exfiltration_guard import DLPExfiltrationGuard
from sentinel_core.execution_anti_exploit_guard import ExecutionAntiExploitGuard
from sentinel_core.network_perimeter_guard import NetworkPerimeterGuard
from sentinel_core.posture_persistence_guard import PosturePersistenceGuard

from sentinel_api import app as flask_app, find_available_port, init_api

def feed_monitoring_metrics():
    """Alimenta o Functions Engine com telemetria do host e dos 20 motores de segurança."""
    try:
        from sentinel_api import telemetry_collector_instance, functions_storage_instance
        if telemetry_collector_instance:
            telemetry_collector_instance.feed_storage(functions_storage_instance)
    except Exception:
        pass

# Configuração visual de logs do Main
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] [SENTINEL-MAIN] %(message)s'
)

# Cronômetro da inicialização — evidencia no console quanto tempo cada etapa levou
_INIT_T0 = time.perf_counter()
_INIT_LAST = [_INIT_T0]

def _mark(label: str):
    now = time.perf_counter()
    logging.info(f"[INIT-TIMING] {label} | total {now - _INIT_T0:.2f}s | etapa {now - _INIT_LAST[0]:.2f}s")
    _INIT_LAST[0] = now

def start_api_server(port=5000):
    """Inicia o servidor Flask em thread separada com logs controlados."""
    try:
        # Suprime logs excessivos de requisições GET periódicas do Werkzeug
        werkzeug_logger = logging.getLogger('werkzeug')
        werkzeug_logger.setLevel(logging.ERROR)
        flask_app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
    except Exception as e:
        logging.error(f"[API SERVER ERROR] {e}")

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))

    logging.info("=" * 65)
    logging.info("🛡️   SENTINELA SECURITY ENGINE (XDR / SIEM / SOAR NEXT-GEN)   🛡️")
    logging.info("=" * 65)

    # 1. Inicializa o Logger SQLite
    db_name = os.path.join(base_dir, "sentinel_events.db")
    logger = SecurityEventLogger(db_name)
    logger.log_event("INFO", "SYSTEM", "ENGINE", "Sentinela Core XDR/SIEM/SOAR Next-Gen iniciado com sucesso.")
    logging.info(f"[+] Banco de dados de auditoria pronto: '{db_name}'")

    # 1.5 DASHBOARD ONLINE ANTECIPADO — o painel web sobe em segundos enquanto
    # os motores ainda estão carregando; as instâncias reais são injetadas depois.
    init_api(logger=logger)
    requested_port = int(os.environ.get("PORT", 5000))
    port = find_available_port(requested_port)
    if port != requested_port:
        logging.warning(f"[!] Porta {requested_port} ocupada. Utilizando porta alternativa: {port}")

    api_thread = threading.Thread(target=start_api_server, args=(port,), daemon=True, name="SentinelAPI")
    api_thread.start()
    _mark("API & Dashboard online")
    logging.info(f"[+] Dashboard Web & API ONLINE em: http://localhost:{port} (motores em carga...)")

    feed_monitoring_metrics()  # Primeira amostra para o Functions Engine

    # Abre o navegador automaticamente após 1.2 segundos
    def open_browser():
        time.sleep(1.2)
        try:
            webbrowser.open(f"http://localhost:{port}")
        except Exception:
            pass
    threading.Thread(target=open_browser, daemon=True).start()

    # 2. Inicializa o Cofre Criptográfico
    key_path = os.path.join(base_dir, "sentinel.key")
    vault = CryptoVault(key_path)
    logging.info(f"[+] Cofre Criptográfico AES-256 inicializado.")

    # 3. Inicializa o Detector de Ameaças & IOCs
    threat_detector = ThreatDetector(logger=logger)
    logging.info(f"[+] Motor de Detecção de Ameaças (IOC / Hashes) ativo.")

    # 4. Inicializa o Motor de Resposta Automática (SOAR)
    quarantine_dir = os.path.join(base_dir, "quarantine")
    soar = AutoResponseEngine(logger=logger, vault=vault, quarantine_dir=quarantine_dir)
    logging.info(f"[+] Motor de Resposta Automática (SOAR & Quarentena) ativo em '{quarantine_dir}'.")

    # 5. Inicializa o Escudo Ativo de Proteção Avançada (Active Shield & DLP)
    active_shield = ActiveShield(logger=logger, threat_detector=threat_detector, soar=soar)
    logging.info(f"[+] Rede de Proteção Avançada (Active Shield - Inbound & Outbound DLP) ativa.")

    # 6. Configura o Monitor de Integridade de Arquivos (FIM)
    watch_dirs = [base_dir]
    logging.info(f"[+] Indexando baseline do FIM no diretório: {base_dir}")
    fim = FileIntegrityMonitor(
        watch_paths=watch_dirs, 
        logger=logger, 
        threat_detector=threat_detector, 
        auto_response=soar,
        auto_isolate=True
    )
    _mark("FIM baseline indexado")

    # 7. Inicializa o Monitor de Processos
    proc_monitor = ProcessMonitor(logger=logger)
    logging.info("[+] Monitor de Processos e Memória ativo.")

    # 8. Inicializa o Monitor de Rede
    net_monitor = NetworkMonitor(logger=logger)
    logging.info("[+] Monitor de Redes e Conexões Suspeitas ativo.")

    # 9. Inicializa o Motor de IA (Isolation Forest - Detecção Zero-Day)
    ai_detector = AIAnomalyDetector(logger=logger)
    logging.info("[+] Motor de IA (Isolation Forest Zero-Day) ativado. Treinando baseline...")
    ai_detector.train_baseline()
    _mark("Baseline de IA treinada")

    # 10. Inicializa Geolocalizador, Tarpit e Firewall de Sistema
    geolocator = IPGeolocator()
    firewall_mgr = OSFirewallManager(logger=logger)
    tarpit_engine = TarpitEngine(port=8888, logger=logger)
    tarpit_engine.start()
    logging.info("[+] Gerenciador de Firewall de Sistema (Kernel OS) e Tarpit ativos.")
    _mark("Firewall & Tarpit ativos")

    def on_threat_detected(ip: str, attack_type: str, severity: str = "CRITICAL"):
        """Reação autônoma de defesa ativa do Sentinela Main."""
        logger.log_event(severity, "CYBER_DEFENSE", attack_type, f"Ameaça detectada de {ip}. Executando contramedidas ativas.")
        geolocator.locate_ip(ip)
        if "BRUTE_FORCE" in attack_type or "PORT_SCAN" in attack_type:
            logging.info(f"[TARPIT] Redirecionando {ip} para contenção no Tarpit.")
        firewall_mgr.block_ip(ip, reason=f"{attack_type} ({severity})")

    # 11. Inicializa a Decepção Ativa & Honeypots
    honeypot_dir = os.path.join(base_dir, "honeypots")
    honeypot = Honeypot(logger=logger, honeypot_dir=honeypot_dir, alert_callback=on_threat_detected)
    honeypot.start()
    logging.info(f"[+] Decepção Ativa & Honeypots iniciados em '{honeypot_dir}'.")

    # 12. Inicializa o Radar NIDS (Network Intrusion Detection System)
    nids = NetworkIDS(logger=logger, alert_callback=on_threat_detected)
    nids.start()
    logging.info("[+] Radar NIDS (Detecção de Intrusão em Rede) ativo.")
    _mark("Honeypots & NIDS ativos")

    # 13. Inicializa Arquivos Canário (Honeyfiles) & Decepção DLP
    honeyfiles = HoneyfileManager(base_dir=base_dir, logger=logger, auto_response_engine=soar)
    honeyfiles.deploy_canaries()
    logging.info("[+] Arquivos Canário (Honeyfiles) e Armadilhas DLP armadas.")

    # 14. Sincroniza Inteligência Global de Ameaças (CTI)
    threat_intel = GlobalThreatIntel(logger=logger)
    threat_intel.sync_global_feeds()
    _mark("Feed CTI sincronizado")

    # 15. Inicializa o Guardião EDR e o Monitor de Kernel
    edr_guard = EDRProcessGuard(logger=logger)
    kernel_monitor = SystemKernelMonitor(logger=logger)
    logging.info("[+] EDR Process Guard e Monitor de Kernel ativos.")

    # 15.1. Inicializa Motores Soberanos Especializados (Identidade, DLP, Anti-Exploit, Rede e Postura)
    identity_guard = IdentityCredentialGuard(logger=logger, soar=soar)
    dlp_guard = DLPExfiltrationGuard(logger=logger, soar=soar)
    anti_exploit_guard = ExecutionAntiExploitGuard(logger=logger, soar=soar)
    perimeter_guard = NetworkPerimeterGuard(logger=logger, soar=soar)
    posture_guard = PosturePersistenceGuard(logger=logger, soar=soar)
    logging.info("[+] 20 Camadas Soberanas ativadas (LSASS Armor, DLP, Anti-Exploit, Perímetro DGA & Postura ASEP).")

    # 16. Injeta dependências na API Flask
    init_api(
        logger=logger, 
        active_shield=active_shield, 
        soar=soar, 
        threat_detector=threat_detector, 
        fim=fim, 
        proc_monitor=proc_monitor, 
        net_monitor=net_monitor, 
        geolocator=geolocator,
        firewall=firewall_mgr,
        honeypot=honeypot,
        nids=nids,
        threat_intel=threat_intel,
        edr_guard=edr_guard,
        kernel_monitor=kernel_monitor,
        identity_guard=identity_guard,
        dlp_guard=dlp_guard,
        anti_exploit_guard=anti_exploit_guard,
        perimeter_guard=perimeter_guard,
        posture_guard=posture_guard
    )

    # 17. Banner final (a API já foi iniciada antecipadamente no passo 1.5)
    _mark("Todos os 20 motores carregados e injetados na API")

    logging.info("\n" + "=" * 65)
    logging.info("🟢 SENTINELA ENGINE & DASHBOARD EM EXECUÇÃO CONTÍNUA")
    logging.info(f"🌐 Acesse o Painel Web: http://localhost:{port}")
    logging.info("💻 Para o Painel CLI interativo: abra outro terminal e digite 'python sentinel_cli.py'")
    logging.info("🛑 Pressione Ctrl+C para encerrar")
    logging.info("=" * 65 + "\n")

    scan_count = 0
    try:
        while True:
            scan_count += 1
            
            # Varreduras síncronas periódicas
            fim.scan()
            proc_monitor.scan_processes()
            net_monitor.scan_network_connections()
            feed_monitoring_metrics()  # Alimenta o Functions Engine com métricas reais do host
            ai_detector.scan_anomalies()  # Análise comportamental contínua com IA
            honeyfiles.check_integrity()  # Monitoramento de armadilhas canário
            edr_guard.auto_remediate()    # Neutralização EDR de comandos suspeitos
            kernel_monitor.inspect_system_integrity() # Integridade de arquivos críticos

            # Varreduras periódicas das novas camadas soberanas
            if scan_count % 3 == 0:
                try:
                    identity_guard.scan_running_processes_and_cmdlines()
                    anti_exploit_guard.inspect_process_tree()
                except Exception as ex:
                    logging.debug(f"[GUARD SCAN ERROR] {ex}")

            if scan_count % 6 == 0:
                try:
                    perimeter_guard.audit_arp_table()
                    posture_guard.scan_asep_registry_and_files()
                except Exception as ex:
                    logging.debug(f"[POSTURE/PERIMETER SCAN ERROR] {ex}")

            # Feedback no console a cada 6 varreduras (~30s)
            if scan_count % 6 == 0:
                logging.info(f"[STATUS] Sentinela operando normalmente (20 Camadas Ativas). Varredura #{scan_count} concluída.")

            time.sleep(5)

    except KeyboardInterrupt:
        logging.info("\n" + "=" * 65)
        logging.info("🛑 ENCERRAMENTO SOLICITADO PELO USUÁRIO")
        
        # Para threads de fundo de forma limpa
        logging.info("[*] Encerrando escutadores Honeypot e NIDS...")
        honeypot.stop()
        nids.stop()
        
        logger.log_event("INFO", "SYSTEM", "ENGINE", "Sentinela Core desligado.")
        logging.info("Sentinela finalizado com total segurança.")
        logging.info("=" * 65)
        sys.exit(0)

if __name__ == "__main__":
    main()
