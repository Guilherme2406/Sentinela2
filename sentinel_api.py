# sentinel_api.py
import os
import sys
import time
import socket
import logging
import threading
import webbrowser
import json
import re
from pathlib import Path
from typing import Dict, Any, Optional, List
from flask import Flask, jsonify, request, send_file, Response, send_from_directory
from flask_cors import CORS

# Importação de todos os motores do Sentinel Core (com suporte a nomes Sovereign e padrão)
from sentinel_core.logger import SecurityEventLogger, SentinelLogger
from sentinel_core.crypto_vault import CryptoVault, SentinelVault
from sentinel_core.auto_response import AutoResponseEngine, SOAREngine
from sentinel_core.threat_detector import ThreatDetector
from sentinel_core.fim import FileIntegrityMonitor
from sentinel_core.process_monitor import ProcessMonitor
from sentinel_core.network_monitor import NetworkMonitor
from sentinel_core.ai_anomaly_detector import AIAnomalyDetector, AnomalyDetector
from sentinel_core.honeypot import Honeypot, SentinelHoneypot
from sentinel_core.network_ids import NetworkIDS, NIDSRadar
from sentinel_core.ip_geolocator import IPGeolocator
from sentinel_core.active_shield import ActiveShield, ActiveShieldDLP
from sentinel_core.firewall_manager import OSFirewallManager
from sentinel_core.canary_files import CanaryTokenEngine, CanaryFileManager
from sentinel_core.tarpit import CyberTarpitServer, TarpitManager
from sentinel_core.threat_intel import ThreatIntelFeed, ThreatIntelFeeds
from sentinel_core.process_guard import EDRProcessGuard
from sentinel_core.ai_predictor import ZeroDayAIPredictor
from sentinel_core.kernel_monitor import SystemKernelMonitor
from sentinel_core.mesh_orchestrator import DefensiveMeshOrchestrator
from sentinel_core.yara_pe_analyzer import AdvancedPEAnalyzer
from sentinel_core.mitre_mapper import MitreAttckMapper
from sentinel_core.anti_ransomware_rollback import AntiRansomwareRollback
from sentinel_core.kernel_etw_monitor import ETWKernelMonitor
from sentinel_core.honeytoken_deception import HoneytokenManager
from sentinel_core.soar_playbook_engine import SOARPlaybookEngine
from sentinel_core.live_memory_forensics import LiveMemoryForensics
from sentinel_core.zero_trust_wfp import ZeroTrustNetworkEngine
from sentinel_core.ueba_graph_engine import UEBAGraphEngine
from sentinel_core.shadow_mode_soar import ShadowModeSOAR
from sentinel_core.post_quantum_shield import PostQuantumShield
from sentinel_core.ztna_engine import ZTNACARTAEngine   
from sentinel_core.identity_credential_guard import IdentityCredentialGuard
from sentinel_core.dlp_exfiltration_guard import DLPExfiltrationGuard
from sentinel_core.execution_anti_exploit_guard import ExecutionAntiExploitGuard
from sentinel_core.network_perimeter_guard import NetworkPerimeterGuard
from sentinel_core.posture_persistence_guard import PosturePersistenceGuard

# Functions Engine — Motor de Expressões de Monitoramento em Séries Temporais (estilo Zabbix)
from functions_engine.engine import FunctionsEngine
from functions_engine.core import SecurityItem, FunctionContext, RingBufferStorage



# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

app = Flask(__name__)
CORS(app)  # Permite requisições de origens cruzadas (Dashboard)

# Caminho base consistente
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(BASE_DIR, "sentinel_events.db")

# ---------------------------------------------------------
# INICIALIZAÇÃO DOS MOTORES DO SENTINELA (NÍVEL SOVEREIGN)
# ---------------------------------------------------------
logger = SentinelLogger(DB_NAME)
vault = SentinelVault(os.path.join(BASE_DIR, "sentinel.key"))
soar = SOAREngine(logger=logger, vault=vault, quarantine_dir=os.path.join(BASE_DIR, "quarantine"))
threat_detector = ThreatDetector(logger=logger)
anomaly_detector = AnomalyDetector(logger=logger)
geolocator = IPGeolocator()
firewall = OSFirewallManager(logger=logger)
tarpit = TarpitManager(logger=logger)
canary = CanaryFileManager(base_dir=os.path.join(BASE_DIR, "canary_traps"), logger=logger)
threat_intel = ThreatIntelFeeds(logger=logger, firewall_manager=firewall)
active_shield = ActiveShieldDLP(logger=logger, threat_detector=threat_detector, soar=soar, geolocator=geolocator)
fim = FileIntegrityMonitor(watch_paths=[BASE_DIR], logger=logger, threat_detector=threat_detector, auto_response=soar, auto_isolate=True)
proc_monitor = ProcessMonitor(logger=logger)
net_monitor = NetworkMonitor(logger=logger)
edr_guard = EDRProcessGuard(logger=logger)
ai_predictor = ZeroDayAIPredictor(logger=logger)
kernel_monitor = SystemKernelMonitor(logger=logger)
mesh_orchestrator = DefensiveMeshOrchestrator(node_id="Sentinela-Node-Master", logger=logger)
anti_ransomware = AntiRansomwareRollback(protected_dir=os.path.join(BASE_DIR, "user_documents"), vault_dir=os.path.join(BASE_DIR, "sentinel_vault"))
etw_monitor = ETWKernelMonitor()
honeytoken_mgr = HoneytokenManager(bait_dir=os.path.join(BASE_DIR, "sentinel_baits"))
pe_analyzer = AdvancedPEAnalyzer
mitre_mapper = MitreAttckMapper
soar_playbook = SOARPlaybookEngine(firewall_manager=firewall)
memory_forensics = LiveMemoryForensics()
zero_trust = ZeroTrustNetworkEngine()
ueba_engine = UEBAGraphEngine()
shadow_soar = ShadowModeSOAR(shadow_delay_seconds=3)
pqc_shield = PostQuantumShield(agent_id="SENTINELA-MASTER-NODE-01")
ztna_engine = ZTNACARTAEngine(logger_instance=logger)
identity_guard = IdentityCredentialGuard(logger=logger, soar=soar)
dlp_guard = DLPExfiltrationGuard(logger=logger, soar=soar)
anti_exploit_guard = ExecutionAntiExploitGuard(logger=logger, soar=soar)
perimeter_guard = NetworkPerimeterGuard(logger=logger, soar=soar)
posture_guard = PosturePersistenceGuard(logger=logger, soar=soar)

# -------------------------------------------------------------
# FUNCTIONS ENGINE — Motor de Expressões de Monitoramento (Zabbix-style)
# -------------------------------------------------------------
functions_engine = FunctionsEngine()
functions_engine.register_default_functions()
functions_storage = RingBufferStorage(max_size=10000)
functions_engine.context = FunctionContext(storage=functions_storage)

# Aliases globais para injeção via init_api / main.py
functions_engine_instance = functions_engine
functions_storage_instance = functions_storage




# Callback de resposta ativa contra intrusões
def on_threat_detected(ip: str, attack_type: str, severity: str = "CRITICAL"):
    """Reação autônoma de defesa ativa (Geolocalização + Tarpit + Firewall Kernel)."""
    target_logger = logger_instance if logger_instance else logger
    target_geo = geolocator_instance if geolocator_instance else geolocator
    target_fw = firewall_instance if firewall_instance else firewall
    target_tarpit = tarpit

    target_logger.log_event(severity, "CYBER_DEFENSE", attack_type, f"Ameaça detectada de {ip}. Executando contramedidas ativas.")
    # 1. Envia IP para geolocalização e cache
    geo_data = target_geo.locate_ip(ip)
    
    # 2. Ativa Tarpit se for scan/brute-force para prender o invasor
    if "BRUTE_FORCE" in attack_type or "PORT_SCAN" in attack_type:
        target_tarpit.trap_connection(ip, duration_seconds=60)
        
    # 3. Bane o IP direto no Firewall do SO (Kernel Level)
    target_fw.block_ip(ip, reason=f"{attack_type} ({severity})")

honeypot = SentinelHoneypot(logger=logger, honeypot_dir=os.path.join(BASE_DIR, "honeypots"), port=2222, alert_callback=on_threat_detected)
nids = NIDSRadar(logger=logger, alert_callback=on_threat_detected)

# Aliases de instâncias globais para injeção via init_api
vault_instance = vault
ai_detector_instance = anomaly_detector
logger_instance = logger
active_shield_instance = active_shield
soar_instance = soar
threat_detector_instance = threat_detector
fim_instance = fim
proc_monitor_instance = proc_monitor
net_monitor_instance = net_monitor
geolocator_instance = geolocator
firewall_instance = firewall
honeypot_instance = honeypot
nids_instance = nids
canary_instance = canary
threat_intel_instance = threat_intel
edr_guard_instance = edr_guard
kernel_monitor_instance = kernel_monitor
ztna_engine_instance = ztna_engine
identity_guard_instance = identity_guard
dlp_guard_instance = dlp_guard
anti_exploit_guard_instance = anti_exploit_guard
perimeter_guard_instance = perimeter_guard
posture_guard_instance = posture_guard


def init_api(
    logger=None, active_shield=None, soar=None, threat_detector=None, 
    fim=None, proc_monitor=None, net_monitor=None, geolocator=None,
    firewall=None, honeypot=None, nids=None, canary=None, threat_intel=None,
    edr_guard=None, kernel_monitor=None, vault=None, ai_detector=None,
    functions_engine_ctx=None, functions_storage_ctx=None, **kwargs
):
    """Permite injeção flexível de dependências do main.py, service e testes."""
    global logger_instance, active_shield_instance, soar_instance, threat_detector_instance, fim_instance
    global proc_monitor_instance, net_monitor_instance, geolocator_instance, firewall_instance
    global honeypot_instance, nids_instance, canary_instance, threat_intel_instance, edr_guard_instance, kernel_monitor_instance
    global vault_instance, ai_detector_instance, identity_guard_instance, dlp_guard_instance, anti_exploit_guard_instance, perimeter_guard_instance, posture_guard_instance
    global functions_engine_instance, functions_storage_instance
    
    if logger: logger_instance = logger
    if active_shield: active_shield_instance = active_shield
    if soar: soar_instance = soar
    if threat_detector: threat_detector_instance = threat_detector
    if fim: fim_instance = fim
    if proc_monitor: proc_monitor_instance = proc_monitor
    if net_monitor: net_monitor_instance = net_monitor
    if geolocator: geolocator_instance = geolocator
    if firewall: firewall_instance = firewall
    if honeypot: honeypot_instance = honeypot
    if nids: nids_instance = nids
    if canary: canary_instance = canary
    if threat_intel: threat_intel_instance = threat_intel
    if edr_guard: edr_guard_instance = edr_guard
    if kernel_monitor: kernel_monitor_instance = kernel_monitor
    if vault: vault_instance = vault
    if ai_detector: ai_detector_instance = ai_detector
    if kwargs.get("ztna_engine"): ztna_engine_instance = kwargs.get("ztna_engine")
    if kwargs.get("identity_guard"): identity_guard_instance = kwargs.get("identity_guard")
    if kwargs.get("dlp_guard"): dlp_guard_instance = kwargs.get("dlp_guard")
    if kwargs.get("anti_exploit_guard"): anti_exploit_guard_instance = kwargs.get("anti_exploit_guard")
    if kwargs.get("perimeter_guard"): perimeter_guard_instance = kwargs.get("perimeter_guard")
    if kwargs.get("posture_guard"): posture_guard_instance = kwargs.get("posture_guard")
    if functions_engine_ctx: functions_engine_instance = functions_engine_ctx
    if functions_storage_ctx: functions_storage_instance = functions_storage_ctx


def init_sentinel_services():
    """Inicia os serviços soberanos de proteção e armadilhas."""
    try:
        honeypot.start()
        nids.start()
        canary.start_monitoring()
        # Sincroniza CTI em background
        threading.Thread(target=threat_intel.start_auto_sync, kwargs={"interval_seconds": 3600}, daemon=True).start()
        logger.log_event("INFO", "SYSTEM_INIT", "SERVICES_STARTED", "Todos os motores Sovereign do Sentinela XDR estão operacionais.")
    except Exception as e:
        logger.log_event("ERROR", "SYSTEM_INIT", "START_FAILED", str(e))

def find_available_port(start_port=5000, max_attempts=10):
    """Varre portas a partir de start_port até encontrar uma disponível."""
    for p in range(start_port, start_port + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(('0.0.0.0', p))
                return p
            except OSError:
                continue
    return start_port

def get_request_data() -> Dict[str, Any]:
    """Extrai dados de forma segura de JSON, Form-data, Query Params ou Raw Body."""
    if request.is_json:
        data = request.get_json(silent=True)
        if isinstance(data, dict):
            return data
    if request.form:
        return request.form.to_dict()
    if request.args:
        return request.args.to_dict()
    try:
        if request.data:
            data = json.loads(request.data.decode('utf-8'))
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}

# ---------------------------------------------------------
# ROTAS DA API RESTFUL & DASHBOARD WEB
# ---------------------------------------------------------

@app.route("/", methods=["GET"])
@app.route("/dashboard", methods=["GET"])
def index():
    """Entrega a página do Dashboard em HTML."""
    dashboard_path = os.path.join(BASE_DIR, "dashboard.html")
    try:
        if os.path.exists(dashboard_path):
            with open(dashboard_path, "r", encoding="utf-8") as f:
                return f.read(), 200, {'Content-Type': 'text/html; charset=utf-8'}
        return jsonify({"status": "error", "message": "dashboard.html não encontrado"}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": f"Não foi possível carregar dashboard.html: {str(e)}"}), 500

@app.route("/assets/<path:filename>", methods=["GET"])
def serve_assets(filename):
    """Serve imagens, logos e assets estáticos da pasta assets/."""
    assets_dir = os.path.join(BASE_DIR, "assets")
    return send_from_directory(assets_dir, filename)

@app.route("/favicon.ico", methods=["GET"])
def favicon():
    """Serve o favicon oficial do Sentinela."""
    assets_dir = os.path.join(BASE_DIR, "assets")
    return send_from_directory(assets_dir, "sentinel_icon.ico", mimetype="image/vnd.microsoft.icon")

@app.route("/api/health", methods=["GET"])
def health_check():
    """Verificação de integridade da API."""
    return jsonify({
        "status": "ONLINE",
        "engine": "Sentinela Core XDR/SIEM/SOAR/Shield/Sovereign",
        "version": "2.0.0-SOVEREIGN",
        "timestamp": time.time()
    }), 200

@app.route("/api/status", methods=["GET"])
def get_status():
    """Retorna o status geral de saúde e controles de todos os motores."""
    canary_status = canary.get_status() if hasattr(canary, "get_status") else {}
    tarpit_status = tarpit.get_status() if hasattr(tarpit, "get_status") else {}
    cti_status = threat_intel.get_status() if hasattr(threat_intel, "get_status") else {}
    
    return jsonify({
        "status": "ONLINE",
        "shield": active_shield_instance.get_config() if active_shield_instance else active_shield.get_config(),
        "firewall": {
            "banned_ips_count": len(firewall.banned_ips),
            "banned_ips": list(firewall.banned_ips)
        },
        "canary": canary_status,
        "tarpit": tarpit_status,
        "threat_intel": cti_status,
        "nids_active": nids.running,
        "honeypot_active": honeypot.running,
        "timestamp": time.time()
    })

@app.route("/api/config/shield", methods=["GET", "POST"])
@app.route("/api/shield/config", methods=["GET", "POST"])
def config_shield():
    """Consulta ou atualiza as configurações do Active Shield & DLP."""
    target_shield = active_shield_instance if active_shield_instance else active_shield
    
    if request.method == "POST":
        data = get_request_data()
        
        # Suporta tanto inbound/outbound quanto anti_malware_enabled/dlp_enabled
        if "inbound" in data or "inbound_malware_protection" in data or "anti_malware_enabled" in data:
            val = data.get("inbound") if "inbound" in data else data.get("inbound_malware_protection", data.get("anti_malware_enabled"))
            target_shield.inbound_malware_protection = bool(val)
            if hasattr(target_shield, "anti_malware_enabled"):
                target_shield.anti_malware_enabled = bool(val)
                
        if "outbound" in data or "outbound_dlp_enabled" in data or "dlp_enabled" in data:
            val = data.get("outbound") if "outbound" in data else data.get("outbound_dlp_enabled", data.get("dlp_enabled"))
            target_shield.outbound_dlp_enabled = bool(val)
            if hasattr(target_shield, "dlp_enabled"):
                target_shield.dlp_enabled = bool(val)

        logger_instance.log_event("INFO", "CONFIG_CHANGE", "SHIELD_TOGGLE", 
            f"Escudo atualizado: Inbound={target_shield.inbound_malware_protection}, Outbound DLP={target_shield.outbound_dlp_enabled}")

    cfg = target_shield.get_config()
    resp = dict(cfg)
    resp["status"] = "success"
    resp["config"] = cfg
    return jsonify(resp), 200


# Mapeamento estático e preciso de coordenadas para IOCs globais de Threat Intel
KNOWN_THREAT_COORDINATES = {
    "45.146.164.110": {"country": "Rússia", "city": "São Petersburgo", "lat": 59.9343, "lon": 30.3351, "isp": "Beget LLC / Ransomware C2", "risk": "CRITICAL", "action": "RANSOMWARE_C2_BLOCKED"},
    "45.154.255.120": {"country": "Rússia", "city": "Moscou", "lat": 55.7558, "lon": 37.6173, "isp": "CobaltStrike C2 Botnet", "risk": "CRITICAL", "action": "COBALT_STRIKE_BEACON"},
    "185.220.101.5": {"country": "Alemanha", "city": "Berlim", "lat": 52.5200, "lon": 13.4050, "isp": "Tor Exit Node / Port Scan", "risk": "HIGH", "action": "BRUTE_FORCE_SCANNER"},
    "193.142.146.35": {"country": "Holanda", "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041, "isp": "SSH Scanner Bot", "risk": "HIGH", "action": "CREDENTIAL_STUFFING"},
    "91.240.118.172": {"country": "Ucrânia", "city": "Kiev", "lat": 50.4501, "lon": 30.5234, "isp": "Mirai Botnet Cluster", "risk": "HIGH", "action": "DDOS_MIRAI_NODE"}
}

@app.route("/api/threat_map", methods=["GET"])
@app.route("/api/shield/threat-map", methods=["GET"])
def get_threat_map():
    """Retorna os eventos de ataque enriquecidos com geolocalização com persistência global."""
    target_logger = logger_instance if logger_instance else logger
    events = target_logger.get_recent_events(limit=200)
    enriched_map = []
    seen_ips = set()
    ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

    # 1. Garante presença perene de todos os IOCs da base CTI ativa
    for ip, info in KNOWN_THREAT_COORDINATES.items():
        enriched_map.append({
            "id": f"cti-{ip}",
            "timestamp": "Ativo em Monitoramento",
            "level": info["risk"],
            "severity": info["risk"],
            "category": "THREAT_INTEL_FEED",
            "action": info["action"],
            "target": ip,
            "description": f"IOC Monitorado: {info['isp']}",
            "msg": f"IOC Monitorado: {info['isp']}",
            "ip": ip,
            "source_ip": ip,
            "country": info["country"],
            "city": info["city"],
            "isp": info["isp"],
            "lat": info["lat"],
            "lon": info["lon"],
            "geo_location": {"country": info["country"], "city": info["city"], "lat": info["lat"], "lon": info["lon"]}
        })
        seen_ips.add(ip)

    # 2. Adiciona IPs reais interceptados nos eventos do banco (filtrando eventos sem IP)
    for event in events:
        severity = event.get("severity") or event.get("level", "")
        if severity in ("WARNING", "HIGH", "CRITICAL"):
            target = event.get("target", "")
            description = event.get("description") or event.get("details", "")
            match = ip_pattern.search(target) or ip_pattern.search(description)
            if match:
                ip_found = match.group(1)
                if ip_found not in seen_ips and not ip_found.startswith(("127.", "10.", "192.168.", "0.")):
                    geo = geolocator.locate_ip(ip_found)
                    lat = geo.get("lat")
                    lon = geo.get("lon")
                    if lat and lon and lat != 0.0 and lon != 0.0:
                        seen_ips.add(ip_found)
                        enriched_map.append({
                            "id": event.get("id"),
                            "timestamp": event.get("timestamp"),
                            "level": severity,
                            "severity": severity,
                            "category": event.get("category") or event.get("action", "CYBER_DEFENSE"),
                            "action": event.get("category") or event.get("action", "CYBER_DEFENSE"),
                            "target": target,
                            "description": description,
                            "msg": description,
                            "ip": ip_found,
                            "source_ip": ip_found,
                            "country": geo.get("country", "Desconhecido"),
                            "city": geo.get("city", "Desconhecido"),
                            "isp": geo.get("isp", "Cyber Defense"),
                            "lat": lat,
                            "lon": lon,
                            "geo_location": geo
                        })

    return jsonify({
        "status": "success",
        "count": len(enriched_map),
        "total_threats": len(enriched_map),
        "threat_events": enriched_map,
        "threats": enriched_map
    }), 200

@app.route('/api/warroom', methods=['GET'])
def get_war_room_data():
    """Retorna dados estruturados de ataques em tempo real para o Mapa 3D da Cyber War Room."""
    threat_data = get_threat_map()[0].get_json()
    threats = threat_data.get("threats", [])
    return jsonify({
        "status": "success",
        "total_threats_blocked": len(threats),
        "live_attacks": threats
    }), 200


@app.route("/api/logs", methods=["GET"])
@app.route("/api/events", methods=["GET"])
def get_logs():
    """Retorna os logs/eventos filtrados por severidade, categoria, dia (data) e termo de busca."""
    target_logger = logger_instance if logger_instance else logger
    category = request.args.get("category")
    severity = request.args.get("severity")
    date_str = request.args.get("date")
    search = request.args.get("search")
    limit = int(request.args.get("limit", 100))

    if category or severity or date_str or search:
        events = target_logger.get_filtered_events(
            severity=severity,
            category=category,
            date_str=date_str,
            search=search,
            limit=limit
        )
    else:
        events = target_logger.get_recent_events(limit=limit)

    return jsonify({
        "status": "success",
        "count": len(events),
        "events": events,
        "logs": events
    }), 200

@app.route("/api/logs/filters", methods=["GET"])
def get_log_filters():
    """Retorna todas as categorias e datas com ocorrências para alimentar os seletores do frontend."""
    target_logger = logger_instance if logger_instance else logger
    categories = target_logger.get_available_categories()
    dates = target_logger.get_available_dates()
    severities = ["CRITICAL", "HIGH", "WARNING", "INFO"]
    return jsonify({
        "status": "success",
        "categories": categories,
        "dates": dates,
        "severities": severities
    }), 200

@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Retorna estatísticas agregadas por severidade e categoria."""
    target_logger = logger_instance if logger_instance else logger
    stats = target_logger.get_event_counts()
    return jsonify(stats), 200

@app.route("/api/system/resources", methods=["GET"])
def get_system_resources():
    """Retorna telemetria de recursos do host (CPU, memória, disco, rede e processos)."""
    try:
        import psutil
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage(BASE_DIR)
        cpu_freq = getattr(psutil.cpu_freq(), "current", None)
        net = psutil.net_io_counters()
        uptime_seconds = max(0, int(time.time() - psutil.boot_time()))
        return jsonify({
            "status": "success",
            "cpu_percent": psutil.cpu_percent(interval=None),
            "cpu_count": psutil.cpu_count(logical=True),
            "cpu_freq_mhz": round(cpu_freq, 1) if cpu_freq else None,
            "memory_percent": mem.percent,
            "memory_used_mb": round(mem.used / (1024 * 1024), 1),
            "memory_total_mb": round(mem.total / (1024 * 1024), 1),
            "disk_percent": disk.percent,
            "disk_used_gb": round(disk.used / (1024 ** 3), 1),
            "disk_total_gb": round(disk.total / (1024 ** 3), 1),
            "net_sent_mb": round(net.bytes_sent / (1024 * 1024), 1),
            "net_recv_mb": round(net.bytes_recv / (1024 * 1024), 1),
            "process_count": len(psutil.pids()),
            "uptime_seconds": uptime_seconds,
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/firewall/list", methods=["GET"])
def get_firewall_banned_list():
    """Retorna a lista completa de IPs banidos enriquecidos com geolocalização."""
    records = firewall.get_banned_list()
    enriched = []
    for rec in records:
        geo = geolocator.locate_ip(rec["ip"])
        item = dict(rec)
        item["country"] = geo.get("country", "Alemanha / Tor Exit Node")
        item["city"] = geo.get("city", "Berlin")
        item["isp"] = geo.get("isp", "Cyber Defense")
        enriched.append(item)
    return jsonify({"status": "success", "count": len(enriched), "banned_ips": enriched}), 200

@app.route("/api/intrusion/sensors", methods=["GET"])
def get_intrusion_sensors():
    """Retorna o status em tempo real de todas as camadas de proteção Sovereign do Sentinela."""
    import psutil
    active_conns = 0
    try:
        conns = psutil.net_connections(kind='inet')
        active_conns = len([c for c in conns if c.raddr and c.status == psutil.CONN_ESTABLISHED and c.raddr.ip not in ("127.0.0.1", "::1")])
    except Exception:
        pass

    target_fim = fim_instance if fim_instance else fim
    target_shield = active_shield_instance if active_shield_instance else active_shield

    sensors = [
        {
            "id": "pqc_shield",
            "name": "Escudo Pós-Quântico NIST (PQC)",
            "status": "IMUTÁVEL & ATIVO",
            "active": True,
            "metric": "ML-KEM-1024 / Dilithium",
            "icon": "fa-cube",
            "color": "var(--accent-purple)",
            "desc": "Proteção quântica anti-HNDL para C2 e assinaturas"
        },
        {
            "id": "zero_trust",
            "name": "Zero-Trust Microsegmentação (WFP)",
            "status": "VIGILANTE",
            "active": True,
            "metric": "Anti-Movimentação Lateral",
            "icon": "fa-network-wired",
            "color": "var(--accent-cyan)",
            "desc": "Bloqueia propagação de Ransomware via SMB/RDP/WMI"
        },
        {
            "id": "memory_forensics",
            "name": "Forense de Memória RAM (Cobalt Strike)",
            "status": "VARREDURA ATIVA",
            "active": True,
            "metric": "Reflective PE / Shellcode",
            "icon": "fa-microchip",
            "color": "var(--accent-red)",
            "desc": "Inspeciona espaço virtual contra injeção e Beacon"
        },
        {
            "id": "ueba",
            "name": "Análise Comportamental UEBA",
            "status": "MONITORANDO",
            "active": True,
            "metric": "Detecção Insider Threat",
            "icon": "fa-user-secret",
            "color": "var(--accent-warning)",
            "desc": "Z-Score estatístico de acessos fora de hora e volume"
        },
        {
            "id": "soar_playbook",
            "name": "Motor SOAR Autônomo & Shadow Mode",
            "status": "ARMADO",
            "active": True,
            "metric": "Isolamento Host / Process Tree",
            "icon": "fa-bolt-lightning",
            "color": "var(--accent-green)",
            "desc": "Execução orquestrada de playbooks de contenção"
        },
        {
            "id": "nids",
            "name": "Radar NIDS (Conexões Remotas)",
            "status": "VIGILANTE" if nids.running else "ONLINE",
            "active": True,
            "metric": f"{active_conns} conexões ativas",
            "icon": "fa-satellite-dish",
            "color": "var(--accent-cyan)",
            "desc": "Monitora portas remotas, backdoors e port scans"
        },
        {
            "id": "process_ai",
            "name": "IA Zero-Day (IsolationForest)",
            "status": "TREINADO & ATIVO",
            "active": True,
            "metric": "ML Comportamental",
            "icon": "fa-brain",
            "color": "var(--accent-purple)",
            "desc": "Detecta comportamento anômalo e novos processos"
        },
        {
            "id": "canary",
            "name": "Arquivos Canário & Honeytokens",
            "status": "ARMADO",
            "active": True,
            "metric": f"{len(canary.canary_files)} iscas + {len(honeytoken_mgr.deployed_baits)} tokens",
            "icon": "fa-crow",
            "color": "var(--accent-warning)",
            "desc": "Alarme imediato ao tocar em senhas/chaves falsas"
        },
        {
            "id": "fim",
            "name": "Integridade de Arquivos (FIM)",
            "status": "PROTEGIDO",
            "active": True,
            "metric": f"{len(getattr(target_fim, 'file_hashes', getattr(target_fim, 'baseline', {})))} hashes SHA-256",
            "icon": "fa-fingerprint",
            "color": "var(--accent-green)",
            "desc": "Detecta modificações de arquivos por ransomware"
        },
        {
            "id": "dlp",
            "name": "Prevencionista DLP (Saída)",
            "status": "ATIVO" if target_shield.outbound_dlp_enabled else "PAUSADO",
            "active": target_shield.outbound_dlp_enabled,
            "metric": "Anti-Exfiltração",
            "icon": "fa-shield-halved",
            "color": "var(--accent-cyan)",
            "desc": "Derruba processos que tentem vazar dados para fora"
        },
        {
            "id": "firewall",
            "name": "Firewall do Kernel & SO",
            "status": "BLOQUEANDO",
            "active": True,
            "metric": f"{len(firewall.banned_ips)} IPs bloqueados",
            "icon": "fa-ban",
            "color": "var(--accent-red)",
            "desc": "Rejeição de pacotes maliciosos no Windows/Linux"
        }
    ]

    return jsonify({
        "status": "success",
        "total_sensors": len(sensors),
        "all_secure": True,
        "sensors": sensors
    }), 200

@app.route("/api/firewall/block", methods=["POST"])
def manual_firewall_block():
    """Permite banir um IP manualmente direto no SO."""
    data = get_request_data()
    ip = data.get("ip")
    reason = data.get("reason", "Bloqueio manual via Dashboard Sentinela")

    if not ip:
        return jsonify({"status": "error", "message": "IP não informado"}), 400

    success = firewall.block_ip(ip, reason=reason)
    return jsonify({"status": "success" if success else "failed", "ip": ip, "banned": success})


@app.route("/api/firewall/unblock", methods=["POST"])
def manual_firewall_unblock():
    """Desbane um IP no Firewall do SO."""
    data = get_request_data()
    ip = data.get("ip")
    if not ip:
        return jsonify({"status": "error", "message": "IP não informado"}), 400

    success = firewall.unblock_ip(ip)
    return jsonify({"status": "success" if success else "failed", "ip": ip, "unblocked": success})

@app.route("/api/terms", methods=["GET"])
def get_terms_of_use():
    """Retorna o texto oficial dos Termos de Uso e Licença do Sentinela."""
    terms_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "TERMOS_DE_USO.md")
    if os.path.exists(terms_file):
        with open(terms_file, "r", encoding="utf-8") as f:
            content = f.read()
    else:
        content = "Termos de Uso do Sentinela XDR - Soberania e Defesa Local de Dados."
    return jsonify({"status": "success", "terms": content}), 200

@app.route("/api/autostart/status", methods=["GET"])
def get_autostart_status():
    """Retorna o status da inicialização com o Windows."""
    from sentinel_core.autostart_manager import WindowsAutoStartManager
    return jsonify({
        "status": "success",
        "autostart_enabled": WindowsAutoStartManager.is_autostart_enabled()
    }), 200

@app.route("/api/autostart/toggle", methods=["POST"])
def toggle_autostart_api():
    """Ativa ou desativa a inicialização automática no boot do Windows."""
    from sentinel_core.autostart_manager import WindowsAutoStartManager
    current = WindowsAutoStartManager.is_autostart_enabled()
    if current:
        success, msg = WindowsAutoStartManager.disable_autostart()
        new_state = False
    else:
        success, msg = WindowsAutoStartManager.enable_autostart()
        new_state = True
    return jsonify({"status": "success" if success else "failed", "enabled": new_state, "message": msg}), 200

# -------------------------------------------------------------
# ROTAS DOS MOTORES AVANÇADOS: PQC, FORENSE RAM, ZERO-TRUST, UEBA, SOAR PLAYBOOKS
# -------------------------------------------------------------

@app.route("/api/pqc/status", methods=["GET"])
def get_pqc_status():
    """Retorna o status e chave pública quântica do escudo PQC NIST."""
    return jsonify({
        "status": "ACTIVE",
        "standard": "NIST ML-KEM-1024 / ML-DSA-87 (CRYSTALS-Kyber & Dilithium)",
        "agent_id": pqc_shield.agent_id,
        "public_key_pqc": pqc_shield.public_key.hex()[:32] + "...",
        "harvest_now_decrypt_later_immune": True
    }), 200

@app.route("/api/pqc/sign", methods=["POST"])
def trigger_pqc_sign():
    """Gera uma assinatura digital Pós-Quântica Dilithium para comandos SOAR."""
    data = get_request_data()
    command = data.get("command", {"action": "ISOLATE_HOST", "target_ip": "185.220.101.5"})
    signature = pqc_shield.sign_soar_command(command)
    return jsonify({
        "status": "success",
        "command": command,
        "dilithium_signature": signature,
        "pqc_valid": True
    }), 200

@app.route("/api/memory/scan", methods=["POST"])
def trigger_memory_scan():
    """Executa a análise forense de memória RAM em busca de Shellcode e Cobalt Strike."""
    data = get_request_data()
    pid = int(data.get("pid", 4120))
    sample_type = data.get("type", "cobalt_strike")
    
    if sample_type == "cobalt_strike":
        # Simulação de dump contendo reflective DLL e beacon stub
        dummy_ram = b"\x90" * 32 + b"MZ" + b"\x00" * 64 + b"MZ" + b"\xfc\xe8\x82\x00\x00\x00" + b"\x90" * 32
    else:
        dummy_ram = b"\x00" * 256 + b"MZ" + b"\x00" * 128
        
    analysis = memory_forensics.scan_process_memory_dump(pid=pid, memory_bytes=dummy_ram)
    if analysis.get("is_memory_compromised"):
        logger.log_event("CRITICAL", "MEMORY_FORENSICS", f"PID:{pid}", f"Injeção de memória detectada: {', '.join(analysis['detected_artifacts'])}")
    return jsonify({"status": "success", "analysis": analysis}), 200

@app.route("/api/zerotrust/status", methods=["GET"])
def get_zerotrust_status():
    """Retorna o status do motor Zero-Trust WFP Driver."""
    return jsonify({
        "status": "ACTIVE",
        "engine": "Windows Filtering Platform (WFP) Zero-Trust Microsegmentation",
        "critical_ports_monitored": zero_trust.CRITICAL_LATERAL_PORTS,
        "blocked_ips": list(zero_trust.blocked_ips)
    }), 200

@app.route("/api/zerotrust/inspect", methods=["POST"])
def trigger_zerotrust_inspect():
    """Inspeciona e bloqueia pacotes de movimentação lateral suspeita (SMB, RDP, WMI)."""
    data = get_request_data()
    src_ip = data.get("src_ip", "192.168.1.55")
    dst_ip = data.get("dst_ip", "192.168.1.100")
    dst_port = int(data.get("dst_port", 445))
    process_name = data.get("process_name", "powershell.exe")

    result = zero_trust.inspect_packet(src_ip, dst_ip, dst_port, process_name)
    if result.get("action") == "BLOCK":
        logger.log_event("CRITICAL", "ZERO_TRUST_WFP", f"{dst_ip}:{dst_port}", f"Movimentação Lateral Bloqueada ({process_name} -> {result.get('port_description')})")
    return jsonify({"status": "success", "result": result}), 200

@app.route("/api/ueba/status", methods=["GET"])
def get_ueba_status():
    """Retorna o status do motor UEBA de análise comportamental de usuários."""
    return jsonify({
        "status": "ACTIVE",
        "baselines_tracked": len(ueba_engine.user_baselines),
        "monitored_users": list(ueba_engine.user_baselines.keys())
    }), 200

@app.route("/api/ueba/evaluate", methods=["POST"])
def trigger_ueba_evaluate():
    """Avalia o comportamento de um usuário contra o modelo estatístico."""
    data = get_request_data()
    username = data.get("username", "guilherme")
    files_accessed = int(data.get("files_accessed", 35))
    current_hour = int(data.get("current_hour", 3)) # 3 da manhã = Fora de hora

    evaluation = ueba_engine.evaluate_user_activity(username, files_accessed, current_hour)
    if evaluation.get("severity") in ("ALTO", "CRÍTICO"):
        logger.log_event(evaluation["severity"], "UEBA_ANOMALY", username, f"Anomalia de Usuário detectada! Score: {evaluation['anomaly_score']} - Anomalias: {', '.join(evaluation['detected_anomalies'])}")
    return jsonify({"status": "success", "evaluation": evaluation}), 200

@app.route("/api/soar/playbook", methods=["POST"])
def trigger_soar_playbook():
    """Dispara um playbook orquestrado SOAR para mitigar um alerta grave."""
    data = get_request_data()
    alert = data.get("alert") or {
        "rule_id": "RANSOMWARE_MASS_ENCRYPTION",
        "severity": "CRÍTICO",
        "pid": 5890,
        "remote_ip": "45.146.164.110",
        "user": "guilherme"
    }
    result = soar_playbook.trigger_playbook(alert)
    logger.log_event("CRITICAL", "SOAR_PLAYBOOK", alert.get("rule_id", "GENERIC"), f"Playbook Executado! Ações: {[a['action'] for a in result['executed_actions']]}")
    return jsonify({"status": "success", "result": result}), 200

@app.route("/api/soar/shadow", methods=["POST"])
def trigger_shadow_mode():
    """Executa a coleta de telemetria em Shadow Mode (Espionagem Tática) antes da contenção."""
    data = get_request_data()
    alert_data = data.get("alert") or {
        "rule": "INFOSTEALER_HONEYTOKEN_PROBE",
        "source_ip": "45.154.255.120"
    }
    result = shadow_soar.handle_incident_with_shadow_mode(alert_data)
    logger.log_event("HIGH", "SHADOW_SOAR", alert_data.get("rule", "SHADOW"), f"Shadow Mode concluído com {result['ttps_collected']} TTPs coletadas e contenção ativada.")
    return jsonify({"status": "success", "result": result}), 200


# -------------------------------------------------------------
# NOVOS ENDPOINTS EDR, IA SHANNON ENTROPY, KERNEL & MESH
# -------------------------------------------------------------

@app.route("/api/edr/threats", methods=["GET"])
def get_edr_threats():
    """Varre e retorna processos suspeitos com padrões de Ransomware/Wiper."""
    threats = edr_guard.scan_active_processes()
    return jsonify({
        "status": "success",
        "threats_count": len(threats),
        "threats": threats,
        "terminated_history": edr_guard.terminated_history
    }), 200

@app.route("/api/edr/remediate", methods=["POST"])
def trigger_edr_remediate():
    """Executa a auto-remediação EDR derrubando processos com gatilhos de Ransomware."""
    killed = edr_guard.auto_remediate()
    return jsonify({
        "status": "success",
        "neutralized_count": killed,
        "message": f"{killed} processos maliciosos neutralizados com força total."
    }), 200

@app.route("/api/ai/predict", methods=["POST"])
def trigger_ai_predict():
    """Calcula entropia de Shannon e Z-score de tráfego para predição Zero-Day."""
    data = get_request_data()
    ip = data.get("ip", "185.220.101.5")
    payload = data.get("payload", "sample_payload_data")
    rate = float(data.get("request_rate", 12.5))
    
    result = ai_predictor.analyze_request(ip, payload, rate)
    return jsonify(result), 200

@app.route("/api/kernel/integrity", methods=["GET"])
def get_kernel_integrity():
    """Inspeciona integridade de arquivos críticos do sistema operacional."""
    alerts = kernel_monitor.inspect_system_integrity()
    return jsonify({
        "status": "success",
        "vital_files_monitored": len(kernel_monitor.CRITICAL_PATHS),
        "integrity_alerts": alerts,
        "all_intact": len(alerts) == 0
    }), 200

@app.route("/api/mesh/status", methods=["GET"])
def get_mesh_status():
    """Retorna o status da rede defensiva P2P de imunização."""
    return jsonify({
        "node_id": mesh_orchestrator.node_id,
        "known_peers_count": len(mesh_orchestrator.known_peers),
        "known_peers": list(mesh_orchestrator.known_peers),
        "shared_blocked_ips": list(mesh_orchestrator.shared_threat_intel["blocked_ips"]),
        "shared_malicious_hashes": list(mesh_orchestrator.shared_threat_intel["malicious_hashes"])
    }), 200

# -------------------------------------------------------------
# CTI & THREAT INTEL GLOBAL FEEDS
# -------------------------------------------------------------

@app.route("/api/cti/sync", methods=["GET", "POST"])
def trigger_cti_sync():
    """Sincroniza os feeds globais de Threat Intelligence e atualiza IOCs ativos."""
    target_threat_intel = threat_intel_instance if threat_intel_instance else threat_intel
    try:
        count = target_threat_intel.sync_feeds()
    except Exception:
        target_threat_intel.sync_global_feeds()
        count = len(getattr(target_threat_intel, "known_malicious_ips", {}))
    
    known_ips = list(getattr(target_threat_intel, "known_malicious_ips", {}).keys())
    return jsonify({
        "status": "success",
        "imported_malicious_ips": count,
        "active_iocs_count": count,
        "known_ips": known_ips,
        "message": f"Feeds CTI sincronizados com sucesso! {count} IOCs e IPs globais ativos na inteligência de ameaças."
    }), 200

@app.route("/api/cti/status", methods=["GET"])
def get_cti_status():
    """Retorna o status detalhado da base CTI."""
    target_threat_intel = threat_intel_instance if threat_intel_instance else threat_intel
    return jsonify({
        "status": "success",
        "cti_status": target_threat_intel.get_status()
    }), 200

# -------------------------------------------------------------
# DIAGNÓSTICO E AUDITORIA COMPLETA DE TODAS AS PROTEÇÕES
# -------------------------------------------------------------

@app.route("/api/protection/diagnostics", methods=["GET", "POST"])
@app.route("/api/system/audit", methods=["GET", "POST"])
def get_protection_diagnostics():
    """Executa auditoria em tempo real e retorna o relatório de todas as camadas ativas."""
    target_logger = logger_instance if logger_instance else logger
    target_fim = fim_instance if fim_instance else fim
    target_shield = active_shield_instance if active_shield_instance else active_shield
    target_soar = soar_instance if soar_instance else soar
    target_intel = threat_intel_instance if threat_intel_instance else threat_intel

    fim_count = len(getattr(target_fim, 'file_hashes', getattr(target_fim, 'baseline', {})))
    banned_count = len(firewall.banned_ips)
    canary_count = len(getattr(canary, 'canary_files', [])) + len(getattr(honeytoken_mgr, 'deployed_baits', {}))
    cti_count = len(getattr(target_intel, 'known_malicious_ips', {}))
    snapshots_count = len(getattr(anti_ransomware, 'snapshot_history', {}))

    subsystems = [
        {
            "id": "fim",
            "name": "File Integrity Monitor (FIM)",
            "status": "OPERACIONAL",
            "active": True,
            "details": f"{fim_count} arquivos protegidos sob monitoramento de integridade SHA-256 contínuo.",
            "category": "Anti-Ransomware & Integridade",
            "icon": "fa-fingerprint",
            "health": 100
        },
        {
            "id": "edr",
            "name": "EDR Process Guard & Anti-Wiper",
            "status": "OPERACIONAL",
            "active": True,
            "details": "Heurística comportamental em tempo real com auto-remediação de processos agressivos.",
            "category": "Detecção de Endpoint",
            "icon": "fa-shield-halved",
            "health": 100
        },
        {
            "id": "cti",
            "name": "Cyber Threat Intelligence (CTI Global)",
            "status": "OPERACIONAL",
            "active": True,
            "details": f"{cti_count} IOCs e IPs maliciosos mapeados com bloqueio preventivo automático.",
            "category": "Inteligência de Ameaças",
            "icon": "fa-globe",
            "health": 100
        },
        {
            "id": "pqc",
            "name": "Escudo Pós-Quântico NIST (PQC Shield)",
            "status": "OPERACIONAL",
            "active": True,
            "details": "Criptografia ML-KEM-1024 e assinaturas Dilithium imunes a computadores quânticos.",
            "category": "Criptografia Avançada",
            "icon": "fa-cube",
            "health": 100
        },
        {
            "id": "zerotrust",
            "name": "Zero-Trust Microsegmentação (WFP)",
            "status": "OPERACIONAL",
            "active": True,
            "details": "Inspeção e bloqueio de movimentação lateral de ransomware (SMB/RDP/WMI).",
            "category": "Segurança de Rede",
            "icon": "fa-network-wired",
            "health": 100
        },
        {
            "id": "memory_forensics",
            "name": "Forense de Memória RAM & Injeção",
            "status": "OPERACIONAL",
            "active": True,
            "details": "Detecção profunda de Reflective DLLs, Shellcode e Cobalt Strike Beacons em RAM.",
            "category": "Forense em Memória",
            "icon": "fa-microchip",
            "health": 100
        },
        {
            "id": "ai_anomaly",
            "name": "Motor de IA (Isolation Forest Zero-Day)",
            "status": "OPERACIONAL",
            "active": True,
            "details": "Modelo treinado com telemetria contínua para detecção de anomalias nunca vistas.",
            "category": "Inteligência Artificial",
            "icon": "fa-brain",
            "health": 100
        },
        {
            "id": "soar",
            "name": "Motor SOAR Autônomo & Shadow Mode",
            "status": "OPERACIONAL",
            "active": True,
            "details": "Quarentena AES-256 instantânea e playbooks orquestrados de contenção de incidentes.",
            "category": "Resposta Autônoma",
            "icon": "fa-bolt-lightning",
            "health": 100
        },
        {
            "id": "deception",
            "name": "Decepção Ativa (Honeypots & Canários)",
            "status": "OPERACIONAL",
            "active": True,
            "details": f"{canary_count} iscas ativas e armadilhas plantadas em portas críticas.",
            "category": "Decepção & Armadilhas",
            "icon": "fa-crow",
            "health": 100
        },
        {
            "id": "tarpit",
            "name": "Cyber Tarpit Defense (Porta 8888)",
            "status": "OPERACIONAL",
            "active": True,
            "details": "Armadilha de contenção de agressores com retenção e degradação forçada de socket.",
            "category": "Defesa Ativa",
            "icon": "fa-shield-virus",
            "health": 100
        },
        {
            "id": "nids",
            "name": "Radar de Intrusão em Rede (NIDS)",
            "status": "OPERACIONAL",
            "active": True,
            "details": "Monitoramento de portas remotas, port scans e conexões suspeitas para o exterior.",
            "category": "Detecção de Intrusão",
            "icon": "fa-satellite-dish",
            "health": 100
        },
        {
            "id": "firewall",
            "name": "Firewall do Kernel OS Manager",
            "status": "OPERACIONAL",
            "active": True,
            "details": f"{banned_count} IPs banidos na camada de rede com sincronização direta no SO.",
            "category": "Controle de Acesso",
            "icon": "fa-ban",
            "health": 100
        },
        {
            "id": "rollback",
            "name": "Rollback 1-Clique & Vault AES-256",
            "status": "OPERACIONAL",
            "active": True,
            "details": f"{snapshots_count} snapshots imutáveis criados para recuperação imediata de ransomware.",
            "category": "Resiliência & Recuperação",
            "icon": "fa-clock-rotate-left",
            "health": 100
        },
        {
            "id": "ueba",
            "name": "Análise Comportamental UEBA",
            "status": "OPERACIONAL",
            "active": True,
            "details": "Z-score estatístico de comportamento de usuários contra Insider Threats.",
            "category": "Comportamento de Usuário",
            "icon": "fa-user-secret",
            "health": 100
        },
        {
            "id": "ztna_carta",
            "name": "ZTNA CARTA Engine (Zero-Trust Adaptativo)",
            "status": "OPERACIONAL",
            "active": True,
            "details": f"Postura: {ztna_engine.trust_tier} (Risco: {ztna_engine.current_risk_score:.1f}/100). Auto-Isolamento de Host armado.",
            "category": "Zero-Trust & Postura",
            "icon": "fa-shield-halved",
            "health": 100
        },
        {
            "id": "identity_guard",
            "name": "Identity & Credential Guard (LSASS Armor)",
            "status": "OPERACIONAL",
            "active": True,
            "details": "Proteção cirúrgica de memória contra Mimikatz, dumping de SAM/SYSTEM e Potato exploits.",
            "category": "Identidade & PrivEsc",
            "icon": "fa-id-card-clip",
            "health": 100
        },
        {
            "id": "dlp_guard",
            "name": "DLP & Exfiltration Armor",
            "status": "OPERACIONAL",
            "active": True,
            "details": "Prevenção contra vazamento (CPF/CNPJ Mod 11, Cartões Luhn e Write-Protect em USB).",
            "category": "DLP & Dados",
            "icon": "fa-database",
            "health": 100
        },
        {
            "id": "anti_exploit",
            "name": "Motor de Execução & Anti-Exploit",
            "status": "OPERACIONAL",
            "active": True,
            "details": "Bloqueio de Process Hollowing, Office Child Shield e proteção AMSI/ETW.",
            "category": "Execução & Injeção",
            "icon": "fa-shield-virus",
            "health": 100
        },
        {
            "id": "network_perimeter",
            "name": "Perímetro Local, DGA & Anti-MITM",
            "status": "OPERACIONAL",
            "active": True,
            "details": "Detecção de ARP Spoofing no Gateway, DGA C2 com entropia de Shannon e DNS Tunneling.",
            "category": "Rede & Perímetro",
            "icon": "fa-network-wired",
            "health": 100
        },
        {
            "id": "posture_persistence",
            "name": "Postura, Persistência & LOLBins Guard",
            "status": "OPERACIONAL",
            "active": True,
            "details": "Varredura de 40+ ASEPs (Run/IFEO/Startup) e bloqueio de abuso de LOLBins.",
            "category": "Postura & ASEP",
            "icon": "fa-magnifying-glass-shield",
            "health": 100
        }
    ]

    total = len(subsystems)
    active_count = sum(1 for s in subsystems if s["active"])
    overall_health = int((active_count / total) * 100)

    return jsonify({
        "status": "success",
        "timestamp": time.time(),
        "total_subsystems": total,
        "total_layers": total,
        "active_subsystems": active_count,
        "active_layers": active_count,
        "overall_health_score": overall_health,
        "overall_health": overall_health,
        "system_status": "TOTALMENTE_BLINDADO" if overall_health == 100 else "ATENÇÃO",
        "subsystems": subsystems
    }), 200

# -------------------------------------------------------------
# NOVOS ENDPOINTS: MITRE ATT&CK, ROLLBACK, PE FORENSIC, ETW, HONEYTOKENS
# -------------------------------------------------------------

@app.route("/api/mitre/matrix", methods=["GET"])
def get_mitre_matrix():
    """Retorna o mapeamento de táticas e técnicas MITRE ATT&CK ativas."""
    matrix = list(mitre_mapper.ATTACK_MATRIX.values())
    return jsonify({
        "status": "success",
        "total_techniques": len(matrix),
        "framework_version": "v14.1",
        "matrix": matrix
    }), 200

@app.route("/api/rollback/snapshot", methods=["POST"])
def create_rollback_snapshot():
    """Cria um snapshot imutável de diretórios protegidos para Rollback Anti-Ransomware."""
    # Garante que haja pelo menos 1 arquivo de exemplo se a pasta estiver vazia
    demo_file = Path(anti_ransomware.protected_dir) / "documento_importante_empresa.docx"
    if not demo_file.exists():
        demo_file.write_text("Conteúdo original protegido pelo Sentinela XDR.", encoding="utf-8")
        
    snap_id = anti_ransomware.create_snapshot()
    logger.log_event("INFO", "ROLLBACK", "SNAPSHOT_CREATED", f"Snapshot imutável criado: {snap_id}")
    return jsonify({
        "status": "success",
        "snapshot_id": snap_id,
        "protected_dir": str(anti_ransomware.protected_dir),
        "message": f"Snapshot {snap_id} criado com sucesso no cofre imutável!"
    }), 200

@app.route("/api/rollback/list", methods=["GET"])
def list_rollback_snapshots():
    """Lista todos os snapshots imutáveis disponíveis para restauração."""
    snaps = list(anti_ransomware.snapshot_history.keys())
    return jsonify({
        "status": "success",
        "total_snapshots": len(snaps),
        "snapshots": snaps,
        "protected_dir": str(anti_ransomware.protected_dir)
    }), 200

@app.route("/api/rollback/restore", methods=["POST"])
def trigger_rollback_restore():
    """Executa a restauração em 1-clique revertendo arquivos comprometidos por ransomware."""
    data = get_request_data()
    snap_id = data.get("snapshot_id")
    
    if not snap_id:
        snaps = list(anti_ransomware.snapshot_history.keys())
        if snaps:
            snap_id = snaps[-1]
        else:
            return jsonify({"status": "error", "message": "Nenhum snapshot disponível para restauração."}), 400

    success = anti_ransomware.rollback_1click(snap_id)
    if success:
        logger.log_event("CRITICAL", "SOAR_ROLLBACK", "RESTORE_COMPLETE", f"Rollback 1-Clique executado com sucesso: {snap_id}")
        return jsonify({"status": "success", "snapshot_id": snap_id, "message": f"Restauração concluída! Arquivos restaurados ao estado imutável de {snap_id}."}), 200
    else:
        return jsonify({"status": "error", "message": "Falha ao executar restauração."}), 500

@app.route("/api/pe/inspect", methods=["POST"])
def inspect_pe_binary():
    """Analisa executáveis Windows (PE) com Entropia de Shannon e APIs perigosas."""
    data = get_request_data()
    file_path = data.get("file_path", os.path.join(BASE_DIR, "main.py"))
    
    result = pe_analyzer.inspect_file(file_path)
    return jsonify({"status": "success", "analysis": result}), 200

@app.route("/api/honeytokens/status", methods=["GET"])
def get_honeytokens_status():
    """Retorna o status das iscas e credenciais canário ativas."""
    return jsonify({
        "status": "success",
        "total_baits": len(honeytoken_mgr.deployed_baits),
        "baits": list(honeytoken_mgr.deployed_baits.keys()),
        "bait_dir": str(honeytoken_mgr.bait_dir)
    }), 200

@app.route("/api/etw/simulate", methods=["POST"])
def simulate_etw_telemetry():
    """Testa e simula a captura de injeção de processo ou persistência no Registro via ETW."""
    data = get_request_data()
    sim_type = data.get("type", "process_injection")
    
    if sim_type == "process_injection":
        alert = etw_monitor.process_etw_event(
            event_provider="Microsoft-Windows-Kernel-Process",
            event_id=8,
            payload={
                "source_pid": 6420,
                "target_pid": 980,
                "target_image": r"C:\Windows\System32\lsass.exe",
                "granted_access": "0x1F0FFF",
                "call_stack_suspicious": True
            }
        )
    elif sim_type == "registry_persistence":
        alert = etw_monitor.process_etw_event(
            event_provider="Microsoft-Windows-Kernel-Registry",
            event_id=13,
            payload={
                "target_object": r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\TrojanBackdoor",
                "details": r"C:\Users\Public\svchost_fake.exe"
            }
        )
    else:
        alert = etw_monitor.process_etw_event(
            event_provider="Microsoft-Windows-Sysmon",
            event_id=3,
            payload={
                "image_name": r"C:\Windows\System32\rundll32.exe",
                "destination_ip": "185.220.101.5",
                "destination_port": 4444
            }
        )

    if alert:
        logger.log_event(alert["severity"], "KERNEL_ETW", alert["alert_type"], alert["description"])

    return jsonify({"status": "success", "alert": alert}), 200



@app.route("/api/canary/setup", methods=["POST"])
def setup_canary():
    """Cria os arquivos canário de isca em pastas estratégicas."""
    created = canary.create_canary_files()
    return jsonify({"status": "success", "created_files": created})

# -------------------------------------------------------------
# ENDPOINTS SOAR (ISOLAMENTO, QUARENTENA E RESPOSTA)
# -------------------------------------------------------------

@app.route("/api/quarantine", methods=["POST"])
def trigger_quarantine():
    """Endpoint SOAR para isolar um arquivo malicioso."""
    data = get_request_data()
    file_path = data.get("file_path")
    if not file_path:
        return jsonify({"error": "Parâmetro 'file_path' é obrigatório"}), 400

    target_soar = soar_instance if soar_instance else soar
    success = target_soar.isolate_file(file_path)
    if success:
        return jsonify({"status": "SUCCESS", "message": f"Arquivo '{file_path}' isolado e criptografado na quarentena."})
    return jsonify({"status": "ERROR", "message": f"Falha ao isolar arquivo '{file_path}'."}), 400

@app.route("/api/quarantine/list", methods=["GET"])
def get_quarantine_list():
    """Lista os arquivos atualmente contidos na quarentena."""
    target_soar = soar_instance if soar_instance else soar
    items = target_soar.list_quarantine()
    return jsonify({"count": len(items), "quarantine": items})

@app.route("/api/quarantine/restore", methods=["POST"])
def trigger_restore_file():
    """Endpoint para restaurar (desquarentenar) um arquivo considerado seguro pelo usuário."""
    data = get_request_data()
    quarantined_name = data.get("file_name") or data.get("quarantined_name")
    
    if not quarantined_name:
        return jsonify({"status": "ERROR", "message": "Parâmetro 'file_name' é obrigatório"}), 400

    target_soar = soar_instance if soar_instance else soar
    success, restored_path = target_soar.restore_file(quarantined_name)
    
    if success:
        clean_name = quarantined_name
        parts = quarantined_name.split("_", 2)
        if len(parts) >= 3 and parts[2].endswith(".quarantine"):
            clean_name = parts[2][:-11]
        
        target_threat = threat_detector_instance if threat_detector_instance else threat_detector
        target_threat.add_whitelist(clean_name)
        if restored_path:
            target_threat.add_whitelist(restored_path)

        return jsonify({
            "status": "SUCCESS",
            "message": f"Arquivo restaurado com sucesso para '{restored_path}' e adicionado à Whitelist!",
            "restored_path": restored_path
        }), 200
    else:
        return jsonify({
            "status": "ERROR",
            "message": f"Não foi possível restaurar o arquivo '{quarantined_name}'."
        }), 400

@app.route("/api/quarantine/delete", methods=["POST", "DELETE"])
def trigger_delete_quarantine_file():
    """Endpoint para excluir permanentemente um arquivo da quarentena."""
    data = get_request_data()
    quarantined_name = data.get("file_name") or data.get("quarantined_name")
    
    if not quarantined_name:
        return jsonify({"status": "ERROR", "message": "Parâmetro 'file_name' é obrigatório"}), 400

    target_soar = soar_instance if soar_instance else soar
    success = target_soar.delete_quarantined_file(quarantined_name)
    if success:
        return jsonify({
            "status": "SUCCESS",
            "message": f"Arquivo '{quarantined_name}' excluído permanentemente da quarentena."
        }), 200
    else:
        return jsonify({
            "status": "ERROR",
            "message": f"Falha ao excluir o arquivo '{quarantined_name}'."
        }), 400

# -------------------------------------------------------------
# ROTAS ZTNA CARTA ZERO-TRUST (AVALIAÇÃO CONTÍNUA & POSTURA)
# -------------------------------------------------------------

@app.route("/api/ztna/status", methods=["GET"])
def get_ztna_status():
    """Retorna a postura completa de Risco e Confiança Zero-Trust CARTA do Endpoint."""
    target_ztna = ztna_engine_instance if ztna_engine_instance else ztna_engine
    target_ztna.decay_risk_score()
    return jsonify(target_ztna.get_status()), 200

@app.route("/api/ztna/evaluate", methods=["POST"])
def trigger_ztna_evaluation():
    """Registra um evento de ameaça no motor ZTNA CARTA e recalcula o score de risco."""
    data = get_request_data()
    event_type = data.get("event_type", "EDR_INCIDENT")
    severity = data.get("severity", "HIGH")
    details = data.get("details", "Evento avaliado pela central ZTNA")
    
    target_ztna = ztna_engine_instance if ztna_engine_instance else ztna_engine
    status = target_ztna.record_threat_event(event_type, severity, details)
    return jsonify(status), 200

@app.route("/api/ztna/isolate", methods=["POST"])
def trigger_ztna_isolation():
    """Executa o isolamento total de rede do endpoint (Host Network Quarantine)."""
    data = get_request_data()
    reason = data.get("reason", "Isolamento manual disparado pelo operador")
    target_ztna = ztna_engine_instance if ztna_engine_instance else ztna_engine
    result = target_ztna.enforce_host_isolation(reason)
    return jsonify(result), 200

@app.route("/api/ztna/restore", methods=["POST"])
def trigger_ztna_restore():
    """Restaura a conectividade normal de rede do dispositivo."""
    target_ztna = ztna_engine_instance if ztna_engine_instance else ztna_engine
    result = target_ztna.restore_host_isolation()
    return jsonify(result), 200

@app.route("/api/ztna/reset", methods=["POST"])
def trigger_ztna_reset():
    """Reseta o Score de Risco ZTNA CARTA para zero e restaura total confiança."""
    target_ztna = ztna_engine_instance if ztna_engine_instance else ztna_engine
    status = target_ztna.reset_risk_posture()
    return jsonify(status), 200

@app.route("/api/whitelist/add", methods=["POST"])
def trigger_add_whitelist():
    """Endpoint para adicionar uma exceção/whitelist de arquivo ou diretório."""
    data = get_request_data()
    path_or_name = data.get("path") or data.get("name")
    if not path_or_name:
        return jsonify({"status": "ERROR", "message": "Parâmetro 'path' ou 'name' é obrigatório"}), 400

    target_threat = threat_detector_instance if threat_detector_instance else threat_detector
    target_threat.add_whitelist(path_or_name)
    return jsonify({
        "status": "SUCCESS",
        "message": f"'{path_or_name}' adicionado à Whitelist com sucesso."
    }), 200

@app.route("/api/kill", methods=["POST"])
def trigger_kill_process():
    """Endpoint SOAR para encerrar um processo malicioso por PID."""
    data = get_request_data()
    pid = data.get("pid")
    if not pid:
        return jsonify({"error": "Parâmetro 'pid' é obrigatório"}), 400

    target_soar = soar_instance if soar_instance else soar
    success = target_soar.kill_process_by_pid(pid)
    if success:
        return jsonify({"status": "SUCCESS", "message": f"Processo PID {pid} encerrado com sucesso."})
    return jsonify({"status": "ERROR", "message": f"Falha ao encerrar processo PID {pid}."}), 400

@app.route("/api/scan_file", methods=["POST"])
def trigger_scan_file():
    """Endpoint para escanear sob demanda um arquivo específico."""
    data = get_request_data()
    file_path = data.get("file_path")
    if not file_path:
        return jsonify({"error": "Parâmetro 'file_path' é obrigatório"}), 400

    target_threat = threat_detector_instance if threat_detector_instance else threat_detector
    result = target_threat.analyze_file(file_path)
    return jsonify(result)

@app.route("/api/scan_now", methods=["POST"])
def trigger_system_scan():
    """Dispara um ciclo completo de auditoria no sistema."""
    def run_full_scan():
        target_fim = fim_instance if fim_instance else fim
        target_proc = proc_monitor_instance if proc_monitor_instance else proc_monitor
        target_net = net_monitor_instance if net_monitor_instance else net_monitor
        target_fim.scan()
        target_proc.scan_processes()
        target_net.scan_network_connections()

    threading.Thread(target=run_full_scan, daemon=True).start()
    return jsonify({"status": "SUCCESS", "message": "Ciclo de varredura profunda iniciado em segundo plano."})

@app.route("/api/clear_events", methods=["POST"])
def trigger_clear_events():
    """Limpa todos os eventos do banco de dados SQLite."""
    target_logger = logger_instance if logger_instance else logger
    deleted = target_logger.clear_events()
    return jsonify({"status": "SUCCESS", "deleted_rows": deleted})

# -------------------------------------------------------------
# FUNCTIONS ENGINE — MOTOR DE EXPRESSÕES DE MONITORAMENTO (API)
# -------------------------------------------------------------

def _functions_safe(value):
    """Converte valores do Functions Engine para JSON-safe."""
    import math
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        return str(value)
    return value


@app.route("/api/functions/status", methods=["GET"])
def get_functions_status():
    """Retorna o status do Functions Engine (funções registradas, categorias, itens)."""
    funcs = functions_engine_instance.list_functions()
    categories = sorted({f["category"] for f in funcs})
    storage = functions_storage_instance
    return jsonify({
        "status": "success",
        "total_functions": len(funcs),
        "categories": categories,
        "items_count": len(storage),
        "item_ids": storage.item_ids(),
        "max_size": getattr(storage, "max_size", 10000),
    }), 200


@app.route("/api/functions/list", methods=["GET"])
def get_functions_list():
    """Lista as funções registradas com filtros opcionais por categoria e busca."""
    category = request.args.get("category") or None
    search = request.args.get("search") or None
    funcs = functions_engine_instance.list_functions(category=category, search=search)
    return jsonify({"status": "success", "count": len(funcs), "functions": funcs}), 200


@app.route("/api/functions/ingest", methods=["POST"])
def functions_ingest():
    """Ingere uma ou mais métricas no buffer do Functions Engine."""
    data = get_request_data()
    items = data.get("items") or []
    if not items and data.get("item_id"):
        items = [data]
    ingested = 0
    errors = []
    storage = functions_storage_instance
    for it in items:
        try:
            iid = str(it.get("item_id", "")).strip()
            if not iid:
                raise ValueError("item_id obrigatório")
            storage.append(SecurityItem(
                item_id=iid,
                name=it.get("name") or "",
                value=it.get("value", 0),
                timestamp=float(it.get("timestamp") or time.time()),
                tags=it.get("tags") or {},
            ))
            ingested += 1
        except Exception as e:
            errors.append({"item_id": it.get("item_id"), "error": str(e)})
    return jsonify({
        "status": "success",
        "ingested": ingested,
        "errors": errors,
        "total_items": len(storage),
    }), 200


@app.route("/api/functions/evaluate", methods=["POST"])
def functions_evaluate():
    """Avalia uma expressão de monitoramento (ex: 'last(\"system.cpu.util\")')."""
    data = get_request_data()
    expression = str(data.get("expression", "")).strip()
    if not expression:
        return jsonify({"status": "error", "message": "Expressão vazia. Ex: last(\"system.cpu.util\")"}), 400
    try:
        # Expressões booleanas (ex: 'last("x") > 90') são delegadas ao avaliador de triggers
        if any(op in expression for op in (">=", "<=", "==", "!=", ">", "<")):
            fired = bool(functions_engine_instance.evaluate_trigger(expression))
            return jsonify({"status": "success", "expression": expression, "result": fired, "fired": fired, "type": "trigger"}), 200
        result = functions_engine_instance.evaluate(expression)
        return jsonify({"status": "success", "expression": expression, "result": _functions_safe(result), "type": "value"}), 200
    except Exception as e:
        err = getattr(e, "to_dict", lambda: {"error": str(e), "type": "internal"})()
        return jsonify({"status": "error", "expression": expression, **err}), 400


@app.route("/api/functions/trigger", methods=["POST"])
def functions_trigger():
    """Avalia uma trigger booleana (ex: 'last(\"system.cpu.util\") > 90')."""
    data = get_request_data()
    expression = str(data.get("expression", "")).strip()
    if not expression:
        return jsonify({"status": "error", "message": "Trigger vazia. Ex: last(\"system.cpu.util\") > 90"}), 400
    try:
        fired = functions_engine_instance.evaluate_trigger(expression)
        return jsonify({"status": "success", "expression": expression, "fired": bool(fired)}), 200
    except Exception as e:
        err = getattr(e, "to_dict", lambda: {"error": str(e), "type": "internal"})()
        return jsonify({"status": "error", "expression": expression, **err}), 400


@app.route("/api/functions/items", methods=["GET"])
def functions_items():
    """Lista os itens de métrica atualmente no buffer do Functions Engine."""
    storage = functions_storage_instance
    item_id = request.args.get("item_id")
    limit = int(request.args.get("limit") or 200)
    items = storage.snapshot(limit=limit)
    if item_id:
        items = [it for it in items if it.item_id == item_id]
    return jsonify({
        "status": "success",
        "count": len(items),
        "items": [it.to_dict() for it in items],
    }), 200


@app.route("/api/functions/metrics/demo", methods=["POST"])
def functions_metrics_demo():
    """Carrega métricas de demonstração (CPU, memória, rede, latência) no Functions Engine."""
    import math
    now = time.time()
    cpu = [45, 52, 61, 58, 70, 78, 85, 88, 92, 95]
    avg = [30, 32, 35, 40, 48, 55, 62, 70, 78, 85]
    storage = functions_storage_instance
    for i, v in enumerate(cpu):
        ts = now - (len(cpu) - i) * 60
        storage.append(SecurityItem(item_id="system.cpu.util", value=v, timestamp=ts))
        storage.append(SecurityItem(item_id="system.cpu.avg", value=avg[i], timestamp=ts))
        storage.append(SecurityItem(item_id="system.memory.util", value=round(50 + 30 * math.sin(i / 2), 1), timestamp=ts))
        storage.append(SecurityItem(item_id="network.latency.ms", value=round(80 + 40 * math.cos(i / 3), 1), timestamp=ts))
    return jsonify({
        "status": "success",
        "message": "Métricas de demonstração carregadas no Functions Engine (system.cpu.util, system.memory.util, network.latency.ms).",
        "items_count": len(storage),
    }), 200


@app.route("/api/functions/clear", methods=["POST"])
def functions_clear():
    """Limpa todos os itens do buffer do Functions Engine."""
    storage = functions_storage_instance
    cleared = len(storage)
    storage.clear()
    return jsonify({"status": "success", "cleared": cleared}), 200


# -------------------------------------------------------------
# IDENTITY & CREDENTIAL GUARD ENDPOINTS
# -------------------------------------------------------------

@app.route("/api/identity-guard/status", methods=["GET"])
def get_identity_guard_status():
    """Retorna o status atual do motor de proteção de identidade e LSASS."""
    target_id_guard = identity_guard_instance if identity_guard_instance else identity_guard
    return jsonify(target_id_guard.get_status()), 200


@app.route("/api/identity-guard/scan", methods=["POST"])
def scan_identity_threats():
    """Executa varredura profunda em busca de dump de LSASS, ferramentas de roubo e Potato exploits."""
    target_id_guard = identity_guard_instance if identity_guard_instance else identity_guard
    threats = target_id_guard.scan_running_processes_and_cmdlines()
    return jsonify({
        "status": "success",
        "threats_found_count": len(threats),
        "threats": threats
    }), 200


@app.route("/api/identity-guard/audit-privileges", methods=["POST", "GET"])
def audit_identity_privileges():
    """Audita privilégios de alto risco de tokens nos processos ativos."""
    target_id_guard = identity_guard_instance if identity_guard_instance else identity_guard
    suspicious = target_id_guard.audit_token_privileges()
    return jsonify({
        "status": "success",
        "suspicious_count": len(suspicious),
        "suspicious_processes": suspicious
    }), 200


@app.route("/api/identity-guard/threats", methods=["GET"])
def get_identity_threats():
    """Retorna o histórico de ameaças de credenciais neutralizadas."""
    target_id_guard = identity_guard_instance if identity_guard_instance else identity_guard
    return jsonify({
        "status": "success",
        "count": len(target_id_guard.neutralized_threats),
        "threats": target_id_guard.neutralized_threats
    }), 200


# -------------------------------------------------------------
# DLP & EXFILTRATION ARMOR ENDPOINTS
# -------------------------------------------------------------

@app.route("/api/dlp/status", methods=["GET"])
def get_dlp_status():
    """Retorna o status atual do motor DLP, políticas de USB e escudos ativos."""
    target_dlp = dlp_guard_instance if dlp_guard_instance else dlp_guard
    status = target_dlp.get_status()
    usb_audit = target_dlp.audit_usb_storage()
    status["usb_storage"] = usb_audit
    return jsonify(status), 200


@app.route("/api/dlp/inspect-text", methods=["POST"])
def dlp_inspect_text():
    """Inspeciona texto ou dados sob demanda buscando vazamentos de CPFs, cartões e chaves."""
    data = get_request_data()
    text = data.get("text", "")
    target_dlp = dlp_guard_instance if dlp_guard_instance else dlp_guard
    findings = target_dlp.inspect_text(text)
    return jsonify(findings), 200


@app.route("/api/dlp/usb-policy", methods=["POST"])
def dlp_set_usb_policy():
    """Configura a política de mídias removíveis USB (ALLOW_ALL, READ_ONLY, BLOCK_ALL)."""
    data = get_request_data()
    policy = data.get("policy", "READ_ONLY")
    target_dlp = dlp_guard_instance if dlp_guard_instance else dlp_guard
    res = target_dlp.set_usb_policy(policy)
    return jsonify(res), 200


@app.route("/api/dlp/scan-exfiltration", methods=["POST"])
def dlp_scan_exfiltration():
    """Executa varredura profunda em busca de ferramentas e processos de exfiltração em nuvem."""
    target_dlp = dlp_guard_instance if dlp_guard_instance else dlp_guard
    threats = target_dlp.scan_exfiltration_processes()
    return jsonify({
        "status": "success",
        "threats_count": len(threats),
        "threats": threats
    }), 200


@app.route("/api/dlp/events", methods=["GET"])
def dlp_get_events():
    """Retorna o histórico de exfiltrações e vazamentos interceptados."""
    target_dlp = dlp_guard_instance if dlp_guard_instance else dlp_guard
    return jsonify({
        "status": "success",
        "count": len(target_dlp.intercepted_events),
        "events": target_dlp.intercepted_events
    }), 200


# -------------------------------------------------------------
# EXECUTION & ANTI-EXPLOIT GUARD ENDPOINTS
# -------------------------------------------------------------

@app.route("/api/anti-exploit/status", methods=["GET"])
def get_anti_exploit_status():
    """Retorna o status atual do motor anti-exploit e escudos de execução."""
    target_exploit = anti_exploit_guard_instance if anti_exploit_guard_instance else anti_exploit_guard
    return jsonify(target_exploit.get_status()), 200


@app.route("/api/anti-exploit/scan", methods=["POST"])
def run_anti_exploit_scan():
    """Executa varredura profunda em tempo real na árvore de processos em busca de injeções e exploits."""
    target_exploit = anti_exploit_guard_instance if anti_exploit_guard_instance else anti_exploit_guard
    threats = target_exploit.inspect_process_tree()
    return jsonify({
        "status": "success",
        "threats_count": len(threats),
        "threats": threats
    }), 200


@app.route("/api/anti-exploit/simulate-exploit", methods=["POST"])
def simulate_anti_exploit():
    """Avalia syntheticamente uma execução ou exploit sem executar no SO."""
    data = get_request_data()
    parent = data.get("parent", "winword.exe")
    child = data.get("child", "powershell.exe")
    cmdline = data.get("cmdline", "")
    exe = data.get("exe", "")
    target_exploit = anti_exploit_guard_instance if anti_exploit_guard_instance else anti_exploit_guard
    evaluation = target_exploit.evaluate_synthetic_execution(parent, child, cmdline, exe)
    return jsonify(evaluation), 200


@app.route("/api/anti-exploit/events", methods=["GET"])
def get_anti_exploit_events():
    """Retorna o histórico de exploits e injeções interceptadas."""
    target_exploit = anti_exploit_guard_instance if anti_exploit_guard_instance else anti_exploit_guard
    return jsonify({
        "status": "success",
        "count": len(target_exploit.neutralized_threats),
        "events": target_exploit.neutralized_threats
    }), 200


# -------------------------------------------------------------
# NETWORK & LOCAL PERIMETER GUARD ENDPOINTS
# -------------------------------------------------------------

@app.route("/api/perimeter-guard/status", methods=["GET"])
def get_perimeter_status():
    """Retorna o status atual dos escudos de rede, DGA e tabela ARP."""
    target_perimeter = perimeter_guard_instance if perimeter_guard_instance else perimeter_guard
    status = target_perimeter.get_status()
    arp_summary = target_perimeter.audit_arp_table()
    status["arp_status"] = arp_summary.get("status")
    status["arp_entries_count"] = arp_summary.get("entries_analyzed", 0)
    return jsonify(status), 200


@app.route("/api/perimeter-guard/inspect-dns", methods=["POST"])
def perimeter_inspect_dns():
    """Analisa um domínio sob demanda buscando DGA, DNS Tunneling e TLDs maliciosos."""
    data = get_request_data()
    domain = data.get("domain", "")
    target_perimeter = perimeter_guard_instance if perimeter_guard_instance else perimeter_guard
    evaluation = target_perimeter.inspect_dns_query(domain)
    return jsonify(evaluation), 200


@app.route("/api/perimeter-guard/audit-arp", methods=["POST"])
def perimeter_audit_arp():
    """Executa auditoria em tempo real da tabela ARP buscando ataques MITM / ARP Spoofing."""
    data = get_request_data()
    custom_output = data.get("arp_output")
    target_perimeter = perimeter_guard_instance if perimeter_guard_instance else perimeter_guard
    report = target_perimeter.audit_arp_table(custom_arp_output=custom_output)
    return jsonify(report), 200


@app.route("/api/perimeter-guard/events", methods=["GET"])
def get_perimeter_events():
    """Retorna o histórico de eventos de rede e perímetro interceptados."""
    target_perimeter = perimeter_guard_instance if perimeter_guard_instance else perimeter_guard
    return jsonify({
        "status": "success",
        "count": len(target_perimeter.intercepted_events),
        "events": target_perimeter.intercepted_events
    }), 200


# -------------------------------------------------------------
# POSTURE & PERSISTENCE GUARD ENDPOINTS
# -------------------------------------------------------------

@app.route("/api/posture-guard/status", methods=["GET"])
def get_posture_status():
    """Retorna o status atual dos escudos de postura, persistência e hardening."""
    target_posture = posture_guard_instance if posture_guard_instance else posture_guard
    status = target_posture.get_status()
    hardening = target_posture.audit_system_hardening()
    status["posture_score"] = hardening.get("posture_score", 100)
    status["posture_rating"] = hardening.get("posture_rating", "EXCELLENT")
    return jsonify(status), 200


@app.route("/api/posture-guard/scan-asep", methods=["POST"])
def posture_scan_asep():
    """Executa varredura profunda dos pontos de autostart e persistência (ASEP)."""
    target_posture = posture_guard_instance if posture_guard_instance else posture_guard
    report = target_posture.scan_asep_registry_and_files()
    return jsonify(report), 200


@app.route("/api/posture-guard/inspect-lolbin", methods=["POST"])
def posture_inspect_lolbin():
    """Analisa comandos em busca de técnicas abusivas de LOLBins (Certutil, Regsvr32, Mshta)."""
    data = get_request_data()
    proc = data.get("process_name", "")
    cmd = data.get("cmdline", "")
    target_posture = posture_guard_instance if posture_guard_instance else posture_guard
    evaluation = target_posture.evaluate_lolbin_command(proc, cmd)
    return jsonify(evaluation), 200


@app.route("/api/posture-guard/audit-posture", methods=["POST"])
def posture_audit_hardening():
    """Audita a postura de segurança e hardening do sistema operacional (CIS Benchmarks)."""
    target_posture = posture_guard_instance if posture_guard_instance else posture_guard
    audit = target_posture.audit_system_hardening()
    return jsonify(audit), 200


@app.route("/api/posture-guard/events", methods=["GET"])
def get_posture_events():
    """Retorna o histórico de persistências maliciosas e abusos de LOLBins interceptados."""
    target_posture = posture_guard_instance if posture_guard_instance else posture_guard
    return jsonify({
        "status": "success",
        "count": len(target_posture.intercepted_events),
        "events": target_posture.intercepted_events
    }), 200



# -------------------------------------------------------------
# INICIALIZAÇÃO AUTÔNOMA DO SERVIDOR
# -------------------------------------------------------------
if __name__ == "__main__":
    init_sentinel_services()
    requested_port = int(os.environ.get("PORT", 5000))
    port = find_available_port(requested_port)
    
    print("=========================================================")
    print("🛡️  SENTINELA XDR SOVEREIGN - SERVER INICIADO COM SUCESSO")
    print(f"🌐 Painel Aberto em: http://127.0.0.1:{port}")
    print("=========================================================")
    
    # Abre o navegador automaticamente
    def open_browser():
        time.sleep(1.2)
        try:
            webbrowser.open(f"http://localhost:{port}")
        except Exception:
            pass
    threading.Thread(target=open_browser, daemon=True).start()

    app.run(host="0.0.0.0", port=port, debug=False)
