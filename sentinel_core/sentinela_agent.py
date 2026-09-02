# sentinel_core/sentinela_agent.py
import os
import sys
import time
import hashlib
import platform
import asyncio
import logging
from typing import Dict, List, Any, Set, Optional
from datetime import datetime
from dataclasses import dataclass, field

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

from sentinel_core.sentinela_orchestrator import SentinelaOrchestrator, SecurityEvent
from sentinel_core.identity_credential_guard import IdentityCredentialGuard
from sentinel_core.dlp_exfiltration_guard import DLPExfiltrationGuard
from sentinel_core.execution_anti_exploit_guard import ExecutionAntiExploitGuard
from sentinel_core.network_perimeter_guard import NetworkPerimeterGuard
from sentinel_core.posture_persistence_guard import PosturePersistenceGuard

logger = logging.getLogger("SentinelaXDR.Agent")

@dataclass
class ProcessSnapshot:
    """Snapshot detalhado de um processo em execução."""
    pid: int
    name: str
    exe_path: str
    cpu_percent: float
    memory_percent: float
    connections: int
    status: str

@dataclass
class FileIntegrityRecord:
    """Registro de integridade criptográfica de arquivo crítico."""
    path: str
    sha256: str
    size: int
    last_modified: float

class SentinelaAgent:
    """
    Agente Unificado de Coleta de Telemetria e Sensores de Endpoint (Sentinela Endpoint Agent).
    Monitora continuamente processos, conexões de rede, arquivos críticos de sistema e rajadas de I/O,
    transmitindo eventos estruturados em tempo real para o SentinelaOrchestrator.
    """

    def __init__(
        self,
        agent_id: Optional[str] = None,
        poll_interval: float = 4.0,
        orchestrator: Optional[SentinelaOrchestrator] = None,
        watched_paths: Optional[List[str]] = None,
        critical_files: Optional[List[str]] = None,
        max_file_changes_threshold: int = 35,
        identity_guard: Optional[IdentityCredentialGuard] = None,
        dlp_guard: Optional[DLPExfiltrationGuard] = None,
        anti_exploit_guard: Optional[ExecutionAntiExploitGuard] = None,
        perimeter_guard: Optional[NetworkPerimeterGuard] = None,
        posture_guard: Optional[PosturePersistenceGuard] = None
    ):
        self.agent_id = agent_id or f"node-{platform.node()}"
        self.poll_interval = poll_interval
        self.orchestrator = orchestrator
        self.watched_paths = watched_paths or [os.path.abspath(".")]
        self.critical_files = critical_files or self._get_default_critical_files()
        self.max_file_changes_threshold = max_file_changes_threshold
        self.identity_guard = identity_guard or IdentityCredentialGuard(orchestrator=self.orchestrator)
        self.dlp_guard = dlp_guard or DLPExfiltrationGuard(orchestrator=self.orchestrator)
        self.anti_exploit_guard = anti_exploit_guard or ExecutionAntiExploitGuard(orchestrator=self.orchestrator)
        self.perimeter_guard = perimeter_guard or NetworkPerimeterGuard(orchestrator=self.orchestrator)
        self.posture_guard = posture_guard or PosturePersistenceGuard(orchestrator=self.orchestrator)

        # Estado interno de telemetria
        self.known_processes: Set[int] = set()
        self.file_baselines: Dict[str, FileIntegrityRecord] = {}
        self.file_change_counter: int = 0
        self.known_connections: Set[str] = set()
        self.running: bool = False
        self.event_callback = None

        self._build_critical_files_baseline()
        logger.info(f"🛡️ [AGENT] Agente '{self.agent_id}' ativo monitorando {len(self.file_baselines)} arquivos críticos.")

    def _get_default_critical_files(self) -> List[str]:
        """Identifica arquivos essenciais do sistema operacional para monitoramento de integridade."""
        system = platform.system()
        if system == "Windows":
            return [
                "C:\\Windows\\System32\\drivers\\etc\\hosts",
                "C:\\Windows\\System32\\config\\SAM",
                "C:\\Windows\\System32\\config\\SYSTEM",
                os.path.abspath("sentinel.key"),
                os.path.abspath("dashboard.html")
            ]
        else:
            return [
                "/etc/passwd",
                "/etc/shadow",
                "/etc/sudoers",
                "/etc/hosts",
                "/etc/ssh/sshd_config"
            ]

    def set_event_callback(self, callback):
        """Registra callback alternativo para encaminhamento de eventos."""
        self.event_callback = callback

    def _emit_event(self, source: str, severity: str, data: Dict[str, Any]):
        """Emite evento padronizado para o Orquestrador e eventuais callbacks."""
        event = SecurityEvent(
            source=source,
            severity=severity,
            data={"agent_id": self.agent_id, **data}
        )

        if self.orchestrator:
            self.orchestrator.emit(event)

        if self.event_callback:
            try:
                if asyncio.iscoroutinefunction(self.event_callback):
                    asyncio.create_task(self.event_callback(event))
                else:
                    self.event_callback(event)
            except Exception as ex:
                logger.debug(f"Erro no callback do agente: {ex}")

    def _calculate_sha256(self, filepath: str) -> Optional[str]:
        """Calcula o hash SHA-256 de um arquivo de forma segura."""
        if not os.path.exists(filepath) or not os.path.isfile(filepath):
            return None
        try:
            hasher = hashlib.sha256()
            with open(filepath, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return None

    def _build_critical_files_baseline(self):
        """Constrói a baseline inicial dos arquivos críticos."""
        for path in self.critical_files:
            if os.path.exists(path) and os.path.isfile(path):
                h = self._calculate_sha256(path)
                if h:
                    try:
                        stat = os.stat(path)
                        self.file_baselines[path] = FileIntegrityRecord(
                            path=path,
                            sha256=h,
                            size=stat.st_size,
                            last_modified=stat.st_mtime
                        )
                    except Exception:
                        pass

    # ── MÓDULO 1: Varredura de Processos e Conexões ──
    def scan_processes(self) -> List[ProcessSnapshot]:
        """Varre processos ativos e detecta novos processos ou conexões anômalas (C2 Floods)."""
        snapshots = []
        if not HAS_PSUTIL:
            return snapshots

        current_pids = set()
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent', 'memory_percent', 'status']):
            try:
                info = proc.info
                pid = info.get('pid')
                if not pid or pid == 0:
                    continue

                current_pids.add(pid)
                name = info.get('name') or "Desconhecido"
                exe = info.get('exe') or ""

                conns_count = 0
                try:
                    conns = proc.net_connections(kind='inet')
                    conns_count = len(conns)
                except Exception:
                    pass

                snap = ProcessSnapshot(
                    pid=pid,
                    name=name,
                    exe_path=exe,
                    cpu_percent=float(info.get('cpu_percent') or 0.0),
                    memory_percent=float(info.get('memory_percent') or 0.0),
                    connections=conns_count,
                    status=str(info.get('status') or "running")
                )
                snapshots.append(snap)

                # Detecção de novos processos hostis
                if self.known_processes and pid not in self.known_processes:
                    if name.lower().endswith(('.exe', '.bat', '.ps1', '.vbs', '.cmd')):
                        self._emit_event(
                            source="AGENT_PROCESS",
                            severity="LOW",
                            data={"msg": f"Novo processo iniciado: {name} (PID: {pid})", "exe": exe, "connections": conns_count}
                        )

                # Detecção de processo com conexões excessivas (C2 Botnet / Port Flood)
                if conns_count > 25 and name.lower() not in ["chrome.exe", "msedge.exe", "firefox.exe", "discord.exe", "spotify.exe"]:
                    self._emit_event(
                        source="AGENT_NETWORK",
                        severity="HIGH",
                        data={"msg": f"Alerta de C2/Beacon: Processo '{name}' com {conns_count} conexões ativas", "pid": pid}
                    )

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        self.known_processes = current_pids
        return snapshots

    # ── MÓDULO 2: Varredura de Integridade de Arquivos Críticos ──
    def scan_critical_files(self) -> List[Dict[str, Any]]:
        """Verifica se arquivos vitais do SO ou do Sentinela foram adulterados."""
        tampered_files = []
        for path, baseline in self.file_baselines.items():
            if not os.path.exists(path):
                tampered_files.append({"path": path, "type": "DELETED"})
                self._emit_event(
                    source="AGENT_FIM",
                    severity="CRITICAL",
                    data={"msg": f"Arquivo crítico DELETADO: {path}", "path": path}
                )
                continue

            current_hash = self._calculate_sha256(path)
            if current_hash and current_hash != baseline.sha256:
                tampered_files.append({"path": path, "type": "MODIFIED", "old_hash": baseline.sha256, "new_hash": current_hash})
                self._emit_event(
                    source="AGENT_FIM",
                    severity="CRITICAL",
                    data={"msg": f"Adulteração em arquivo crítico detectada: {path}", "path": path}
                )

        return tampered_files

    # ── MÓDULO 3: Varredura de Conexões de Rede ──
    def scan_network_connections(self) -> List[Dict[str, Any]]:
        """Inspeciona conexões ativas na interface de rede."""
        anomalies = []
        if not HAS_PSUTIL:
            return anomalies

        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    conn_id = f"{remote_ip}:{remote_port}"

                    # Flag de portas perigosas conhecidas
                    if remote_port in [4444, 5555, 6666, 1337, 31337]:
                        anomalies.append({"remote_ip": remote_ip, "port": remote_port, "pid": conn.pid})
                        self._emit_event(
                            source="AGENT_NETWORK",
                            severity="CRITICAL",
                            data={"msg": f"Conexão para porta de backdoor conhecida: {remote_ip}:{remote_port}", "pid": conn.pid}
                        )
        except Exception:
            pass

        return anomalies

    # ── MÓDULO 4: Ciclo de Auditoria do Agente ──
    def run_cycle(self) -> Dict[str, Any]:
        """Executa um ciclo completo de auditoria do Agente."""
        procs = self.scan_processes()
        tampered = self.scan_critical_files()
        net_anomalies = self.scan_network_connections()
        credential_threats = self.identity_guard.scan_running_processes_and_cmdlines() if self.identity_guard else []
        dlp_threats = self.dlp_guard.scan_exfiltration_processes() if self.dlp_guard else []
        exploit_threats = self.anti_exploit_guard.inspect_process_tree() if self.anti_exploit_guard else []
        arp_audit = self.perimeter_guard.audit_arp_table() if self.perimeter_guard else {}
        asep_scan = self.posture_guard.scan_asep_registry_and_files() if self.posture_guard else {}

        return {
            "agent_id": self.agent_id,
            "timestamp": time.time(),
            "active_processes_count": len(procs),
            "tampered_critical_files": tampered,
            "network_anomalies": net_anomalies,
            "credential_threats_detected": len(credential_threats),
            "dlp_exfiltrations_detected": len(dlp_threats),
            "anti_exploit_threats_detected": len(exploit_threats),
            "arp_mitm_detected": arp_audit.get("status") == "MITM_ATTACK_DETECTED",
            "persistence_threats_detected": asep_scan.get("threats_count", 0)
        }

    async def run(self):
        """Loop contínuo assíncrono do Agente."""
        self.running = True
        logger.info(f"🚀 [AGENT] Loop de telemetria ativo (Intervalo: {self.poll_interval}s).")
        while self.running:
            try:
                self.run_cycle()
            except Exception as ex:
                logger.error(f"[AGENT ERROR] Falha no ciclo de telemetria: {ex}")
            await asyncio.sleep(self.poll_interval)

    def stop(self):
        self.running = False
