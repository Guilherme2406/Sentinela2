"""
Sentinela XDR - Guardião de Varredura e Proteção Autônoma Contínua (Threat Watchdog Daemon)
Executa em thread contínua de segundo plano:
1. Auditoria periódica de memória virtual RWX de processos críticos (MemoryRWXHunter).
2. Cruzamento automático de conexões de rede ativas contra a base global STIX 2.1 / MISP.
3. Despacho automático de incidentes para o SOAR e Webhooks Notifier.
"""

import time
import threading
import psutil
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("SentinelaThreatWatchdog")


class ThreatWatchdogDaemon:
    """Daemon autônomo que coordena a varredura contínua e correlação ativa de ameaças."""

    def __init__(self, rwx_hunter, stix_engine, vss_shield, amsi_guard, notifier=None, soar_engine=None, logger_instance=None, honeyfiles_guard=None, cloud_k8s=None, hook_guard=None, token_armor=None, reverse_shell=None, c2_hunter=None, portscan_disruptor=None, byovd_guard=None, anti_hollowing_guard=None, lsass_guard=None, **kwargs):
        self.rwx_hunter = rwx_hunter
        self.stix_engine = stix_engine
        self.vss_shield = vss_shield
        self.amsi_guard = amsi_guard
        self.notifier = notifier
        self.soar_engine = soar_engine
        self.logger = logger_instance
        self.honeyfiles_guard = honeyfiles_guard
        self.cloud_k8s = cloud_k8s
        self.hook_guard = hook_guard
        self.token_armor = token_armor
        self.reverse_shell = reverse_shell
        self.c2_hunter = c2_hunter
        self.portscan_disruptor = portscan_disruptor
        self.byovd_guard = byovd_guard
        self.anti_hollowing_guard = anti_hollowing_guard
        self.lsass_guard = lsass_guard

        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.cycle_interval: int = 45  # Intervalo de 45 segundos por ciclo
        self.total_cycles: int = 0
        self.last_cycle_time: float = 0.0
        self.threats_intercepted: int = 0
        self.active_c2_connections: List[Dict[str, Any]] = []

    def _log(self, level: str, category: str, action: str, msg: str):
        try:
            if self.logger and hasattr(self.logger, "log_event"):
                self.logger.log_event(level, category, action, msg)
            elif self.logger and hasattr(self.logger, level.lower()):
                getattr(self.logger, level.lower())(f"[{category}] {msg}")
        except Exception:
            pass
        logging.info(f"[{category}] {msg}")

    def start(self):
        """Inicia o daemon autônomo em segundo plano."""
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._run_loop, daemon=True, name="SentinelaThreatWatchdog")
        self.thread.start()
        self._log("INFO", "WATCHDOG_DAEMON", "STARTED", f"Guardião Autônomo ativo (ciclos de {self.cycle_interval}s).")

    def stop(self):
        """Finaliza o daemon autônomo."""
        self.running = False

    def _run_loop(self):
        """Loop contínuo de varredura e correlação."""
        # Pequeno atraso na inicialização para estabilizar o servidor
        time.sleep(5)
        while self.running:
            try:
                self.execute_single_cycle()
            except Exception as e:
                self._log("WARNING", "WATCHDOG_DAEMON", "CYCLE_ERROR", f"Erro no ciclo do guardião: {e}")
            
            # Aguarda próximo ciclo com verificação suave de parada
            for _ in range(self.cycle_interval):
                if not self.running:
                    break
                time.sleep(1)

    def execute_single_cycle(self) -> Dict[str, Any]:
        """Executa um ciclo completo de auditoria e correlação ativa."""
        self.total_cycles += 1
        self.last_cycle_time = time.time()
        cycle_findings = []

        # 1. Auditoria de Conexões de Rede Ativas contra a Base STIX 2.1
        try:
            active_conns = psutil.net_connections(kind='inet')
            for conn in active_conns:
                if conn.raddr and conn.raddr.ip:
                    remote_ip = conn.raddr.ip
                    # Ignorar endereços locais e de loopback
                    if remote_ip.startswith("127.") or remote_ip.startswith("192.168.") or remote_ip.startswith("10.") or remote_ip == "::1":
                        continue
                    
                    # Consultar na base STIX
                    match = self.stix_engine.lookup_ioc(remote_ip)
                    if match:
                        self.threats_intercepted += 1
                        finding = {
                            "type": "C2_NETWORK_CONNECTION",
                            "ip": remote_ip,
                            "port": conn.raddr.port,
                            "pid": conn.pid,
                            "threat_name": match["indicator"].get("name", "Unknown C2")
                        }
                        cycle_findings.append(finding)
                        self.active_c2_connections.insert(0, finding)
                        if len(self.active_c2_connections) > 20:
                            self.active_c2_connections.pop()

                        self._log(
                            "CRITICAL",
                            "WATCHDOG_ALERT",
                            "C2_DETECTED",
                            f"ALERTA CRÍTICO! Conexão tática com nó C2 detectada: {remote_ip}:{conn.raddr.port} (PID: {conn.pid}) - {match['indicator'].get('name')}"
                        )

                        if self.notifier and hasattr(self.notifier, "dispatch_incident_alert"):
                            self.notifier.dispatch_incident_alert(
                                title=f"C2 Detectado: {match['indicator'].get('name')}",
                                details=f"O host estabeleceu conexão com {remote_ip}:{conn.raddr.port} (PID: {conn.pid}).",
                                severity="CRITICAL",
                                metadata=finding
                            )
        except Exception:
            pass

        # 2. Auditoria de Memória de Processos com RWX Hunter
        try:
            rwx_res = self.rwx_hunter.scan_all_critical_processes()
            if rwx_res.get("threats_found", 0) > 0:
                self.threats_intercepted += rwx_res["threats_found"]
                cycle_findings.append({
                    "type": "RWX_UNBACKED_MEMORY",
                    "threats_count": rwx_res["threats_found"]
                })
        except Exception:
            pass

        # 3. Auditoria de Iscas Anti-Ransomware (Honeyfiles)
        if self.honeyfiles_guard and hasattr(self.honeyfiles_guard, "check_integrity"):
            try:
                hf_res = self.honeyfiles_guard.check_integrity()
                if hf_res.get("has_threat"):
                    self.threats_intercepted += hf_res.get("compromised_count", 1)
                    cycle_findings.append({
                        "type": "HONEYFILE_RANSOMWARE_TAMPER",
                        "compromised": hf_res.get("compromised_files", [])
                    })
            except Exception:
                pass

        # 4. Auditoria de Integridade de Hooks e Defesa Anti-Unhooking
        if self.hook_guard and hasattr(self.hook_guard, "audit_memory_hooks"):
            try:
                hook_res = self.hook_guard.audit_memory_hooks()
                if hook_res:
                    self.threats_intercepted += len(hook_res)
                    cycle_findings.append({
                        "type": "EDR_HOOK_TAMPER",
                        "tampered_functions": [h.get("function") for h in hook_res]
                    })
            except Exception:
                pass

        # 5. Auditoria de Abuso de Tokens e Exploits Potato
        if self.token_armor and hasattr(self.token_armor, "audit_running_processes_tokens"):
            try:
                token_res = self.token_armor.audit_running_processes_tokens()
                if token_res:
                    self.threats_intercepted += len(token_res)
                    cycle_findings.append({
                        "type": "TOKEN_ARMOR_POTATO_VIOLATION",
                        "processes": [t.get("process_name") for t in token_res]
                    })
            except Exception:
                pass

        # 6. Auditoria de Reverse Shells Interativos
        if self.reverse_shell and hasattr(self.reverse_shell, "scan_for_reverse_shells"):
            try:
                shell_res = self.reverse_shell.scan_for_reverse_shells()
                if shell_res:
                    self.threats_intercepted += len(shell_res)
                    cycle_findings.append({
                        "type": "INTERACTIVE_REVERSE_SHELL",
                        "intercepted_pids": [s.get("pid") for s in shell_res]
                    })
            except Exception:
                pass

        # 7. Auditoria de C2 Beaconing e Jitter
        if self.c2_hunter and hasattr(self.c2_hunter, "analyze_beaconing_patterns"):
            try:
                c2_findings = self.c2_hunter.analyze_beaconing_patterns()
                if c2_findings:
                    self.threats_intercepted += len(c2_findings)
                    cycle_findings.append({
                        "type": "C2_BEACONING_PATTERN",
                        "beacons": c2_findings
                    })
            except Exception:
                pass

        # 8. Auditoria de BYOVD e Drivers Vulneráveis em Kernel
        if self.byovd_guard and hasattr(self.byovd_guard, "audit_installed_services_registry"):
            try:
                byovd_threats = self.byovd_guard.audit_installed_services_registry()
                if byovd_threats:
                    self.threats_intercepted += len(byovd_threats)
                    cycle_findings.append({
                        "type": "BYOVD_VULNERABLE_DRIVER",
                        "drivers": byovd_threats
                    })
            except Exception:
                pass

        # 9. Auditoria de Process Hollowing e Masquerading
        if self.anti_hollowing_guard and hasattr(self.anti_hollowing_guard, "scan_system_processes_integrity"):
            try:
                hollow_threats = self.anti_hollowing_guard.scan_system_processes_integrity()
                if hollow_threats:
                    self.threats_intercepted += len(hollow_threats)
                    cycle_findings.append({
                        "type": "PROCESS_HOLLOWING_DETECTED",
                        "anomalies": hollow_threats
                    })
            except Exception:
                pass

        # 10. Auditoria de Acesso e Extração de Memória do LSASS
        if self.lsass_guard and hasattr(self.lsass_guard, "audit_lsass_access"):
            try:
                lsass_threats = self.lsass_guard.audit_lsass_access()
                if lsass_threats:
                    self.threats_intercepted += len(lsass_threats)
                    cycle_findings.append({
                        "type": "LSASS_ACCESS_ATTEMPT",
                        "events": lsass_threats
                    })
            except Exception:
                pass

        return {
            "status": "success",
            "cycle": self.total_cycles,
            "timestamp": self.last_cycle_time,
            "findings_count": len(cycle_findings),
            "findings": cycle_findings
        }

    def get_status(self) -> Dict[str, Any]:
        """Retorna o status operacional do daemon guardião."""
        return {
            "status": "active" if self.running else "stopped",
            "total_cycles": self.total_cycles,
            "last_cycle_time": self.last_cycle_time,
            "cycle_interval_seconds": self.cycle_interval,
            "threats_intercepted": self.threats_intercepted,
            "active_c2_connections": self.active_c2_connections[:10]
        }
