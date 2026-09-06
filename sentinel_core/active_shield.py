# sentinel_core/active_shield.py
import os
import logging
from typing import Dict, Any, List
from sentinel_core.logger import SecurityEventLogger
from sentinel_core.ip_geolocator import IPGeolocator
from sentinel_core.threat_detector import ThreatDetector
from sentinel_core.auto_response import AutoResponseEngine

class ActiveShield:
    """
    Rede de Proteção Avançada de Nível Superior (Superior Level Shield).
    Controla o Bloqueio de Entrada (Anti-Malware Gatekeeper) e de Saída (DLP Exfiltration Prevention).
    """

    def __init__(self, logger: SecurityEventLogger = None, threat_detector: ThreatDetector = None, soar: AutoResponseEngine = None, geolocator: IPGeolocator = None):
        self.logger = logger
        self.threat_detector = threat_detector
        self.soar = soar
        self.geolocator = geolocator or IPGeolocator()

        # Chaves de Ativação (Toggles de Proteção Ativa)
        self.inbound_protection_enabled = True   # Bloqueio de arquivos/programas maliciosos (Entrada)
        self.outbound_dlp_enabled = True         # Prevenção de vazamento/saída de dados não autorizados (Saída)
        self.shield_level = "SUPERIOR"

    @property
    def inbound_malware_protection(self) -> bool:
        return self.inbound_protection_enabled

    @inbound_malware_protection.setter
    def inbound_malware_protection(self, value: bool):
        self.inbound_protection_enabled = bool(value)

    @property
    def anti_malware_enabled(self) -> bool:
        return self.inbound_protection_enabled

    @anti_malware_enabled.setter
    def anti_malware_enabled(self, value: bool):
        self.inbound_protection_enabled = bool(value)

    @property
    def dlp_enabled(self) -> bool:
        return self.outbound_dlp_enabled

    @dlp_enabled.setter
    def dlp_enabled(self, value: bool):
        self.outbound_dlp_enabled = bool(value)

    def get_config(self) -> Dict[str, Any]:
        """Retorna o status atual dos módulos de proteção."""
        return {
            "shield_level": self.shield_level,
            "inbound_malware_protection": self.inbound_protection_enabled,
            "outbound_dlp_protection": self.outbound_dlp_enabled,
            "anti_malware_enabled": self.inbound_protection_enabled,
            "dlp_enabled": self.outbound_dlp_enabled
        }

    def set_config(self, inbound: bool = None, outbound: bool = None) -> Dict[str, Any]:
        """Atualiza os toggles de controle de entrada e saída."""
        if inbound is not None:
            self.inbound_protection_enabled = bool(inbound)
            status = "ATIVADO" if self.inbound_protection_enabled else "DESATIVADO"
            if self.logger:
                self.logger.log_event("WARNING", "SHIELD", "INBOUND_TOGGLE", f"Bloqueio de Entrada de Arquivos Maliciosos {status}.")
            
        if outbound is not None:
            self.outbound_dlp_enabled = bool(outbound)
            status = "ATIVADO" if self.outbound_dlp_enabled else "DESATIVADO"
            if self.logger:
                self.logger.log_event("WARNING", "SHIELD", "OUTBOUND_TOGGLE", f"Proteção contra Saída de Dados (DLP) {status}.")


        return self.get_config()

    def inspect_inbound_file(self, file_path: str, source_ip: str = "127.0.0.1") -> Dict[str, Any]:
        """
        Mapeia e Intercepta novos arquivos que tentam entrar no sistema.
        Se a proteção de entrada estiver ATIVADA e o arquivo for malicioso, impede a entrada enviando para Quarentena imediata.
        """
        threat = self.threat_detector.scan_file(file_path)
        geo_data = self.geolocator.locate_ip(source_ip)

        is_threat = threat.get("status") in ("MALWARE_DETECTED", "SUSPICIOUS") or threat.get("is_threat", False)
        details = threat.get("description") or threat.get("details") or threat.get("reason", "Scan concluído")

        assessment = {
            "file_path": file_path,
            "is_threat": is_threat,
            "details": details,
            "geo_info": geo_data,
            "action_taken": "NONE"
        }

        if is_threat:
            log_msg = (f"Ameaça de Entrada detectada no arquivo '{file_path}'. "
                       f"Origem: {geo_data['country']} ({geo_data['city']}) - IP: {source_ip}")
            
            if self.inbound_protection_enabled:
                logging.warning(f"[ACTIVE SHIELD] 🛑 INBOUND BLOCKED: Isolando '{file_path}'!")
                self.soar.quarantine_file(file_path, f"Bloqueio Ativo Inbound | {details}")
                assessment["action_taken"] = "BLOCKED_AND_QUARANTINED"
                self.logger.log_event("CRITICAL", "ACTIVE_SHIELD", "INBOUND_BLOCKED", log_msg)
            else:
                logging.info("[ACTIVE SHIELD] ⚠️ INBOUND DETECTED (Modo Apenas Alerta): Arquivo mantido.")
                assessment["action_taken"] = "ALERT_ONLY"
                self.logger.log_event("HIGH", "ACTIVE_SHIELD", "INBOUND_ALERT", log_msg)

        return assessment


    def inspect_outbound_traffic(self, remote_ip: str, remote_port: int, pid: int, process_name: str) -> Dict[str, Any]:
        """
        Mapeia e Intercepta tráfego de saída (DLP / Exfiltração).
        Se a proteção de saída estiver ATIVADA e o destino/processo for suspeito, encerra a conexão/processo.
        """
        geo_data = self.geolocator.locate_ip(remote_ip)
        
        # Exemplo de verificação de DLP: Conexões de saída não autorizadas para portas críticas ou países sem reputação
        is_suspicious_outbound = remote_port in {4444, 5555, 6667, 1337, 31337} or (not geo_data["is_local"] and remote_port not in {80, 443})

        assessment = {
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "pid": pid,
            "process_name": process_name,
            "geo_info": geo_data,
            "is_suspicious": is_suspicious_outbound,
            "action_taken": "NONE"
        }

        if is_suspicious_outbound:
            log_msg = (f"Tentativa de Saída de Dados (DLP) Suspeita! Processo: {process_name} (PID {pid}) -> "
                       f"Destino: {remote_ip}:{remote_port} [{geo_data['country']} - {geo_data['isp']}]")

            if self.outbound_dlp_enabled:
                logging.warning(f"[ACTIVE SHIELD] 🛑 OUTBOUND DLP BLOCKED: Matando processo emissor {process_name} (PID {pid})!")
                self.soar.kill_process(pid, f"DLP Outbound Block | IP {remote_ip}:{remote_port}")
                assessment["action_taken"] = "BLOCKED_AND_KILLED"
                self.logger.log_event("CRITICAL", "ACTIVE_SHIELD", "OUTBOUND_BLOCKED", log_msg)
            else:
                logging.info("[ACTIVE SHIELD] ⚠️ OUTBOUND DETECTED (Modo Apenas Alerta): Conexão permitida.")
                assessment["action_taken"] = "ALERT_ONLY"
                self.logger.log_event("HIGH", "ACTIVE_SHIELD", "OUTBOUND_ALERT", log_msg)

        return assessment

ActiveShieldDLP = ActiveShield

