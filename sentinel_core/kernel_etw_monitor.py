# sentinel_core/kernel_etw_monitor.py
import logging
import re
from typing import Dict, Any, Optional, List

logger = logging.getLogger("SentinelaXDR.KernelETW")

class ETWKernelMonitor:
    """
    Monitorador de Kernel nativo via Event Tracing for Windows (ETW / Sysmon).
    Captura Injeção de Processos, Persistência no Registro/Schtasks e Conexões Suspeitas via Rundll32.
    """
    
    # Chaves de registro monitoradas para persistência
    PERSISTENCE_REG_KEYS = [
        r"software\microsoft\windows\currentversion\run",
        r"software\microsoft\windows\currentversion\runonce",
        r"system\currentcontrolset\services"
    ]
    
    # Binários de Living-off-the-Land (LOLBins) para monitorar rede
    LOLBINS = ["rundll32.exe", "regsvr32.exe", "certutil.exe", "mshta.exe", "powershell.exe"]

    def __init__(self):
        self.running = True
        logger.info("🛡️ Motor ETW Kernel Monitor inicializado com sucesso.")

    def process_etw_event(self, event_provider: str, event_id: int, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Analisa eventos em tempo real do barramento ETW.
        """
        # --- 1. DETECÇÃO DE PROCESS HOLLOWING / INJECTION (Sysmon Event ID 8/10) ---
        if event_id in [8, 10] or event_provider == "Microsoft-Windows-Kernel-Process":
            source_pid = payload.get("source_pid")
            target_pid = payload.get("target_pid")
            granted_access = payload.get("granted_access", "")
            target_image = str(payload.get("target_image", "")).lower()
            
            # Se um processo não assinado ou externo tenta injetar em processos críticos do Windows
            if target_image.endswith(("lsass.exe", "svchost.exe", "explorer.exe", "winlogon.exe")):
                if "0x1f0fff" in str(granted_access).lower() or payload.get("call_stack_suspicious"):
                    return {
                        "alert_type": "PROCESS_INJECTION_DETECTED",
                        "mitre_id": "T1055.012",
                        "mitre_tactic": "Defense Evasion / Privilege Escalation",
                        "severity": "CRÍTICO",
                        "description": f"Tentativa de Process Hollowing/Injeção no processo crítico '{target_image}' (Target PID: {target_pid}) a partir do PID {source_pid}.",
                        "details": payload
                    }

        # --- 2. DETECÇÃO DE PERSISTÊNCIA NO REGISTRO E TAREFAS AGENDADAS (Event ID 12/13/1) ---
        if event_id in [12, 13]: # Registry Modification
            target_object = str(payload.get("target_object", "")).lower()
            value_written = str(payload.get("details", "")).lower()
            
            if any(key in target_object for key in self.PERSISTENCE_REG_KEYS):
                return {
                    "alert_type": "REGISTRY_PERSISTENCE_ADD",
                    "mitre_id": "T1547.001",
                    "mitre_tactic": "Persistence",
                    "severity": "ALTA",
                    "description": f"Chave de inicialização automática modificada no Registro: {target_object} -> {value_written}",
                    "details": payload
                }
                
        elif event_id == 1 and "schtasks" in str(payload.get("image_path", "")).lower():
            cmd_line = str(payload.get("command_line", "")).lower()
            if "/create" in cmd_line:
                return {
                    "alert_type": "SCHEDULED_TASK_PERSISTENCE",
                    "mitre_id": "T1053.005",
                    "mitre_tactic": "Persistence",
                    "severity": "ALTA",
                    "description": f"Nova tarefa agendada criada no Windows: {cmd_line}",
                    "details": payload
                }

        # --- 3. CONEXÕES DE REDE INVISÍVEIS ORIGINADAS POR RUNDLL32 / LOLBINS (Event ID 3) ---
        if event_id == 3: # Network Connection Event
            image_name = str(payload.get("image_name", "")).lower().split("\\")[-1]
            dest_ip = payload.get("destination_ip")
            dest_port = payload.get("destination_port")
            
            if image_name in self.LOLBINS:
                return {
                    "alert_type": "SUSPICIOUS_LOLBIN_NETWORK_CONNECTION",
                    "mitre_id": "T1218.011",
                    "mitre_tactic": "Defense Evasion / Command and Control",
                    "severity": "CRÍTICO",
                    "description": f"Conexão de rede de saída invisível iniciada pelo utilitário do sistema '{image_name}' enviando dados para {dest_ip}:{dest_port}.",
                    "details": payload
                }

        return None
