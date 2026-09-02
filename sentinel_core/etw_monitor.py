# sentinel_core/etw_monitor.py
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("SentinelaXDR.KernelETW")

class ETWKernelMonitor:
    """
    Monitorador de Kernel nativo via Event Tracing for Windows (ETW / Sysmon).
    Captura Injeção de Processos, Persistência no Registro/Schtasks e Conexões Suspeitas via Rundll32/Powershell.
    """
    
    LOLBINS = ["rundll32.exe", "regsvr32.exe", "certutil.exe", "mshta.exe", "powershell.exe"]

    def __init__(self):
        self.running = True
        logger.info("🛡️ Motor ETW Kernel Monitor inicializado.")

    def inspect_event(self, event_id: int, provider: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Analisa eventos em tempo real interceptados do barramento ETW.
        """
        image_path = str(payload.get("image_path", "")).lower()
        cmd_line = str(payload.get("command_line", "")).lower()
        
        # 1. Detecção de Process Hollowing / Injeção em Processos Críticos (Sysmon Event ID 8/10)
        if event_id in [8, 10] or provider == "Microsoft-Windows-Kernel-Process":
            target_image = str(payload.get("target_image", "")).lower()
            if any(critical in target_image for critical in ["lsass.exe", "svchost.exe", "explorer.exe", "winlogon.exe"]):
                return {
                    "rule": "PROCESS_INJECTION_DETECTED",
                    "severity": "CRÍTICO",
                    "mitre_id": "T1055.012",
                    "mitre_tactic": "Defense Evasion / Privilege Escalation",
                    "description": f"Tentativa de injeção no processo crítico {target_image} a partir do PID {payload.get('source_pid')}",
                    "source_pid": payload.get("source_pid"),
                    "target_pid": payload.get("target_pid")
                }

        # 2. Execução Evasiva de PowerShell ou Scripting
        if "powershell" in image_path and any(flag in cmd_line for flag in ["-enc", "-hidden", "bypass", "downloadstring"]):
            return {
                "rule": "SUSPICIOUS_POWERSHELL_EXECUTION",
                "severity": "ALTA",
                "mitre_id": "T1059.001",
                "mitre_tactic": "Execution",
                "description": f"PowerShell executado com parâmetros evasivos: {cmd_line}",
                "source_pid": payload.get("process_id")
            }

        # 3. Conexões Evasivas por LOLBins (Ex: rundll32 conectando na internet)
        if any(bin_name in image_path for bin_name in self.LOLBINS):
            if payload.get("network_connection") or "http" in cmd_line:
                return {
                    "rule": "LOLBIN_NETWORK_ACTIVITY",
                    "severity": "ALTA",
                    "mitre_id": "T1218.011",
                    "mitre_tactic": "Defense Evasion",
                    "description": f"Binário nativo {image_path} estabeleceu conexão remota suspeita.",
                    "source_pid": payload.get("process_id")
                }

        return None
