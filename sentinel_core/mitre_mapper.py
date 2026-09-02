# sentinel_core/mitre_mapper.py
import logging

logger = logging.getLogger("MitreMapper")

class MitreAttckMapper:
    """
    Enriquece telemetrias e alertas do EDR/XDR mapeando-os nativamente
    para a matriz oficial MITRE ATT&CK®.
    """
    ATTACK_MATRIX = {
        "RANSOMWARE_ENCRYPTION": {
            "id": "T1486",
            "name": "Data Encrypted for Impact",
            "tactic": "Impact",
            "description": "Adversários podem criptografar dados no sistema para interromper a disponibilidade."
        },
        "PROCESS_INJECTION": {
            "id": "T1055",
            "name": "Process Injection",
            "tactic": "Defense Evasion, Privilege Escalation",
            "description": "Injeção de código em processos legítimos para ocultar a execução."
        },
        "CREDENTIAL_DUMPING": {
            "id": "T1003.001",
            "name": "OS Credential Dumping: LSASS Memory",
            "tactic": "Credential Access",
            "description": "Extração de credenciais diretamente da memória do processo LSASS."
        },
        "POWERSHELL_SUSPICIOUS": {
            "id": "T1059.001",
            "name": "Command and Scripting Interpreter: PowerShell",
            "tactic": "Execution",
            "description": "Uso de scripts PowerShell codificados para bypass de políticas."
        }
    }

    @classmethod
    def enrich(cls, event_type: str, raw_event: dict) -> dict:
        mitre_data = cls.ATTACK_MATRIX.get(event_type, {
            "id": "T1059",
            "name": "Command and Scripting Interpreter",
            "tactic": "Execution",
            "description": "Execução genérica de código ou script."
        })
        
        enriched_event = raw_event.copy()
        enriched_event["mitre_attck"] = mitre_data
        logger.info(f"🏷️ Alerta Enriquecido: [{mitre_data['id']}] {mitre_data['name']} (Tática: {mitre_data['tactic']})")
        return enriched_event
