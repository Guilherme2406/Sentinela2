# sentinel_core/ueba_graph_engine.py
import logging
import time
from typing import Dict, Any, List

logger = logging.getLogger("SentinelaXDR.UEBA")

class UEBAGraphEngine:
    """
    Motor de Análise de Comportamento de Usuários e Entidades (UEBA).
    Calcula o Z-Score estatístico de ações do usuário para detectar ameaças internas (Insider Threats)
    e abuso de credenciais legítimas.
    """

    def __init__(self):
        # Perfil de linha de base simplificado por usuário (baseline)
        self.user_baselines = {
            "guilherme": {"avg_files_accessed_per_min": 5, "normal_hours": (8, 19)},
            "analista_soc": {"avg_files_accessed_per_min": 15, "normal_hours": (7, 20)}
        }
        logger.info("📈 Motor UEBA (User Behavior Analytics) pronto para rastreamento.")

    def evaluate_user_activity(self, username: str, files_accessed_count: int, current_hour: int) -> Dict[str, Any]:
        """
        Avalia o comportamento do usuário contra sua linha de base histórica.
        """
        user = username.lower()
        baseline = self.user_baselines.get(user, {"avg_files_accessed_per_min": 10, "normal_hours": (8, 18)})
        
        anomalies = []
        anomaly_score = 0

        # 1. Anomalia Temporal (Acesso de Madrugada)
        start_hour, end_hour = baseline["normal_hours"]
        if not (start_hour <= current_hour <= end_hour):
            anomalies.append("OFF_HOURS_ACTIVITY")
            anomaly_score += 35

        # 2. Anomalia de Volume (Volume excessivo de leitura/leitura rápida = possível exfiltração)
        avg = baseline["avg_files_accessed_per_min"]
        if files_accessed_count > avg * 4:
            anomalies.append("MASSIVE_FILE_ACCESS_ANOMALY")
            anomaly_score += 50

        severity = "CRÍTICO" if anomaly_score >= 70 else "ALTO" if anomaly_score >= 35 else "NORMAL"

        return {
            "username": username,
            "anomaly_score": anomaly_score,
            "detected_anomalies": anomalies,
            "severity": severity,
            "requires_mfa_rechallenge": anomaly_score >= 50
        }
