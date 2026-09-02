# sentinel_core/ai_predictor.py
import math
import time
import logging
from typing import List, Dict, Any, Tuple

class ZeroDayAIPredictor:
    """
    Motor Preditivo de Ameaças Zero-Day baseado em Análise de Anomalia Estocástica e Machine Learning.
    Avalia vetores de tráfego, entropia de payload e flutuações de requisições.
    """

    def __init__(self, logger=None):
        self.logger = logger
        self.traffic_history: List[float] = []
        self.payload_entropy_history: List[float] = []
        self.baseline_window = 100  # Tamanho da janela de aprendizado

    def _log(self, level: str, category: str, action: str, msg: str):
        if self.logger:
            self.logger.log_event(level, category, action, msg)
        logging.info(f"[{category}] {msg}")

    def calculate_entropy(self, data: str) -> float:
        """Calcula a Entropia de Shannon de uma string/payload para detectar payloads ofuscados/criptografados."""
        if not data:
            return 0.0

        entropy = 0.0
        length = len(data)
        frequency = {}

        for char in data:
            frequency[char] = frequency.get(char, 0) + 1

        for count in frequency.values():
            p = count / length
            entropy -= p * math.log2(p)

        return round(entropy, 4)

    def analyze_request(self, ip: str, payload: str, request_rate: float) -> Dict[str, Any]:
        """
        Analisa uma requisição sob o prisma estocástico de Zero-Day.
        Retorna pontuação de risco AI (0.0 a 1.0) e diagnósticos.
        """
        entropy = self.calculate_entropy(payload)
        
        self.traffic_history.append(request_rate)
        self.payload_entropy_history.append(entropy)

        if len(self.traffic_history) > self.baseline_window:
            self.traffic_history.pop(0)
            self.payload_entropy_history.pop(0)

        # Cálculo de Média e Desvio Padrão para detecção de anomalia
        avg_rate, std_rate = self._get_stats(self.traffic_history)
        avg_entropy, std_entropy = self._get_stats(self.payload_entropy_history)

        risk_score = 0.0
        flags = []

        # 1. Anomalia de Entropia Alta (indica Shellcode/Payload Ofuscado)
        if entropy > 5.2:
            risk_score += 0.45
            flags.append("HIGH_ENTROPY_PAYLOAD_DETECTED")

        # 2. Desvio padrão de Taxa de Requisição (Z-score anomaly)
        if std_rate > 0 and (request_rate - avg_rate) / std_rate > 3.0:
            risk_score += 0.35
            flags.append("STATISTICAL_TRAFFIC_SPIKE")

        # 3. Tamanho Anômalo de Carga Útil
        if len(payload) > 4096:
            risk_score += 0.20
            flags.append("ABNORMAL_PAYLOAD_SIZE")

        risk_score = min(round(risk_score, 2), 1.0)
        is_zero_day = risk_score >= 0.70

        if is_zero_day:
            self._log("CRITICAL", "AI_PREDICTOR", "ZERO_DAY_DETECTED", 
                      f"Ameaça Zero-Day predita para IP {ip}! Score: {risk_score} | Flags: {', '.join(flags)}")

        return {
            "ip": ip,
            "zero_day_predicted": is_zero_day,
            "risk_score": risk_score,
            "payload_entropy": entropy,
            "flags": flags,
            "timestamp": time.time()
        }

    def _get_stats(self, data: List[float]) -> Tuple[float, float]:
        if not data:
            return 0.0, 0.0
        mean = sum(data) / len(data)
        variance = sum((x - mean) ** 2 for x in data) / len(data)
        return mean, math.sqrt(variance)
