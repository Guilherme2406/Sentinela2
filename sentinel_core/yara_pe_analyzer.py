# sentinel_core/yara_pe_analyzer.py
import math
import logging
from pathlib import Path

logger = logging.getLogger("SentinelaXDR.YaraPEAnalyzer")

class AdvancedPEAnalyzer:
    """
    Motor Avançado de Análise Estática de Binários Executáveis (PE / ELF / DLL) — Modo Hardened.
    Avalia Entropia de Shannon, seções empacotadas (Packers/Crypters), chamadas de API perigosas
    para Injeção de Processos e evasão de antivírus.
    """

    SUSPICIOUS_APIS = {
        "VirtualAllocEx": 35,
        "WriteProcessMemory": 35,
        "CreateRemoteThread": 40,
        "NtUnmapViewOfSection": 30,
        "QueueUserAPC": 25,
        "SetThreadContext": 30,
        "VirtualProtect": 25,
        "MiniDumpWriteDump": 35,
        "RtlMoveMemory": 20,
        "IsDebuggerPresent": 15,
        "CheckRemoteDebuggerPresent": 15
    }

    KNOWN_PACKER_SECTIONS = [
        b".upx0", b".upx1", b".upx2", b".aspack", b".themida", 
        b".vmp0", b".vmp1", b".enigma", b".petite", b".mpress"
    ]

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calcula a entropia de Shannon. Valores acima de 7.2 indicam dados empacotados ou criptografados."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        for x in range(256):
            p_x = float(data.count(bytes([x]))) / length
            if p_x > 0:
                entropy -= p_x * math.log2(p_x)
        return round(entropy, 4)

    @classmethod
    def inspect_file(cls, file_path: str) -> dict:
        path = Path(file_path)
        if not path.exists() or not path.is_file():
            return {"error": "Arquivo não encontrado."}

        try:
            with open(path, "rb") as f:
                content = f.read()

            entropy = cls.calculate_entropy(content)
            detected_apis = []
            detected_packers = []
            risk_score = 0

            # 1. Checagem de APIs de Injeção em Memória
            for api, weight in cls.SUSPICIOUS_APIS.items():
                if api.encode("utf-8") in content:
                    detected_apis.append(api)
                    risk_score += weight

            # 2. Checagem de Seções de Packers / Crypters conhecidos
            content_lower = content.lower()
            for packer in cls.KNOWN_PACKER_SECTIONS:
                if packer in content_lower:
                    packer_name = packer.decode("utf-8", errors="ignore").upper()
                    detected_packers.append(packer_name)
                    risk_score += 40

            # 3. Entropia Anômala (> 7.2 bits/byte)
            is_packed = entropy > 7.2
            if is_packed:
                risk_score += 35

            risk_score = min(100, risk_score)
            severity = "CRÍTICO" if risk_score >= 70 else "ALTO" if risk_score >= 40 else "BAIXO"

            return {
                "file_name": path.name,
                "file_size": len(content),
                "entropy": entropy,
                "is_packed": is_packed,
                "detected_packers": detected_packers,
                "detected_apis": detected_apis,
                "risk_score": risk_score,
                "severity": severity,
                "mitre_techniques": ["T1027 (Obfuscated Files)", "T1055 (Process Injection)"] if risk_score >= 40 else []
            }
        except Exception as e:
            return {"error": str(e)}
