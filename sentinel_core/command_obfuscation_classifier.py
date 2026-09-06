# sentinel_core/command_obfuscation_classifier.py
"""
🛡️ SENTINELA COMMAND OBFUSCATION CLASSIFIER
Motor Heurístico e Estatístico de Análise de Ofuscação de Linhas de Comando.
Calcula Entropia de Shannon, densidade de caracteres de escape, fragmentação de strings,
troca caótica de maiúsculas/minúsculas e sequências de desofuscação em runtime.
Alinhado com MITRE ATT&CK T1027 (Obfuscated Files or Information) e T1059 (Command and Scripting Interpreter).
"""

import math
import re
from typing import Dict, Any, List


class CommandObfuscationClassifier:
    """
    Classificador de Evasão e Ofuscação de Scripts e Comandos Windows (CMD, PowerShell, WScript).
    Avalia a probabilidade de uma linha de comando ter sido intencionalmente camuflada para evadir EDRs.
    """

    def __init__(self, logger=None):
        self.logger = logger

    @staticmethod
    def calculate_shannon_entropy(text: str) -> float:
        """Calcula a entropia de informação de Shannon de uma string."""
        if not text:
            return 0.0
        entropy = 0.0
        length = len(text)
        frequencies: Dict[str, int] = {}
        for char in text:
            frequencies[char] = frequencies.get(char, 0) + 1
        for count in frequencies.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 4)

    def analyze_command(self, cmdline: str) -> Dict[str, Any]:
        """
        Analisa a linha de comando e retorna um relatório completo de risco e ofuscação.
        Retorna score de 0.0 (Legítimo) a 1.0 (Altamente Ofuscado/Malicioso).
        """
        raw = str(cmdline or "").strip()
        if not raw:
            return {
                "score": 0.0,
                "is_obfuscated": False,
                "entropy": 0.0,
                "risk_level": "LOW",
                "indicators": [],
                "details": "Comando vazio."
            }

        indicators: List[str] = []
        risk_score = 0.0
        entropy = self.calculate_shannon_entropy(raw)

        # 1. Entropia anormalmente alta para comandos curtos ou longos
        if len(raw) > 40 and entropy > 4.8:
            indicators.append("HIGH_SHANNON_ENTROPY")
            risk_score += 0.25

        # 2. Uso intensivo de caracteres de escape e inserção (Carets no CMD: s^e^t)
        caret_count = raw.count("^")
        if caret_count >= 3:
            indicators.append(f"CMD_CARET_ESCAPE_INJECTION (count={caret_count})")
            risk_score += min(0.35, 0.10 + (caret_count * 0.03))

        # 3. Uso de backticks no PowerShell (b`y`p`a`s`s)
        backtick_count = raw.count("`")
        if backtick_count >= 3:
            indicators.append(f"POWERSHELL_BACKTICK_OBFUSCATION (count={backtick_count})")
            risk_score += min(0.35, 0.10 + (backtick_count * 0.03))

        # 4. Concatenação excessiva de strings e aspas duplas/simples intercaladas (ex: "iex"+"("+"ne"+"w")
        quote_concat = len(re.findall(r'["\']\s*\+\s*["\']', raw))
        if quote_concat >= 2:
            indicators.append(f"STRING_CONCATENATION_EVASION (count={quote_concat})")
            risk_score += min(0.30, 0.15 + (quote_concat * 0.05))

        # 5. Formatação com operadores de substituição de string (ex: "{0}{1}" -f 'Invoke-','Expression')
        if re.search(r'\{[0-9]+\}\s*(-f|-format)', raw, re.IGNORECASE):
            indicators.append("POWERSHELL_FORMAT_OPERATOR_OBFUSCATION")
            risk_score += 0.35

        # 6. Codificação Base64 ou Comandos Compactados
        if re.search(r'-(?:e|enc|encodedcommand)\s+[a-zA-Z0-9+/=]{20,}', raw, re.IGNORECASE):
            indicators.append("BASE64_ENCODED_COMMAND_EXECUTION")
            risk_score += 0.40
        elif re.search(r'FromBase64String|\[Convert\]::', raw, re.IGNORECASE):
            indicators.append("INLINE_BASE64_DECODING_ROUTINE")
            risk_score += 0.30

        # 7. Invocação de inversão de strings (ex: [Array]::Reverse ou strings invertidas)
        if re.search(r'\[Array\]::Reverse|reverse\s*\(', raw, re.IGNORECASE):
            indicators.append("STRING_REVERSAL_DEOBFUSCATION")
            risk_score += 0.35

        # 8. Extração de variáveis de ambiente por fatiamento de caracteres (ex: %COMSPEC:~4,1%)
        env_slice = len(re.findall(r'%[a-zA-Z0-9_]+:~[0-9]+,[0-9]+%', raw))
        if env_slice >= 2:
            indicators.append(f"CMD_ENV_VAR_SLICING (count={env_slice})")
            risk_score += min(0.40, 0.20 + (env_slice * 0.08))

        # 9. Troca caótica e não padronizada de maiúsculas/minúsculas em palavras-chave
        mixed_case_match = re.search(r'\b(?:p[oO][wW][eE][rR]s[hH][eE][lL][lL]|i[nN][vV][oO][kK][eE]-[eE][xX][pP][rR][eE][sS][sS][iI][oO][nN]|d[oO][wW][nN][lL][oO][aA][dD]s[tT][rR][iI][nN][gG])\b', raw)
        if mixed_case_match:
            indicators.append("CHAOTIC_CASE_VARIATION_LOLBIN")
            risk_score += 0.25

        # 10. Uso excessivo de caracteres especiais como proporção do tamanho total
        special_chars = sum(1 for c in raw if c in r"^`+&|;$%{}[]()\",'")
        special_ratio = special_chars / len(raw)
        if len(raw) > 25 and special_ratio > 0.35:
            indicators.append(f"HIGH_SPECIAL_CHAR_RATIO ({round(special_ratio * 100, 1)}%)")
            risk_score += 0.20

        # Normaliza pontuação final entre 0.0 e 1.0
        final_score = round(min(1.0, risk_score), 3)
        is_obfuscated = final_score >= 0.60

        if final_score >= 0.75:
            risk_level = "CRITICAL"
        elif final_score >= 0.50:
            risk_level = "HIGH"
        elif final_score >= 0.25:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return {
            "score": final_score,
            "is_obfuscated": is_obfuscated,
            "entropy": entropy,
            "risk_level": risk_level,
            "indicators": indicators,
            "length": len(raw),
            "command_sample": raw[:80] + ("..." if len(raw) > 80 else "")
        }
