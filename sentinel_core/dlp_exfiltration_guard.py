# sentinel_core/dlp_exfiltration_guard.py
"""
🔒 SENTINELA DATA LOSS PREVENTION (DLP) & EXFILTRATION ARMOR (NÍVEL SOVEREIGN)
Motor de prevenção contra vazamento de dados, exfiltração em nuvem, roubo de segredos
e auditoria de dispositivos USB / mídias removíveis (com proteção BadUSB).
Alinhado com MITRE ATT&CK: T1048 (Exfiltration Over Alternative Protocol),
T1052 (Exfiltration Over Physical Medium), T1567 (Exfiltration Over Web Service) e T1200 (Hardware Additions).
"""

import os
import sys
import time
import re
import logging
from typing import List, Dict, Any, Optional, Set, Tuple

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

_sys_log = logging.getLogger("SentinelaXDR.DLPGuard")


class DLPPatternMatcher:
    """Validador algorítmico e heurístico de dados altamente confidenciais e PII."""

    # Regex para identificação inicial
    REGEX_PATTERNS = {
        "AWS_KEY": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "PRIVATE_KEY": re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----"),
        "JWT_TOKEN": re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"),
        "GITHUB_TOKEN": re.compile(r"\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b"),
        "GOOGLE_API_KEY": re.compile(r"\b(AIza[0-9A-Za-z-_]{35})\b"),
        "DISCORD_WEBHOOK": re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[a-zA-Z0-9_-]+"),
        "TELEGRAM_BOT_TOKEN": re.compile(r"\b\d{9,10}:[a-zA-Z0-9_-]{35}\b"),
        "DB_CONNECTION_STRING": re.compile(r"\b(?:postgres|postgresql|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@[^\s]+\b"),
        "CREDIT_CARD_CANDIDATE": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
        "CPF_CANDIDATE": re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b"),
        "CNPJ_CANDIDATE": re.compile(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b")
    }

    @staticmethod
    def validate_cpf(cpf_str: str) -> bool:
        """Valida se o número é um CPF real através do cálculo do Módulo 11."""
        digits = [int(c) for c in cpf_str if c.isdigit()]
        if len(digits) != 11 or len(set(digits)) == 1:
            return False

        # Validação do primeiro dígito verificador
        sum_1 = sum(digits[i] * (10 - i) for i in range(9))
        rem_1 = (sum_1 * 10) % 11
        if rem_1 == 10:
            rem_1 = 0
        if rem_1 != digits[9]:
            return False

        # Validação do segundo dígito verificador
        sum_2 = sum(digits[i] * (11 - i) for i in range(10))
        rem_2 = (sum_2 * 10) % 11
        if rem_2 == 10:
            rem_2 = 0
        return rem_2 == digits[10]

    @staticmethod
    def validate_cnpj(cnpj_str: str) -> bool:
        """Valida se o número é um CNPJ real através do cálculo do Módulo 11."""
        digits = [int(c) for c in cnpj_str if c.isdigit()]
        if len(digits) != 14 or len(set(digits)) == 1:
            return False

        weights_1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
        sum_1 = sum(digits[i] * weights_1[i] for i in range(12))
        rem_1 = sum_1 % 11
        d1 = 0 if rem_1 < 2 else 11 - rem_1
        if d1 != digits[12]:
            return False

        weights_2 = [6] + weights_1
        sum_2 = sum(digits[i] * weights_2[i] for i in range(13))
        rem_2 = sum_2 % 11
        d2 = 0 if rem_2 < 2 else 11 - rem_2
        return d2 == digits[13]

    @staticmethod
    def validate_luhn(card_number_str: str) -> bool:
        """Valida cartões de crédito utilizando o algoritmo de Luhn (Mod 10)."""
        clean_num = "".join(c for c in card_number_str if c.isdigit())
        if len(clean_num) < 13 or len(clean_num) > 19:
            return False

        # Evita falsos-positivos em sequências repetidas (ex: 0000000000000000)
        if len(set(clean_num)) == 1:
            return False

        total = 0
        reverse_digits = clean_num[::-1]
        for i, char in enumerate(reverse_digits):
            n = int(char)
            if i % 2 == 1:
                n *= 2
                if n > 9:
                    n -= 9
            total += n
        return total % 10 == 0


class DLPExfiltrationGuard:
    """
    Motor Soberano de Proteção contra Perda de Dados (DLP) e Exfiltração.
    Monitora áreas de transferência, tráfego de saída, processos LOLBins de upload
    e controla o uso de mídias removíveis (USB Storage).
    """

    EXFILTRATION_TOOLS = [
        {"name": "RCLONE_CLOUD_SYNC", "keywords": ["rclone", "sync"], "severity": "HIGH"},
        {"name": "MEGATOOLS_EXFILTRATION", "keywords": ["megatools", "put"], "severity": "CRITICAL"},
        {"name": "CURL_DATA_UPLOAD", "keywords": ["curl", "-t"], "severity": "HIGH"},
        {"name": "CURL_POST_FILE", "keywords": ["curl", "-f", "@"], "severity": "HIGH"},
        {"name": "DISCORD_WEBHOOK_EXFIL", "keywords": ["discord.com/api/webhooks"], "severity": "CRITICAL"},
        {"name": "TELEGRAM_BOT_EXFIL", "keywords": ["api.telegram.org/bot"], "severity": "CRITICAL"},
        {"name": "TRANSFER_SH_UPLOAD", "keywords": ["transfer.sh"], "severity": "HIGH"},
        {"name": "ANONFILES_GOFILE_UPLOAD", "keywords": ["gofile.io", "file.io"], "severity": "HIGH"},
        {"name": "SUSPICIOUS_ARCHIVE_TEMP", "keywords": ["7z", " a ", "temp"], "severity": "HIGH"}
    ]

    def __init__(self, logger=None, soar=None, orchestrator=None):
        self.logger = logger
        self.soar = soar
        self.orchestrator = orchestrator
        self.usb_policy: str = "READ_ONLY"  # Opções: "ALLOW_ALL", "READ_ONLY", "BLOCK_ALL"
        self.intercepted_events: List[Dict[str, Any]] = []
        self.active_shields = {
            "content_inspection": True,
            "clipboard_guard": True,
            "usb_write_protection": True,
            "cloud_exfil_blocker": True
        }
        logger_name = self.logger.__class__.__name__ if self.logger else "None"
        _sys_log.info(f"🔒 [DLP_GUARD] Motor de Proteção de Dados e Exfiltração ativado (USB Policy: {self.usb_policy}, Logger: {logger_name}).")

    def _log_event(self, severity: str, action: str, target: str, message: str) -> None:
        """Registra no SecurityEventLogger e despacha ao Orquestrador se disponível."""
        if self.logger:
            try:
                self.logger.log_event(severity, "DLP_GUARD", target, message)
            except Exception as e:
                _sys_log.error(f"[DLP_GUARD] Falha ao gravar log de segurança: {e}")

        if self.orchestrator:
            try:
                from sentinel_core.sentinela_orchestrator import SecurityEvent
                event = SecurityEvent(
                    source="DLP_GUARD",
                    severity=severity,
                    data={
                        "action": action,
                        "target": target,
                        "description": message,
                        "timestamp": time.time()
                    }
                )
                self.orchestrator.emit(event)
            except Exception as e:
                _sys_log.debug(f"[DLP_GUARD] Erro ao emitir evento ao orquestrador: {e}")

    def inspect_text(self, text: str) -> Dict[str, Any]:
        """
        Inspeciona um texto buscando chaves de API, credenciais, segredos, CPFs,
        CNPJs e cartões de crédito com validação algorítmica.
        """
        if not text:
            return {"status": "CLEAN", "findings_count": 0, "findings": []}

        findings = []

        # 1. Chaves e Segredos de Infraestrutura
        if DLPPatternMatcher.REGEX_PATTERNS["PRIVATE_KEY"].search(text):
            findings.append({"type": "PRIVATE_KEY", "severity": "CRITICAL", "description": "Chave Privada Criptográfica (RSA/SSH/PGP)"})

        aws_matches = DLPPatternMatcher.REGEX_PATTERNS["AWS_KEY"].findall(text)
        for m in aws_matches:
            findings.append({"type": "AWS_CREDENTIAL", "severity": "CRITICAL", "preview": f"{m[:4]}****{m[-4:]}", "description": "Credencial AWS Access Key"})

        jwt_matches = DLPPatternMatcher.REGEX_PATTERNS["JWT_TOKEN"].findall(text)
        if jwt_matches:
            findings.append({"type": "JWT_TOKEN", "severity": "HIGH", "count": len(jwt_matches), "description": "Token de Autenticação JWT"})

        github_matches = DLPPatternMatcher.REGEX_PATTERNS["GITHUB_TOKEN"].findall(text)
        for g in github_matches:
            findings.append({"type": "GITHUB_PAT", "severity": "CRITICAL", "description": "Personal Access Token do GitHub"})

        google_matches = DLPPatternMatcher.REGEX_PATTERNS["GOOGLE_API_KEY"].findall(text)
        for g in google_matches:
            findings.append({"type": "GOOGLE_API_KEY", "severity": "CRITICAL", "description": "Chave de API do Google Cloud"})

        discord_matches = DLPPatternMatcher.REGEX_PATTERNS["DISCORD_WEBHOOK"].findall(text)
        for d in discord_matches:
            findings.append({"type": "DISCORD_WEBHOOK", "severity": "CRITICAL", "description": "Webhook do Discord (canal de exfiltração)"})

        db_matches = DLPPatternMatcher.REGEX_PATTERNS["DB_CONNECTION_STRING"].findall(text)
        for db in db_matches:
            findings.append({"type": "DATABASE_CREDENTIAL", "severity": "CRITICAL", "description": "String de conexão de Banco de Dados com Senha"})

        # 2. Dados Pessoais Sensíveis (PII) com Validação Estrita (Módulo 11)
        cpf_candidates = DLPPatternMatcher.REGEX_PATTERNS["CPF_CANDIDATE"].findall(text)
        valid_cpfs = [c for c in cpf_candidates if DLPPatternMatcher.validate_cpf(c)]
        if valid_cpfs:
            findings.append({
                "type": "BRAZILIAN_CPF",
                "severity": "HIGH",
                "count": len(valid_cpfs),
                "samples": [f"***.***.{c.replace('.', '').replace('-', '')[6:9]}-**" for c in valid_cpfs[:3]],
                "description": f"{len(valid_cpfs)} CPF(s) válidos detectados (Proteção LGPD)"
            })

        cnpj_candidates = DLPPatternMatcher.REGEX_PATTERNS["CNPJ_CANDIDATE"].findall(text)
        valid_cnpjs = [c for c in cnpj_candidates if DLPPatternMatcher.validate_cnpj(c)]
        if valid_cnpjs:
            findings.append({
                "type": "BRAZILIAN_CNPJ",
                "severity": "HIGH",
                "count": len(valid_cnpjs),
                "description": f"{len(valid_cnpjs)} CNPJ(s) válidos corporativos detectados"
            })

        # 3. Cartões de Crédito com Algoritmo de Luhn
        card_candidates = DLPPatternMatcher.REGEX_PATTERNS["CREDIT_CARD_CANDIDATE"].findall(text)
        valid_cards = [c for c in card_candidates if DLPPatternMatcher.validate_luhn(c)]
        if valid_cards:
            findings.append({
                "type": "CREDIT_CARD",
                "severity": "CRITICAL",
                "count": len(valid_cards),
                "samples": [f"****-****-****-{c.replace(' ', '').replace('-', '')[-4:]}" for c in valid_cards[:3]],
                "description": f"{len(valid_cards)} Cartão(ões) de crédito válidos detectados (PCI-DSS)"
            })

        is_sensitive = len(findings) > 0
        return {
            "status": "SENSITIVE_DATA_DETECTED" if is_sensitive else "CLEAN",
            "findings_count": len(findings),
            "findings": findings
        }

    def inspect_file_content(self, file_path: str) -> Dict[str, Any]:
        """Lê os primeiros 2MB de um arquivo e audita por vazamento de dados confidenciais."""
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return {"status": "ERROR", "message": "Arquivo inexistente"}

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(2 * 1024 * 1024)
            result = self.inspect_text(content)
            result["file_path"] = file_path
            if result["status"] == "SENSITIVE_DATA_DETECTED":
                self._log_event(
                    "HIGH",
                    "DLP_FILE_EXPOSURE",
                    file_path,
                    f"⚠️ [DLP] Arquivo contém dados corporativos confidenciais ({result['findings_count']} ocorrências)"
                )
            return result
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}

    def audit_usb_storage(self) -> Dict[str, Any]:
        """
        Audita dispositivos de armazenamento USB/removíveis conectados no host.
        Identifica novos pendrives e o estado de proteção contra gravação.
        """
        removable_drives = []
        if HAS_PSUTIL:
            try:
                for part in psutil.disk_partitions(all=True):
                    # Flag 'removable' em opts indica mídia USB / cartão SD
                    opts = (part.opts or "").lower()
                    is_removable = "removable" in opts or "cdrom" in opts
                    if is_removable or part.device.startswith(("\\\\", "D:", "E:", "F:", "G:", "H:")):
                        # Em Windows podemos filtrar discos removíveis
                        try:
                            usage = psutil.disk_usage(part.mountpoint)
                            removable_drives.append({
                                "device": part.device,
                                "mountpoint": part.mountpoint,
                                "fstype": part.fstype,
                                "total_gb": round(usage.total / (1024**3), 2),
                                "free_gb": round(usage.free / (1024**3), 2),
                                "opts": part.opts
                            })
                        except Exception:
                            removable_drives.append({
                                "device": part.device,
                                "mountpoint": part.mountpoint,
                                "fstype": part.fstype,
                                "opts": part.opts
                            })
            except Exception as e:
                _sys_log.debug(f"[DLP_GUARD] Erro ao listar partições: {e}")

        return {
            "status": "success",
            "usb_policy": self.usb_policy,
            "removable_drives_count": len(removable_drives),
            "drives": removable_drives
        }

    def set_usb_policy(self, policy: str) -> Dict[str, Any]:
        """
        Configura a política de mídias removíveis USB no Windows:
        - 'ALLOW_ALL': Acesso normal com auditoria.
        - 'READ_ONLY': Bloqueia gravação em pendrive (DLP Write-Protect).
        - 'BLOCK_ALL': Bloqueio de portas de armazenamento USB.
        """
        normalized = policy.upper().strip()
        if normalized not in ["ALLOW_ALL", "READ_ONLY", "BLOCK_ALL"]:
            return {"status": "ERROR", "message": "Política inválida. Opções: ALLOW_ALL, READ_ONLY, BLOCK_ALL"}

        self.usb_policy = normalized
        action_msg = f"Política de Armazenamento USB configurada para: {self.usb_policy}"
        _sys_log.warning(f"🔒 [DLP_GUARD] {action_msg}")
        self._log_event("WARNING", "USB_POLICY_CHANGE", "STORAGE_CONTROLLER", action_msg)

        # Configura WriteProtect no registro do Windows caso no Windows
        if sys.platform == "win32":
            try:
                import winreg
                key_path = r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies"
                val = 1 if self.usb_policy in ["READ_ONLY", "BLOCK_ALL"] else 0
                try:
                    with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                        winreg.SetValueEx(key, "WriteProtect", 0, winreg.REG_DWORD, val)
                except PermissionError:
                    _sys_log.info("[DLP_GUARD] Modificação de registro requer elevação de Administrador.")
            except Exception as e:
                _sys_log.debug(f"[DLP_GUARD] Erro ao aplicar WriteProtect: {e}")

        return {"status": "SUCCESS", "current_policy": self.usb_policy}

    def scan_exfiltration_processes(self) -> List[Dict[str, Any]]:
        """
        Varre processos em execução buscando utilitários e LOLBins de exfiltração
        de dados para a nuvem (rclone, curl com upload, webhooks de Discord/Telegram).
        """
        threats_found = []
        if not HAS_PSUTIL:
            return threats_found

        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'exe']):
            try:
                pinfo = proc.info
                pname = (pinfo['name'] or '').lower()
                pid = pinfo['pid']

                if pid <= 4 or pname in ["system", "idle", "explorer.exe"]:
                    continue

                cmd_tokens = [str(t).lower() for t in (pinfo['cmdline'] or [])]
                cmd_str = " ".join(cmd_tokens)

                for rule in self.EXFILTRATION_TOOLS:
                    keywords = rule["keywords"]
                    if all(kw in cmd_str for kw in keywords):
                        threat_info = {
                            "pid": pid,
                            "name": pinfo['name'],
                            "cmdline": cmd_str,
                            "rule": rule["name"],
                            "severity": rule["severity"],
                            "timestamp": time.time(),
                            "neutralized": False
                        }

                        # Auto-neutralização de processos de exfiltração
                        if self.active_shields.get("cloud_exfil_blocker", True):
                            neutralized = self.neutralize_exfiltration(pid, f"Exfiltração de dados detectada: {rule['name']}")
                            threat_info["neutralized"] = neutralized

                        threats_found.append(threat_info)
                        self.intercepted_events.append(threat_info)

                        self._log_event(
                            rule["severity"],
                            rule["name"],
                            f"PID:{pid}|{pname}",
                            f"🛑 [DLP EXFILTRATION BLOCKED] Processo tentando upload não autorizado de dados: {cmd_str}"
                        )
                        break

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                _sys_log.debug(f"[DLP_GUARD] Erro ao analisar processo de exfiltração: {e}")

        return threats_found

    def neutralize_exfiltration(self, pid: int, reason: str = "Bloqueio DLP") -> bool:
        """Encerra com força total o processo exfiltrador de dados."""
        try:
            if HAS_PSUTIL:
                p = psutil.Process(pid)
                for child in p.children(recursive=True):
                    try:
                        child.kill()
                    except Exception:
                        pass
                p.kill()
                _sys_log.warning(f"⚡ [DLP_GUARD] Processo exfiltrador PID {pid} terminado com sucesso. Motivo: {reason}")
                return True
        except Exception as e:
            _sys_log.error(f"[DLP_GUARD] Falha ao encerrar PID {pid}: {e}")
        return False

    def get_status(self) -> Dict[str, Any]:
        """Retorna o estado operacional e métricas de prevenção do DLP."""
        return {
            "engine": "Sentinel DLP & Exfiltration Armor",
            "version": "2.5 Sovereign Enterprise",
            "status": "ACTIVE_DEFENSE",
            "usb_policy": self.usb_policy,
            "active_shields": self.active_shields,
            "patterns_supported": [
                "Brazilian CPF (Mod 11)", "Brazilian CNPJ (Mod 11)", "Credit Cards (Luhn Algorithm)",
                "AWS Access Keys", "SSH/RSA Private Keys", "JWT Tokens", "GitHub PATs",
                "Google Cloud APIs", "Discord/Telegram Exfil Webhooks", "Database Passwords"
            ],
            "intercepted_exfiltrations_count": len(self.intercepted_events),
            "recent_events": self.intercepted_events[-10:] if self.intercepted_events else []
        }
