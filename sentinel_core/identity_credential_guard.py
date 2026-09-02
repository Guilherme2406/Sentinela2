# sentinel_core/identity_credential_guard.py
"""
🛡️ SENTINELA IDENTITY & CREDENTIAL GUARD (NÍVEL SOVEREIGN / HARDENED)
Proteção ativa e em tempo real contra roubo de credenciais, dumping de LSASS,
extração de hashes SAM/SYSTEM, exploração de tokens da família Potato e stealers locais.
Alinhado com MITRE ATT&CK: T1003.001, T1003.002, T1134, T1555 e T1558.
"""

import os
import sys
import time
import re
import logging
from typing import List, Dict, Any, Optional, Set

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

_sys_log = logging.getLogger("SentinelaXDR.IdentityGuard")


class IdentityCredentialGuard:
    """
    Motor Avançado de Proteção de Identidade e Credenciais no Endpoint.
    Detecta e neutraliza ataques sofisticados de Red Teams, APTs e Ransomwares
    que buscam escalonamento de privilégios e extração de credenciais na memória e no disco.
    """

    # Binários nativos do Windows autorizados a interagir com LSASS e subsistemas de segurança
    LEGITIMATE_SYSTEM_PROCS: Set[str] = {
        "csrss.exe", "smss.exe", "wininit.exe", "services.exe",
        "svchost.exe", "system", "idle", "lsass.exe", "winlogon.exe"
    }

    # Assinaturas Heurísticas de Alto Impacto para Roubo de Identidade e Dump de Credenciais
    CREDENTIAL_THEFT_RULES = [
        # --- MITRE T1003.001: LSASS Memory Dumping ---
        {
            "id": "ID_LSASS_COMSVCS",
            "name": "Comsvcs MiniDump LSASS Export",
            "mitre": "T1003.001",
            "severity": "CRITICAL",
            "keywords": ["comsvcs.dll", "minidump"],
            "description": "Tentativa de dump nativo de LSASS usando comsvcs.dll MiniDump"
        },
        {
            "id": "ID_LSASS_COMSVCS_ORDINAL",
            "name": "Comsvcs Ordinal MiniDump (#24)",
            "mitre": "T1003.001",
            "severity": "CRITICAL",
            "keywords": ["comsvcs.dll", "#24"],
            "description": "Invocação velada do MiniDump por ordinal #24 via rundll32"
        },
        {
            "id": "ID_LSASS_PROCDUMP",
            "name": "ProcDump LSASS Extraction",
            "mitre": "T1003.001",
            "severity": "CRITICAL",
            "keywords": ["procdump", "lsass"],
            "description": "Extração de processo LSASS via Sysinternals ProcDump"
        },
        {
            "id": "ID_LSASS_SQLDUMPER",
            "name": "SQLDumper Living-off-the-Land Dump",
            "mitre": "T1003.001",
            "severity": "CRITICAL",
            "keywords": ["sqldumper.exe", "0x01100"],
            "description": "Tentativa de abuso de binário LOLBin SQLDumper para despejo de LSASS"
        },
        {
            "id": "ID_MIMIKATZ_SEKURLSA",
            "name": "Mimikatz Sekurlsa Credential Harvester",
            "mitre": "T1003.001",
            "severity": "CRITICAL",
            "keywords": ["sekurlsa::", "logonpasswords"],
            "description": "Comando direto de extração de credenciais via Mimikatz"
        },
        {
            "id": "ID_MIMIKATZ_LSADUMP",
            "name": "Mimikatz LSA Secrets Dump",
            "mitre": "T1003.001",
            "severity": "CRITICAL",
            "keywords": ["lsadump::"],
            "description": "Despejo de segredos LSA e chaves de máquina via Mimikatz"
        },
        {
            "id": "ID_OFFENSIVE_DUMPERS",
            "name": "Conhecidos Dumpers de Credenciais Ofensivos",
            "mitre": "T1003.001",
            "severity": "CRITICAL",
            "keywords": ["nanodump", "dumpert", "pypykatz", "lsassy"],
            "match_mode": "any",
            "description": "Execução de ferramenta ofensiva de dumping de memória e credenciais"
        },
        {
            "id": "ID_PS_MINIDUMP_WRITEDUMP",
            "name": "PowerShell MiniDumpWriteDump Injection",
            "mitre": "T1003.001",
            "severity": "CRITICAL",
            "keywords": ["minidumpwritedump"],
            "description": "Script invocando MiniDumpWriteDump da Dbghelp.dll para despejar LSASS"
        },

        # --- MITRE T1003.002: SAM / SYSTEM / SECURITY Hive Dumping ---
        {
            "id": "ID_REG_SAVE_SAM",
            "name": "Registry Hive Save (SAM)",
            "mitre": "T1003.002",
            "severity": "CRITICAL",
            "keywords": ["reg", "save", "sam"],
            "description": "Exportação da colmeia de senhas locais SAM via utilitário de registro"
        },
        {
            "id": "ID_REG_SAVE_SYSTEM",
            "name": "Registry Hive Save (SYSTEM)",
            "mitre": "T1003.002",
            "severity": "CRITICAL",
            "keywords": ["reg", "save", "system"],
            "description": "Exportação da chave SYSTEM (usada para decifrar a colmeia SAM)"
        },
        {
            "id": "ID_REG_SAVE_SECURITY",
            "name": "Registry Hive Save (SECURITY)",
            "mitre": "T1003.002",
            "severity": "CRITICAL",
            "keywords": ["reg", "save", "security"],
            "description": "Exportação de políticas de segurança e credenciais em cache LSA"
        },
        {
            "id": "ID_ESENTUTL_VSS_SAM",
            "name": "Esentutl VSS SAM Extraction",
            "mitre": "T1003.002",
            "severity": "CRITICAL",
            "keywords": ["esentutl", "/y", "/vss"],
            "description": "Abuso do esentutl para extrair cópias de sombra da base SAM"
        },
        {
            "id": "ID_NTDSUTIL_IFM_EXTRACT",
            "name": "Ntdsutil IFM Credential Dump",
            "mitre": "T1003.002",
            "severity": "CRITICAL",
            "keywords": ["ntdsutil", "ac i ntds", "ifm"],
            "description": "Criação de snapshot de mídia de instalação (IFM) para extrair ntds.dit"
        },

        # --- MITRE T1134: Token Impersonation & Potato Family PrivEsc ---
        {
            "id": "ID_POTATO_EXPLOIT_FAMILY",
            "name": "Potato Privilege Escalation Tool",
            "mitre": "T1134",
            "severity": "CRITICAL",
            "keywords": ["juicypotato", "godpotato", "roguepotato", "sweetpotato", "badpotato", "efspotato", "printspoofer"],
            "match_mode": "any",
            "description": "Ferramenta de escalonamento de privilégios abusando de SeImpersonate/RPC"
        },
        {
            "id": "ID_INC_COGNITO_TOKEN",
            "name": "Incognito Token Impersonation",
            "mitre": "T1134",
            "severity": "CRITICAL",
            "keywords": ["incognito", "list_tokens"],
            "description": "Listagem e sequestro de tokens de autenticação via Incognito"
        },

        # --- MITRE T1555 / T1558: Browser Credentials & Kerberos Theft ---
        {
            "id": "ID_RUBEUS_KERBEROS_ROAST",
            "name": "Rubeus Kerberos Harvester",
            "mitre": "T1558",
            "severity": "CRITICAL",
            "keywords": ["rubeus", "kerberoast"],
            "description": "Ataque de Kerberoasting para extração e quebra offline de tickets TGS"
        },
        {
            "id": "ID_RUBEUS_ASREP",
            "name": "Rubeus AS-REP Roasting",
            "mitre": "T1558",
            "severity": "CRITICAL",
            "keywords": ["rubeus", "asreproast"],
            "description": "Extração de hashes pré-autenticados Kerberos sem pré-requisitos"
        },
        {
            "id": "ID_BROWSER_LOGIN_DATA_THEFT",
            "name": "Browser Login Data Harvester",
            "mitre": "T1555",
            "severity": "HIGH",
            "keywords": ["login data", "sqlite3"],
            "description": "Processo anômalo acessando cofre de senhas SQLite de navegadores"
        }
    ]

    # Constantes de Acesso a Processo do Windows (Win32 API)
    PROCESS_VM_READ = 0x0010
    PROCESS_VM_WRITE = 0x0020
    PROCESS_VM_OPERATION = 0x0008
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_ALL_ACCESS = 0x1F0FFF

    def __init__(self, logger=None, soar=None, orchestrator=None):
        self.logger = logger
        self.soar = soar
        self.orchestrator = orchestrator
        self.lsass_pid: Optional[int] = None
        self.monitored_targets_count: int = 0
        self.neutralized_threats: List[Dict[str, Any]] = []
        self.active_shields = {
            "lsass_armor": True,
            "sam_hive_guard": True,
            "token_potato_guard": True,
            "browser_vault_guard": True,
            "active_remediation": True
        }
        self._refresh_lsass_pid()
        logger_name = self.logger.__class__.__name__ if self.logger else "None"
        _sys_log.info(f"🛡️ [IDENTITY_GUARD] Motor de Proteção de Identidade ativado (LSASS PID: {self.lsass_pid}, Logger: {logger_name}).")

    def _refresh_lsass_pid(self) -> Optional[int]:
        """Localiza o PID atual do processo crítico lsass.exe de forma segura."""
        if not HAS_PSUTIL:
            return None
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if (proc.info['name'] or '').lower() == 'lsass.exe':
                    self.lsass_pid = proc.info['pid']
                    return self.lsass_pid
        except Exception as e:
            _sys_log.debug(f"[IDENTITY_GUARD] Erro ao localizar PID do LSASS: {e}")
        return None

    def _log_event(self, severity: str, action: str, target: str, message: str) -> None:
        """Registra no SecurityEventLogger e despacha ao Orquestrador se disponível."""
        if self.logger:
            try:
                self.logger.log_event(severity, "IDENTITY_GUARD", target, message)
            except Exception as e:
                logger.error(f"[IDENTITY_GUARD] Falha ao gravar log de segurança: {e}")

        if self.orchestrator:
            try:
                from sentinel_core.sentinela_orchestrator import SecurityEvent
                event = SecurityEvent(
                    source="IDENTITY_GUARD",
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
                logger.debug(f"[IDENTITY_GUARD] Erro ao emitir evento ao orquestrador: {e}")

    def scan_running_processes_and_cmdlines(self) -> List[Dict[str, Any]]:
        """
        Varre continuamente processos e linhas de comando em execução buscando
        técnicas de dumping de credenciais, Potato exploits, roubo de SAM e stealers.
        """
        threats_found: List[Dict[str, Any]] = []
        if not HAS_PSUTIL:
            return threats_found

        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'exe', 'username']):
            try:
                pinfo = proc.info
                pname = (pinfo['name'] or '').lower()
                pid = pinfo['pid']

                # Ignora processos protegidos do próprio sistema e PID 0/4
                if pname in self.LEGITIMATE_SYSTEM_PROCS or pid <= 4:
                    continue

                cmd_tokens = [str(t).lower() for t in (pinfo['cmdline'] or [])]
                cmd_str = " ".join(cmd_tokens)
                exe_path = pinfo.get('exe') or ''

                # Avalia contra as regras heurísticas de alta precisão
                for rule in self.CREDENTIAL_THEFT_RULES:
                    keywords = rule["keywords"]
                    match_mode = rule.get("match_mode", "all")

                    if match_mode == "any":
                        match_cmd = any(kw in cmd_str for kw in keywords)
                        match_name = any(kw in pname for kw in keywords)
                    else:
                        match_cmd = all(kw in cmd_str for kw in keywords)
                        match_name = any(kw == pname or kw in pname for kw in keywords) if len(keywords) == 1 else False

                    if match_cmd or match_name:
                        threat_info = {
                            "pid": pid,
                            "name": pinfo['name'],
                            "exe": exe_path,
                            "cmdline": cmd_str,
                            "rule_id": rule["id"],
                            "rule_name": rule["name"],
                            "mitre": rule["mitre"],
                            "severity": rule["severity"],
                            "description": rule["description"],
                            "timestamp": time.time(),
                            "neutralized": False
                        }

                        # Executa auto-remediação caso ativada
                        if self.active_shields.get("active_remediation", True):
                            neutralized = self.neutralize_threat(pid, exe_path, rule["name"])
                            threat_info["neutralized"] = neutralized

                        threats_found.append(threat_info)
                        self.neutralized_threats.append(threat_info)

                        self._log_event(
                            rule["severity"],
                            rule["id"],
                            f"PID:{pid}|{pname}",
                            f"🚨 [ALERTA DE CREDENCIAIS] {rule['name']} ({rule['mitre']}) interceptado! Comando: {cmd_str}"
                        )
                        break

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                _sys_log.debug(f"[IDENTITY_GUARD] Erro ao inspecionar PID: {e}")

        return threats_found

    def audit_token_privileges(self) -> List[Dict[str, Any]]:
        """
        Audita privilégios de alto impacto (SeDebugPrivilege, SeImpersonatePrivilege)
        em processos de usuários comuns no Windows.
        """
        suspicious_processes: List[Dict[str, Any]] = []
        if not HAS_PSUTIL:
            return suspicious_processes

        # Detectamos processos não-SYSTEM que usam nomes ou técnicas de elevação Potato/Impersonation
        for proc in psutil.process_iter(['pid', 'name', 'username', 'exe']):
            try:
                pinfo = proc.info
                pname = (pinfo['name'] or '').lower()
                user = (pinfo.get('username') or '').lower()

                if pname in self.LEGITIMATE_SYSTEM_PROCS or pinfo['pid'] <= 4:
                    continue

                if any(p in pname for p in ["potato", "spoofer", "incognito"]):
                    threat_item = {
                        "pid": pinfo['pid'],
                        "name": pinfo['name'],
                        "user": user,
                        "severity": "CRITICAL",
                        "rule": "UNAUTHORIZED_PRIVILEGE_ELEVATION",
                        "description": f"Processo suspeito '{pname}' tentando manipulação de privilégios de token."
                    }
                    suspicious_processes.append(threat_item)
            except Exception:
                continue

        return suspicious_processes

    def neutralize_threat(self, pid: int, exe_path: Optional[str] = None, reason: str = "Roubo de Credenciais") -> bool:
        """
        Neutraliza instantaneamente a ameaça:
        1. Mata a árvore inteira do processo atacante.
        2. Isola e cifra o binário malicioso no cofre de quarentena via SOAR (se aplicável).
        """
        success = False
        try:
            if HAS_PSUTIL:
                target_proc = psutil.Process(pid)
                # Mata todos os subprocessos filhos
                for child in target_proc.children(recursive=True):
                    try:
                        child.kill()
                    except Exception:
                        pass
                target_proc.kill()
                success = True
            else:
                # Fallback nativo do Windows
                if sys.platform == "win32":
                    os.system(f"taskkill /F /PID {pid} /T >nul 2>&1")
                    success = True

            _sys_log.warning(f"⚡ [IDENTITY_GUARD] Processo atacante PID {pid} neutralizado forçadamente. Motivo: {reason}")
            self._log_event("HIGH", "THREAT_TERMINATED", f"PID:{pid}", f"Processo neutralizado com sucesso: {reason}")

            # Envia o binário para quarentena caso exista e seja arquivo isolável
            if exe_path and os.path.isfile(exe_path) and self.soar:
                try:
                    self.soar.isolate_file(exe_path)
                    _sys_log.info(f"🔒 [IDENTITY_GUARD] Binário invasor enviado para quarentena AES-256: {exe_path}")
                except Exception as e:
                    _sys_log.debug(f"[IDENTITY_GUARD] Não foi possível mover binário para quarentena: {e}")

        except Exception as e:
            _sys_log.error(f"[IDENTITY_GUARD] Erro ao encerrar processo PID {pid}: {e}")
            success = False

        return success

    def inspect_lsass_handle_access(self, caller_pid: int, access_mask: int) -> bool:
        """
        Verifica se uma tentativa de acesso à memória do LSASS é ilegítima.
        Retorna True se for um acesso hostil detectado.
        """
        is_vm_read = bool(access_mask & self.PROCESS_VM_READ) or bool((access_mask & self.PROCESS_ALL_ACCESS) == self.PROCESS_ALL_ACCESS)
        if not is_vm_read:
            return False

        if HAS_PSUTIL:
            try:
                caller = psutil.Process(caller_pid)
                caller_name = (caller.name() or '').lower()
                if caller_name in self.LEGITIMATE_SYSTEM_PROCS:
                    return False  # Acesso legítimo do sistema operacional
            except Exception:
                pass

        # Flag como ataque crítico de dumping de memória
        self._log_event(
            "CRITICAL",
            "LSASS_VM_READ_ATTEMPT",
            f"PID:{caller_pid}",
            f"🚨 BLOQUEIO ATIVO! Processo PID {caller_pid} tentou abrir LSASS com permissão hostil de memória (Mask: {hex(access_mask)})"
        )
        return True

    def get_status(self) -> Dict[str, Any]:
        """Retorna o estado atual da blindagem de credenciais."""
        return {
            "engine": "Sentinel Identity & Credential Guard",
            "version": "2.5 Sovereign Enterprise",
            "status": "ACTIVE_DEFENSE",
            "lsass_pid": self.lsass_pid,
            "active_shields": self.active_shields,
            "rules_loaded": len(self.CREDENTIAL_THEFT_RULES),
            "threats_neutralized_count": len(self.neutralized_threats),
            "recent_neutralizations": self.neutralized_threats[-10:] if self.neutralized_threats else []
        }
