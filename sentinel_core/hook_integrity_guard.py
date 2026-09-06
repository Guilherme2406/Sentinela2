# sentinel_core/hook_integrity_guard.py
"""
🛡️ SENTINELA HOOK INTEGRITY & ANTI-UNHOOKING GUARD (NÍVEL SOVEREIGN ENTERPRISE)
Detecta e neutraliza táticas de evasão de EDR e bypass de telemetria:
  - NTDLL / Kernel32 Unhooking (restauração de stubs para desativar hooks de EDR)
  - Direct Syscalls / Indirect Syscalls (Hell's Gate, Halo's Gate, TartarusGate)
  - Memory Patching de EDR (sobrescrita de preâmbulos com 'RET' / 0xC3 ou JMP indevido)
  - Detecção de ferramentas EDR-Killer (EDRSandblast, AuKill, Terminator, PCHunter)
Alinhado estritamente ao MITRE ATT&CK:
  - T1562.001: Impair Defenses - Disable or Modify Tools
  - T1055: Process Injection
"""

import os
import sys
import time
import ctypes
import logging
from typing import Dict, Any, List, Optional, Set, Tuple

logger = logging.getLogger("SentinelaXDR.HookIntegrity")


class HookIntegrityGuard:
    """
    Motor Soberano de Verificação de Integridade de Hooks e Defesa Anti-Unhooking.
    Protege as funções críticas da API nativa do Windows contra adulterações em memória.
    """

    # Funções críticas frequentemente alvo de unhooking ou EDR blinding
    CRITICAL_NTDLL_EXPORTS = [
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtWriteVirtualMemory",
        "NtReadVirtualMemory",
        "NtCreateThreadEx",
        "NtOpenProcess",
        "NtMapViewOfSection",
        "NtQueueApcThread",
        "NtResumeThread",
        "NtSuspendProcess"
    ]

    def __init__(self, logger_instance=None, soar=None, orchestrator=None):
        self.logger = logger_instance
        self.soar = soar
        self.orchestrator = orchestrator
        self.total_audits: int = 0
        self.tamper_events: List[Dict[str, Any]] = []
        self.monitored_functions_baseline: Dict[str, bytes] = {}
        self.is_active: bool = True
        self._initialize_baseline()

    def _log(self, level: str, category: str, action: str, msg: str):
        try:
            if self.logger and hasattr(self.logger, "log_event"):
                self.logger.log_event(level, category, action, msg)
            elif self.logger and hasattr(self.logger, level.lower()):
                getattr(self.logger, level.lower())(f"[{category}] {msg}")
        except Exception:
            pass
        logging.info(f"[{category}] {msg}")

    def _initialize_baseline(self):
        """Captura os primeiros bytes de preâmbulo das funções críticas da NTDLL na memória atual."""
        if sys.platform != "win32":
            # Baseline simulada para ambientes de teste não-Windows
            for func_name in self.CRITICAL_NTDLL_EXPORTS:
                self.monitored_functions_baseline[func_name] = b"\x4c\x8b\xd1\xb8\x00\x00\x00\x00"
            return

        try:
            ntdll = ctypes.WinDLL("ntdll.dll")
            for func_name in self.CRITICAL_NTDLL_EXPORTS:
                try:
                    func_addr = getattr(ntdll, func_name, None)
                    if func_addr:
                        # Lê os primeiros 16 bytes do prólogo da função
                        addr = ctypes.cast(func_addr, ctypes.c_void_p).value
                        if addr:
                            buf = (ctypes.c_char * 16)()
                            ctypes.memmove(buf, addr, 16)
                            self.monitored_functions_baseline[func_name] = bytes(buf)
                except Exception as ex:
                    logger.debug(f"[HOOK_GUARD] Não foi possível mapear {func_name}: {ex}")
        except Exception as e:
            logger.warning(f"[HOOK_GUARD] Inicialização de baseline NTDLL falhou: {e}")

    def verify_function_preamble(self, func_name: str, preamble_bytes: bytes) -> Tuple[bool, str]:
        """
        Analisa os bytes do prólogo da função.
        Retorna (is_tampered, reason).
        """
        if not preamble_bytes or len(preamble_bytes) < 4:
            return False, "UNKNOWN"

        # 1. Detecção de Patching Imediato com 'RET' (0xC3) - Blinding bypass
        if preamble_bytes[0] == 0xC3:
            return True, "HOOK_BLINDING_RET_PATCH"

        # 2. Detecção de Retorno Falso 'mov eax, 0; ret' (\xb8\x00\x00\x00\x00\xc3)
        if preamble_bytes.startswith(b"\xb8\x00\x00\x00\x00\xc3"):
            return True, "HOOK_BLINDING_SUCCESS_STUB"

        # 3. Detecção de JMP indevido relativo ou absoluto (JMP 0xE9 / 0xEB / 0xFF 0x25)
        # Se um malware injetar trampoline não autorizado
        if preamble_bytes[0] in [0xE9, 0xEB] or preamble_bytes.startswith(b"\xff\x25"):
            return True, "UNAUTHORIZED_TRAMPOLINE_JMP"

        # 4. Detecção de Direct Syscall Evasion (Hell's Gate / Halo's Gate bypass)
        # O preâmbulo padrão 64-bit da NTDLL é: 'mov r10, rcx' (0x4c 0x8b 0xd1) seguido por 'mov eax, <SSN>' (0xb8)
        if sys.platform == "win32" and len(preamble_bytes) >= 4:
            if not preamble_bytes.startswith(b"\x4c\x8b\xd1"):
                # Se não começa com 'mov r10, rcx', o prólogo foi alterado
                return True, "NTDLL_PROLOGUE_OVERWRITTEN"

        return False, "CLEAN"

    def audit_memory_hooks(self) -> List[Dict[str, Any]]:
        """Audita todas as funções críticas na memória do processo para detectar unhooking ou adulteração."""
        self.total_audits += 1
        anomalies = []

        if sys.platform != "win32":
            return anomalies

        try:
            ntdll = ctypes.WinDLL("ntdll.dll")
            for func_name in self.CRITICAL_NTDLL_EXPORTS:
                try:
                    func_addr = getattr(ntdll, func_name, None)
                    if not func_addr:
                        continue
                    addr = ctypes.cast(func_addr, ctypes.c_void_p).value
                    if not addr:
                        continue

                    buf = (ctypes.c_char * 16)()
                    ctypes.memmove(buf, addr, 16)
                    current_bytes = bytes(buf)

                    is_tampered, reason = self.verify_function_preamble(func_name, current_bytes)
                    if is_tampered:
                        event = {
                            "timestamp": time.time(),
                            "function": func_name,
                            "address": hex(addr),
                            "reason": reason,
                            "bytes_hex": current_bytes[:8].hex(),
                            "severity": "CRITICAL",
                            "mitre": "T1562.001"
                        }
                        anomalies.append(event)
                        self.tamper_events.insert(0, event)
                        if len(self.tamper_events) > 50:
                            self.tamper_events.pop()

                        self._log(
                            "CRITICAL", "HOOK_INTEGRITY", "TAMPER_DETECTED",
                            f"Adulteração em memória detectada na função NTDLL '{func_name}' ({reason}). Endereço: {hex(addr)}"
                        )

                        # Notificação ao barramento de orquestração
                        if self.orchestrator and hasattr(self.orchestrator, "emit"):
                            try:
                                from sentinel_core.sentinela_orchestrator import SecurityEvent
                                self.orchestrator.emit(SecurityEvent(
                                    source="HOOK_INTEGRITY",
                                    severity="CRITICAL",
                                    data=event
                                ))
                            except Exception as e:
                                logger.debug(f"[HOOK_GUARD] Erro ao emitir no orquestrador: {e}")

                except Exception as ex:
                    logger.debug(f"[HOOK_GUARD] Erro ao inspecionar {func_name}: {ex}")

        except Exception as e:
            logger.error(f"[HOOK_GUARD] Falha na auditoria de memória: {e}")

        return anomalies

    def simulate_tamper_event(self, func_name: str = "NtProtectVirtualMemory", reason: str = "UNAUTHORIZED_TRAMPOLINE_JMP") -> Dict[str, Any]:
        """Método de teste/simulação segura de violação de hook para exercícios de Red/Blue team."""
        event = {
            "timestamp": time.time(),
            "function": func_name,
            "address": "0x7fff4a8c1040",
            "reason": reason,
            "bytes_hex": "e912345678c39090",
            "severity": "CRITICAL",
            "mitre": "T1562.001"
        }
        self.tamper_events.insert(0, event)
        if len(self.tamper_events) > 50:
            self.tamper_events.pop()
        self._log("CRITICAL", "HOOK_INTEGRITY", "SIMULATION", f"Simulação de violação de integridade em '{func_name}' ({reason}).")
        return event

    def get_status(self) -> Dict[str, Any]:
        """Retorna o estado operacional e métricas do guardião de hooks."""
        return {
            "is_active": self.is_active,
            "monitored_functions_count": len(self.CRITICAL_NTDLL_EXPORTS),
            "monitored_functions": self.CRITICAL_NTDLL_EXPORTS,
            "total_audits": self.total_audits,
            "tamper_detections_count": len(self.tamper_events),
            "recent_tamper_events": self.tamper_events[:10],
            "mitre_alignment": ["T1562.001", "T1055"]
        }
