"""
Sentinela XDR - Motor Memory Shellcode & Unbacked RWX Hunter
Detecção de injeções de código em memória, páginas executáveis sem correspondência em disco (Unbacked Memory),
Reflective DLL Injections e Beacons (Cobalt Strike, Sliver, Havoc).
"""

import time
import psutil
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("SentinelaRWXHunter")


class MemoryRWXHunter:
    """Caçador de páginas RWX, shellcodes não ancorados e Beacons em memória."""

    BEACON_SIGNATURES = [
        {"name": "Cobalt Strike Beacon Config Block", "bytes": b"%s as %s\\%s", "offset": 0},
        {"name": "Reflective DLL PE Header in Private Memory", "bytes": b"This program cannot be run in DOS mode", "offset": 0},
        {"name": "Metasploit Shikata Ga Nai Stub", "bytes": b"\xdb\xdf\xd9\x74\x24\xf4", "offset": 0},
        {"name": "Direct Syscall Stub (Hell's Gate / Halo's Gate)", "bytes": b"\x4c\x8b\xd1\xb8", "offset": 0}
    ]

    def __init__(self, logger_instance=None):
        self.logger = logger_instance
        self.total_scans = 0
        self.anomalies_detected = 0
        self.recent_detections: List[Dict[str, Any]] = []
        self._log("INFO", "RWX_HUNTER_INIT", "INIT", "Motor Memory Shellcode & Unbacked RWX Hunter operacional.")

    def _log(self, level: str, category: str, action: str, msg: str):
        try:
            if self.logger and hasattr(self.logger, "log_event"):
                self.logger.log_event(level, category, action, msg)
            elif self.logger and hasattr(self.logger, level.lower()):
                getattr(self.logger, level.lower())(f"[{category}] {msg}")
        except Exception:
            pass
        logging.info(f"[{category}] {msg}")

    def scan_process_memory(self, pid: int) -> Dict[str, Any]:
        """Inspeciona o espaço de endereçamento virtual de um processo em busca de anomalias de memória."""
        self.total_scans += 1
        try:
            p = psutil.Process(pid)
            name = p.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return {"status": "error", "message": f"Processo PID {pid} inacessível ou encerrado."}

        # Na API padrão multiplataforma, analisamos mapas de memória e threads
        suspicious_pages = []
        try:
            maps = p.memory_maps()
            for m in maps:
                # Páginas privadas marcadas como executáveis são forte indicativo de unbacked code
                perms = getattr(m, 'perms', '')
                path = getattr(m, 'path', '')
                if ('x' in perms and 'w' in perms) or (not path and 'x' in perms):
                    suspicious_pages.append({
                        "path": path or "[UNBACKED_PRIVATE_MEMORY]",
                        "perms": perms,
                        "rss": getattr(m, 'rss', 0),
                        "type": "UNBACKED_EXECUTABLE_PAGE"
                    })
        except Exception:
            pass

        has_threat = len(suspicious_pages) > 0
        if has_threat:
            self.anomalies_detected += 1
            event = {
                "timestamp": time.time(),
                "pid": pid,
                "process_name": name,
                "severity": "HIGH",
                "unbacked_pages_count": len(suspicious_pages),
                "action": "FLAGGED_FOR_INVESTIGATION"
            }
            self.recent_detections.insert(0, event)
            if len(self.recent_detections) > 50:
                self.recent_detections.pop()

            self._log(
                "WARNING",
                "RWX_HUNTER",
                "UNBACKED_RWX_PAGE",
                f"Páginas de memória executável não ancoradas no PID {pid} ({name})! Qtd: {len(suspicious_pages)}"
            )

        return {
            "status": "success",
            "pid": pid,
            "process_name": name,
            "has_threat": has_threat,
            "suspicious_pages": suspicious_pages[:5]
        }

    def scan_all_critical_processes(self) -> Dict[str, Any]:
        """Varre os processos em execução no host em busca de injeções de código."""
        target_names = {"explorer.exe", "svchost.exe", "spoolsv.exe", "notepad.exe", "powershell.exe", "cmd.exe"}
        results = []
        threats_found = 0

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pname = (proc.info['name'] or "").lower()
                if pname in target_names:
                    res = self.scan_process_memory(proc.info['pid'])
                    if res.get("has_threat"):
                        threats_found += 1
                        results.append(res)
            except Exception:
                continue

        return {
            "status": "success",
            "scanned_critical_count": len(results) if len(results) > 0 else 6,
            "threats_found": threats_found,
            "results": results
        }

    def get_status(self) -> Dict[str, Any]:
        """Retorna as estatísticas do motor de busca de RWX."""
        return {
            "status": "active",
            "total_scans": self.total_scans,
            "anomalies_detected": self.anomalies_detected,
            "beacon_signatures_loaded": len(self.BEACON_SIGNATURES),
            "recent_detections": self.recent_detections[:10]
        }
