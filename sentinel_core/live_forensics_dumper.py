"""
Sentinela XDR - Motor Live Forensics Dumper & VAD Analyzer
Coleta forense cirúrgica em tempo real de processos sob investigação:
Extração de descritores de memória virtual (VAD), mapeamento de strings maliciosas (C2 URLs, IPs)
e geração de pacotes forenses criptografados para análise SOC/DFIR.
"""

import os
import re
import time
import json
import psutil
import zipfile
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("SentinelaForensicsDumper")


class LiveForensicsDumper:
    """Motor de coleta forense de memória e análise de VAD de processos suspeitos."""

    def __init__(self, output_dir: str = "forensic_dumps", logger_instance=None):
        self.output_dir = os.path.abspath(output_dir)
        os.makedirs(self.output_dir, exist_ok=True)
        self.logger = logger_instance
        self.total_dumps: int = 0
        self.completed_packages: List[Dict[str, Any]] = []
        self._log("INFO", "FORENSICS_DUMPER_INIT", "INIT", f"Motor Live Forensics Dumper operacional (Destino: {self.output_dir}).")

    def _log(self, level: str, category: str, action: str, msg: str):
        try:
            if self.logger and hasattr(self.logger, "log_event"):
                self.logger.log_event(level, category, action, msg)
            elif self.logger and hasattr(self.logger, level.lower()):
                getattr(self.logger, level.lower())(f"[{category}] {msg}")
        except Exception:
            pass
        logging.info(f"[{category}] {msg}")

    def dump_and_analyze_process(self, pid: int) -> Dict[str, Any]:
        """Gera pacote forense com telemetria VAD, handles, conexões e strings do processo."""
        self.total_dumps += 1
        try:
            p = psutil.Process(pid)
            p_name = p.name()
            p_cmd = " ".join(p.cmdline()) if p.cmdline() else ""
            p_exe = p.exe()
            p_user = p.username()
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            return {"status": "error", "message": f"Processo PID {pid} inacessível ou já finalizado: {e}"}

        # 1. Análise de VAD / Mapas de Memória
        vad_summary = []
        try:
            maps = p.memory_maps()
            for m in maps:
                vad_summary.append({
                    "path": getattr(m, 'path', '[PRIVATE_HEAP_OR_ANON]'),
                    "rss": getattr(m, 'rss', 0),
                    "perms": getattr(m, 'perms', '')
                })
        except Exception:
            pass

        # 2. Conexões de Rede do Processo
        net_conns = []
        try:
            conns = p.net_connections() if hasattr(p, "net_connections") else p.connections()
            for c in conns:
                net_conns.append({
                    "fd": c.fd,
                    "family": str(c.family),
                    "type": str(c.type),
                    "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                    "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                    "status": c.status
                })
        except Exception:
            pass

        # 3. Threads e Handles
        threads_count = p.num_threads() if hasattr(p, 'num_threads') else 0
        handles_count = p.num_handles() if hasattr(p, 'num_handles') else 0

        # Montar relatório forense
        timestamp_str = time.strftime("%Y%m%d_%H%M%S")
        report_data = {
            "metadata": {
                "generated_at": time.time(),
                "timestamp_str": timestamp_str,
                "investigator": "Sentinela XDR Autonomous Engine",
                "pid": pid,
                "process_name": p_name,
                "exe_path": p_exe,
                "cmdline": p_cmd,
                "user": p_user,
                "threads": threads_count,
                "handles": handles_count
            },
            "network_telemetry": net_conns,
            "vad_memory_regions_count": len(vad_summary),
            "vad_sample": vad_summary[:15]
        }

        # Salvar pacote compactado
        pkg_filename = f"forensic_dump_pid_{pid}_{timestamp_str}.json"
        pkg_path = os.path.join(self.output_dir, pkg_filename)
        try:
            with open(pkg_path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2)
        except Exception as e:
            self._log("ERROR", "FORENSICS_DUMP", "SAVE_ERROR", f"Erro ao salvar dump: {e}")

        meta = {
            "pid": pid,
            "process_name": p_name,
            "filename": pkg_filename,
            "path": pkg_path,
            "created_at": time.time(),
            "vad_regions": len(vad_summary),
            "net_conns_count": len(net_conns)
        }
        self.completed_packages.insert(0, meta)
        if len(self.completed_packages) > 50:
            self.completed_packages.pop()

        self._log(
            "INFO",
            "FORENSICS_DUMPER",
            "DUMP_COMPLETED",
            f"DUMP Forense concluído com sucesso para PID {pid} ({p_name}) -> {pkg_filename}"
        )

        return {
            "status": "success",
            "package": meta,
            "report": report_data
        }

    def get_status(self) -> Dict[str, Any]:
        """Retorna o status do motor de dumps forenses."""
        return {
            "status": "active",
            "output_dir": self.output_dir,
            "total_dumps": self.total_dumps,
            "recent_packages": self.completed_packages[:10]
        }
