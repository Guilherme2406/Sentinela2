# sentinel_core/sysmon_installer.py
"""
🛡️ SENTINELA SYSMON LIFECYCLE & INSTALLATION MANAGER
Gerencia detecção, status de integridade e automação de instalação do Microsoft Sysmon
com configuração endurecida para telemetria de Ring 3 e visibilidade forense de processos e rede.
"""

import os
import sys
import json
import time
import shutil
import ctypes
import logging
import subprocess
from typing import Dict, Any, Optional

logger = logging.getLogger("SentinelaXDR.SysmonInstaller")


class SysmonInstallerManager:
    """Orquestrador do ciclo de vida e configuração do Sysmon no Windows."""

    SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

    def __init__(self, project_root: Optional[str] = None):
        if project_root is None:
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.project_root = project_root
        self.config_path = os.path.join(
            self.project_root, "configs", "sysmon", "sysmon-config-hardened.xml"
        )
        self.script_path = os.path.join(
            self.project_root, "scripts", "install_sysmon.ps1"
        )
        self.vault_dir = os.path.join(self.project_root, "sentinel_vault")
        os.makedirs(self.vault_dir, exist_ok=True)
        self.state_file = os.path.join(self.vault_dir, "sysmon_install_state.json")

    @staticmethod
    def is_admin() -> bool:
        """Verifica se o processo atual roda com privilégios de Administrador."""
        if sys.platform != "win32":
            return False
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def get_status(self) -> Dict[str, Any]:
        """Retorna diagnóstico completo do Sysmon no host."""
        is_win = sys.platform == "win32"
        admin = self.is_admin()
        service_installed = False
        service_running = False
        channel_active = False
        service_name = None

        if is_win:
            # Checa serviço do Windows
            for sname in ["Sysmon", "Sysmon64"]:
                try:
                    res = subprocess.run(
                        ["sc", "query", sname],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    if res.returncode == 0:
                        service_installed = True
                        service_name = sname
                        if "RUNNING" in res.stdout:
                            service_running = True
                        break
                except Exception:
                    pass

            # Checa canal de eventos via wevtutil
            try:
                evt_res = subprocess.run(
                    ["wevtutil", "gl", self.SYSMON_CHANNEL],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if evt_res.returncode == 0 and "enabled: true" in evt_res.stdout.lower():
                    channel_active = True
            except Exception:
                pass

        # Lê estado persistido, se existir
        state_data = {}
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    state_data = json.load(f)
            except Exception:
                pass

        config_exists = os.path.exists(self.config_path)

        return {
            "platform_windows": is_win,
            "is_admin": admin,
            "service_installed": service_installed,
            "service_running": service_running,
            "service_name": service_name,
            "channel_active": channel_active,
            "config_exists": config_exists,
            "config_path": self.config_path,
            "script_exists": os.path.exists(self.script_path),
            "state_manifest": state_data,
            "recommendation": (
                "Pronto para telemetria profunda."
                if (service_running and channel_active)
                else "Instale ou ative o Sysmon via powershell com privilégios de Administrador."
            )
        }

    def get_install_command(self, force: bool = False) -> str:
        """Gera comando PowerShell recomendado para execução por um administrador."""
        cmd = f"powershell -ExecutionPolicy Bypass -File \"{self.script_path}\""
        if force:
            cmd += " -ForceUpdate"
        return cmd

    def install(self, force_update: bool = False, custom_config: Optional[str] = None) -> Dict[str, Any]:
        """
        Executa a instalação ou atualização do Sysmon caso elevado.
        Se não estiver elevado, retorna erro estruturado com instrução clara.
        """
        if sys.platform != "win32":
            return {
                "status": "error",
                "code": "NON_WINDOWS",
                "message": "Sysmon só é suportado em ambientes Microsoft Windows."
            }

        if not self.is_admin():
            cmd = self.get_install_command(force=force_update)
            logger.warning("[SYSMON INSTALLER] Privilégios insuficientes. Comando manual: %s", cmd)
            return {
                "status": "error",
                "code": "ELEVATION_REQUIRED",
                "message": "Privilégios de Administrador são necessários para instalar o driver Sysmon.",
                "recommended_command": cmd
            }

        config_to_use = custom_config or self.config_path
        if not os.path.exists(config_to_use):
            return {
                "status": "error",
                "code": "CONFIG_NOT_FOUND",
                "message": f"Arquivo de configuração do Sysmon não encontrado: {config_to_use}"
            }

        try:
            ps_args = [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-File", self.script_path,
                "-ConfigPath", config_to_use
            ]
            if force_update:
                ps_args.append("-ForceUpdate")

            res = subprocess.run(
                ps_args,
                capture_output=True,
                text=True,
                timeout=120
            )

            success = (res.returncode == 0)
            status_summary = self.get_status()

            return {
                "status": "success" if success else "failed",
                "return_code": res.returncode,
                "stdout": res.stdout,
                "stderr": res.stderr,
                "sysmon_status": status_summary
            }
        except subprocess.TimeoutExpired:
            return {
                "status": "error",
                "code": "TIMEOUT",
                "message": "Tempo limite esgotado ao executar o instalador do Sysmon."
            }
        except Exception as exc:
            return {
                "status": "error",
                "code": "EXEC_EXCEPTION",
                "message": str(exc)
            }
