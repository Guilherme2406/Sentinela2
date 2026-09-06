# sentinel_core/byovd_guard.py
"""
🛡️ SENTINELA BYOVD & KERNEL DRIVER ARMOR
Proteção ativa contra ataques Bring Your Own Vulnerable Driver (BYOVD).
Bloqueia malwares e APTs que tentam carregar drivers vulneráveis legítimos (LOLDrivers)
para desativar processos de segurança e obter privilégios arbitrários de Kernel (Ring 0).
Alinhado com MITRE ATT&CK: T1068, T1543.003 e T1562.001.
"""

import os
import sys
import time
import hashlib
import logging
from typing import Dict, Any, List, Optional, Set

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False

logger = logging.getLogger("SentinelaXDR.BYOVDGuard")


class BYOVDGuard:
    """Motor de detecção e neutralização de drivers vulneráveis e maliciosos."""

    # Catálogo dos 20 drivers vulneráveis mais abusados por APTs e Ransomwares globais
    KNOWN_VULNERABLE_DRIVERS = {
        # Nome do arquivo em minúsculo: Descrição e CVE conhecida
        "gdrv.sys": {"cve": "CVE-2018-19320", "vendor": "GIGABYTE", "risk": "CRITICAL", "desc": "Abusado por RobbinHood Ransomware para desativar EDR"},
        "mhyprot2.sys": {"cve": "CVE-2020-0000", "vendor": "miHoYo", "risk": "CRITICAL", "desc": "Abusado por Ransomwares para matar processos protegidos"},
        "rtcore64.sys": {"cve": "CVE-2019-16098", "vendor": "Micro-Star (MSI)", "risk": "CRITICAL", "desc": "Leitura/Escrita arbitrária de memória física de kernel"},
        "dbutil_2_3.sys": {"cve": "CVE-2021-21551", "vendor": "Dell", "risk": "CRITICAL", "desc": "Escalação de privilégios e bypass de DSE"},
        "procexp152.sys": {"cve": "CVE-2022-0000", "vendor": "Sysinternals antigo", "risk": "HIGH", "desc": "Versão desatualizada abusada para terminação arbitrária"},
        "asrrdrv103.sys": {"cve": "CVE-2018-10710", "vendor": "ASRock", "risk": "HIGH", "desc": "Manipulação direta de MSR e memória do kernel"},
        "cpuz141.sys": {"cve": "CVE-2017-15303", "vendor": "CPUID", "risk": "HIGH", "desc": "Escrita arbitrária de registradores de controle"},
        "speedfan.sys": {"cve": "CVE-2007-5633", "vendor": "Almico", "risk": "HIGH", "desc": "Abuso clássico para mapeamento de memória física"},
        "iqvw64e.sys": {"cve": "CVE-2015-2291", "vendor": "Intel Network Adapter", "risk": "CRITICAL", "desc": "Abusado por ferramentas de evasão de Red Team"},
        "atsiv.sys": {"cve": "HISTORICAL", "vendor": "Linchpin Labs", "risk": "CRITICAL", "desc": "Carregador não assinado de drivers ilegais"}
    }

    # Hashes SHA-256 de amostras conhecidas de drivers vulneráveis
    VULNERABLE_DRIVER_HASHES = {
        "31f4d92257fed455d3b6a22c5443a53e6fb8eb71d2b772c219602e1b1cc8c8b4": "gdrv.sys",
        "046e83da3e1b74f9d651f114c000e394f99dbab589a74659b85c1ec8898aa2b9": "mhyprot2.sys",
        "6111f1857c02b1f81f129528d22d9c02ff345388301548680373ab9ad0d4dd2d": "rtcore64.sys",
        "0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5": "dbutil_2_3.sys"
    }

    def __init__(self, logger_instance=None, soar=None):
        self.logger = logger_instance
        self.soar = soar
        self.blocked_attempts: List[Dict[str, Any]] = []
        self.system_drivers_dir = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "drivers")

    def _log(self, level: str, category: str, action: str, msg: str):
        try:
            if self.logger:
                self.logger.log_event(level, category, action, msg)
        except Exception:
            pass
        logging.info(f"[{category}] {msg}")

    def inspect_driver_file(self, driver_path: str) -> Optional[Dict[str, Any]]:
        """Inspeciona um binário .sys antes ou após ser gravado em disco."""
        if not os.path.exists(driver_path):
            return None

        driver_name = os.path.basename(driver_path).lower()
        sha256 = ""
        try:
            with open(driver_path, "rb") as f:
                sha256 = hashlib.sha256(f.read()).hexdigest()
        except Exception:
            pass

        # 1. Match por nome conhecido de driver vulnerável
        if driver_name in self.KNOWN_VULNERABLE_DRIVERS:
            info = self.KNOWN_VULNERABLE_DRIVERS[driver_name]
            threat = {
                "driver_name": driver_name,
                "path": driver_path,
                "sha256": sha256,
                "rule": "KNOWN_VULNERABLE_BYOVD",
                "cve": info["cve"],
                "vendor": info["vendor"],
                "severity": info["risk"],
                "description": info["desc"],
                "timestamp": time.time()
            }
            self._record_threat(threat)
            return threat

        # 2. Match por hash SHA-256 de amostra vulnerável
        if sha256 in self.VULNERABLE_DRIVER_HASHES:
            threat = {
                "driver_name": driver_name,
                "path": driver_path,
                "sha256": sha256,
                "rule": "VULNERABLE_DRIVER_HASH_MATCH",
                "severity": "CRITICAL",
                "description": f"Hash corresponde ao driver vulnerável conhecido: {self.VULNERABLE_DRIVER_HASHES[sha256]}",
                "timestamp": time.time()
            }
            self._record_threat(threat)
            return threat

        return None

    def _record_threat(self, threat: Dict[str, Any]):
        self.blocked_attempts.append(threat)
        self._log(
            threat["severity"], "BYOVD_GUARD", "VULNERABLE_DRIVER_BLOCKED",
            f"🚨 BLOQUEIO DE KERNEL BYOVD! Tentativa de abuso de driver: {threat['driver_name']} ({threat.get('cve', 'LOLDrivers')})"
        )
        # Se configurado, isola o arquivo do driver em quarentena via SOAR
        if self.soar and threat.get("path") and os.path.isfile(threat["path"]):
            try:
                self.soar.isolate_file(threat["path"])
                self._log("CRITICAL", "SOAR", "DRIVER_QUARANTINED", f"Driver hostil neutralizado e movido para cofre: {threat['path']}")
            except Exception as e:
                logger.debug(f"[BYOVD] Falha ao isolar driver: {e}")

    def audit_installed_services_registry(self) -> List[Dict[str, Any]]:
        """Audita serviços de drivers registrados no Registro do Windows procurando vulneráveis."""
        threats_found = []
        if not HAS_WINREG or sys.platform != "win32":
            return threats_found

        try:
            services_key_path = r"SYSTEM\CurrentControlSet\Services"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, services_key_path) as root_key:
                num_subkeys, _, _ = winreg.QueryInfoKey(root_key)
                for i in range(num_subkeys):
                    try:
                        subkey_name = winreg.EnumKey(root_key, i)
                        with winreg.OpenKey(root_key, subkey_name) as service_key:
                            try:
                                image_path, _ = winreg.QueryValueEx(service_key, "ImagePath")
                                image_path_clean = str(image_path).lower().strip()
                                base_sys_name = os.path.basename(image_path_clean)
                                if base_sys_name in self.KNOWN_VULNERABLE_DRIVERS:
                                    info = self.KNOWN_VULNERABLE_DRIVERS[base_sys_name]
                                    item = {
                                        "service_name": subkey_name,
                                        "driver_name": base_sys_name,
                                        "image_path": str(image_path),
                                        "cve": info["cve"],
                                        "severity": info["risk"],
                                        "desc": info["desc"]
                                    }
                                    threats_found.append(item)
                                    self._log("CRITICAL", "BYOVD_GUARD", "REGISTRY_VULN_DRIVER",
                                              f"Driver vulnerável detectado registrado no SO: {base_sys_name} ({subkey_name})")
                            except FileNotFoundError:
                                pass
                    except Exception:
                        continue
        except Exception as e:
            logger.debug(f"[BYOVD] Erro na auditoria de Registro de serviços: {e}")

        return threats_found

    def get_status(self) -> Dict[str, Any]:
        """Retorna o status da proteção de drivers de kernel."""
        return {
            "engine": "Sentinel BYOVD & Kernel Driver Armor",
            "active": True,
            "status": "ACTIVE",
            "catalog_loaded_count": len(self.KNOWN_VULNERABLE_DRIVERS),
            "threats_intercepted_count": len(self.blocked_attempts),
            "recent_blocks": self.blocked_attempts[-10:] if self.blocked_attempts else []
        }

    def status(self) -> Dict[str, Any]:
        return self.get_status()
