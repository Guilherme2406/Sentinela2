# sentinel_core/machine_identity.py
"""
Módulo de Identidade Soberana da Máquina (Hardware UUID & Pairing Engine).
Gera e gerencia a identidade imutável do endpoint local para vinculação com
a conta do usuário na nuvem (Vercel Cloud Console).
"""

import os
import sys
import uuid
import json
import socket
import platform
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional

IDENTITY_FILE = Path(__file__).resolve().parent.parent / "configs" / "machine_identity.json"

def _get_windows_machine_guid() -> Optional[str]:
    """Lê o MachineGuid nativo do Registro do Windows se estiver no Windows."""
    if sys.platform != "win32":
        return None
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        value, _ = winreg.QueryValueEx(key, "MachineGuid")
        winreg.CloseKey(key)
        if value and len(value) > 10:
            return str(value).strip().lower()
    except Exception:
        pass
    return None

def generate_hardware_id() -> str:
    """
    Gera um ID único, estável e imutável para a máquina local.
    Formato: SENT-XXXX-XXXX-XXXX
    """
    guid = _get_windows_machine_guid()
    node = str(uuid.getnode())
    hostname = socket.gethostname()
    system = platform.system()
    machine = platform.machine()
    
    raw_seed = f"{guid}|{node}|{hostname}|{system}|{machine}".encode("utf-8")
    digest = hashlib.sha256(raw_seed).hexdigest().upper()
    
    # Formata como chave de dispositivo elegante
    return f"SENT-{digest[:4]}-{digest[4:8]}-{digest[8:12]}"

def get_machine_info() -> Dict[str, Any]:
    """Retorna detalhes completos do hardware e sistema operacional local."""
    return {
        "hostname": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()} ({platform.version()})",
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "python_version": platform.python_version()
    }

def load_or_create_identity() -> Dict[str, Any]:
    """Carrega ou inicializa a identidade persistente do endpoint."""
    IDENTITY_FILE.parent.mkdir(parents=True, exist_ok=True)
    
    data = {}
    if IDENTITY_FILE.exists():
        try:
            with open(IDENTITY_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {}
            
    hwid = data.get("computer_id")
    if not hwid:
        hwid = generate_hardware_id()
        data["computer_id"] = hwid
        
    info = get_machine_info()
    data.update({
        "hostname": info["hostname"],
        "os": info["os"],
        "architecture": info["architecture"],
        "paired": data.get("paired", False),
        "user_email": data.get("user_email", ""),
        "cloud_url": data.get("cloud_url", ""),
        "sync_token": data.get("sync_token", ""),
        "created_at": data.get("created_at", None)
    })
    
    if not data.get("created_at"):
        import datetime
        data["created_at"] = datetime.datetime.now().isoformat()
        
    try:
        with open(IDENTITY_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
    except Exception:
        pass
        
    return data

def save_pairing_info(cloud_url: str, user_email: str, sync_token: str) -> bool:
    """Salva as credenciais de vinculação com a conta da nuvem."""
    identity = load_or_create_identity()
    identity["paired"] = True
    identity["cloud_url"] = cloud_url.rstrip("/")
    identity["user_email"] = user_email
    identity["sync_token"] = sync_token
    
    try:
        with open(IDENTITY_FILE, "w", encoding="utf-8") as f:
            json.dump(identity, f, indent=4, ensure_ascii=False)
        return True
    except Exception:
        return False

if __name__ == "__main__":
    ident = load_or_create_identity()
    print("Identidade do Computador Local:")
    print(json.dumps(ident, indent=2))
