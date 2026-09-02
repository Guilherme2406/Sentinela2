# sentinel_core/autostart_manager.py
import os
import sys
import winreg
import logging
from typing import Tuple, Optional

class WindowsAutoStartManager:
    """
    Gerenciador de Inicialização Automática e Atalhos no Sistema Windows.
    Controla o registro no boot via HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run.
    """

    APP_NAME = "SentinelXDR_Shield"
    REG_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"

    @classmethod
    def get_pythonw_path(cls) -> str:
        """Localiza o binário pythonw.exe para execução 100% silenciosa sem tela preta."""
        python_dir = os.path.dirname(sys.executable)
        pythonw_candidate = os.path.join(python_dir, "pythonw.exe")
        if os.path.exists(pythonw_candidate):
            return pythonw_candidate
        return sys.executable

    @classmethod
    def get_tray_app_path(cls, base_dir: Optional[str] = None) -> str:
        """Retorna o caminho absoluto do script da bandeja (tray_app.pyw)."""
        if not base_dir:
            base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        return os.path.join(base_dir, "tray_app.pyw")

    @classmethod
    def get_vbs_launcher_path(cls, base_dir: Optional[str] = None) -> str:
        """Retorna o caminho absoluto do inicializador silencioso VBScript."""
        if not base_dir:
            base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        return os.path.join(base_dir, "iniciar_segundo_plano.vbs")

    @classmethod
    def is_autostart_enabled(cls) -> bool:
        """Verifica se o Sentinela está configurado para iniciar com o Windows."""
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, cls.REG_KEY, 0, winreg.KEY_READ) as key:
                val, _ = winreg.QueryValueEx(key, cls.APP_NAME)
                return bool(val)
        except (FileNotFoundError, OSError):
            return False

    @classmethod
    def enable_autostart(cls, base_dir: Optional[str] = None) -> Tuple[bool, str]:
        """
        Registra o Sentinela no Registro do Windows para subir com o boot em segundo plano.
        """
        try:
            if not base_dir:
                base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

            vbs_path = cls.get_vbs_launcher_path(base_dir)
            
            # Se o VBS existir, utiliza wscript.exe para garantir silêncio absoluto
            if os.path.exists(vbs_path):
                command = f'wscript.exe "{vbs_path}"'
            else:
                pythonw = cls.get_pythonw_path()
                tray_script = cls.get_tray_app_path(base_dir)
                command = f'"{pythonw}" "{tray_script}"'

            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, cls.REG_KEY, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, cls.APP_NAME, 0, winreg.REG_SZ, command)

            logging.info(f"[AUTOSTART] Inicialização automática ativada no Registro: {command}")
            return True, "Inicialização automática ativada com sucesso no Windows."
        except Exception as e:
            err_msg = f"Falha ao registrar no Registro do Windows: {e}"
            logging.error(f"[AUTOSTART ERROR] {err_msg}")
            return False, err_msg

    @classmethod
    def disable_autostart(cls) -> Tuple[bool, str]:
        """Remove a entrada do Sentinela da inicialização do Windows."""
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, cls.REG_KEY, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, cls.APP_NAME)
            logging.info("[AUTOSTART] Inicialização automática desativada no Registro.")
            return True, "Inicialização automática desativada."
        except FileNotFoundError:
            return True, "O software já não estava configurado para iniciar com o Windows."
        except Exception as e:
            err_msg = f"Falha ao remover do Registro: {e}"
            logging.error(f"[AUTOSTART ERROR] {err_msg}")
            return False, err_msg

    @classmethod
    def create_desktop_shortcut(cls, base_dir: Optional[str] = None) -> bool:
        """Cria atalho na Área de Trabalho e no Menu Iniciar do Windows via VBS / WScript.Shell."""
        try:
            if not base_dir:
                base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

            desktop_dir = os.path.join(os.environ["USERPROFILE"], "Desktop")
            shortcut_path = os.path.join(desktop_dir, "SENTINEL XDR.lnk")
            vbs_target = cls.get_vbs_launcher_path(base_dir)
            icon_candidate = os.path.join(base_dir, "assets", "sentinel_icon.ico")

            vbs_script = f"""
Set ws = WScript.CreateObject("WScript.Shell")
Set s = ws.CreateShortcut("{shortcut_path.replace(chr(92), chr(92)+chr(92))}")
s.TargetPath = "wscript.exe"
s.Arguments = """"{vbs_target.replace(chr(92), chr(92)+chr(92))}""""
s.WorkingDirectory = "{base_dir.replace(chr(92), chr(92)+chr(92))}"
s.Description = "SENTINEL XDR - Sovereign Cyber Defense Shield"
If ws.CreateObject("Scripting.FileSystemObject").FileExists("{icon_candidate.replace(chr(92), chr(92)+chr(92))}") Then
    s.IconLocation = "{icon_candidate.replace(chr(92), chr(92)+chr(92))}, 0"
End If
s.Save
"""
            temp_vbs = os.path.join(base_dir, "_temp_shortcut.vbs")
            with open(temp_vbs, "w", encoding="utf-8") as f:
                f.write(vbs_script)

            os.system(f'cscript //nologo "{temp_vbs}"')
            if os.path.exists(temp_vbs):
                os.remove(temp_vbs)

            return True
        except Exception as e:
            logging.error(f"[SHORTCUT ERROR] {e}")
            return False
