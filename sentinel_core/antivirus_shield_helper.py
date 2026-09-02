# sentinel_core/antivirus_shield_helper.py
import os
import sys
import subprocess
import ctypes
import logging

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

class AntivirusAndFirewallShield:
    """
    Assistente de Auto-Blindagem e Compatibilidade contra Falsos-Positivos no Windows.
    Garante que o Windows Defender, SmartScreen e Firewall não bloqueiem a execução legítima.
    """

    FIREWALL_RULES = [
        {"name": "SENTINEL_XDR_DASHBOARD", "port": 5000, "protocol": "TCP", "desc": "Painel Web Sovereign Sentinela"},
        {"name": "SENTINEL_XDR_TARPIT", "port": 8888, "protocol": "TCP", "desc": "Contramedida Tarpit Sentinela"},
        {"name": "SENTINEL_XDR_HONEYPOT", "port": 2222, "protocol": "TCP", "desc": "Decepcao Ativa Honeypot Sentinela"}
    ]

    @staticmethod
    def is_admin() -> bool:
        """Verifica se o processo atual possui privilégios de Administrador no Windows."""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    @classmethod
    def unblock_project_files(cls, base_dir: str) -> bool:
        """
        Remove o bloqueio 'Mark of the Web' (Zone.Identifier) de todos os arquivos.
        Evita que o Windows SmartScreen bloqueie scripts baixados da web.
        """
        try:
            print("   🔓 Desbloqueando arquivos no Windows SmartScreen (Unblock-File)...")
            ps_cmd = f'Get-ChildItem -Path "{base_dir}" -Recurse | Unblock-File'
            cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd]
            subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return True
        except Exception as e:
            logging.debug(f"[SHIELD HELPER] Unblock-File: {e}")
            return False

    @classmethod
    def configure_windows_firewall(cls) -> bool:
        """Adiciona regras de entrada seguras no Windows Defender Firewall para as portas do Sentinela."""
        print("   🧱 Configurando regras de exceção no Windows Firewall...")
        success_count = 0

        for rule in cls.FIREWALL_RULES:
            name = rule["name"]
            port = rule["port"]
            proto = rule["protocol"]
            desc = rule["desc"]

            # 1. Remove regra anterior se existir
            del_cmd = f'netsh advfirewall firewall delete rule name="{name}"'
            subprocess.run(del_cmd, shell=True, capture_output=True)

            # 2. Adiciona a nova regra
            add_cmd = (
                f'netsh advfirewall firewall add rule name="{name}" '
                f'dir=in action=allow protocol={proto} localport={port} '
                f'description="{desc}" profile=any'
            )
            res = subprocess.run(add_cmd, shell=True, capture_output=True, text=True)
            if res.returncode == 0:
                success_count += 1

        if success_count > 0:
            print(f"   [✓] {success_count} regra(s) do Firewall aplicadas com sucesso.")
            return True
        else:
            print("   [!] Regras de Firewall necessitam de elevação (executar como Administrador).")
            return False

    @classmethod
    def configure_defender_exclusions(cls, base_dir: str) -> bool:
        """
        Adiciona a pasta do Sentinela e o processo pythonw às exclusões do Windows Defender.
        Impede que o antivírus interfira nas iscas canário, honeytokens ou cofres criptografados.
        """
        print("   🛡️  Registrando exceções de pasta e processo no Windows Defender...")
        try:
            # Exclusão de Pasta
            ps_path_cmd = f'Add-MpPreference -ExclusionPath "{base_dir}"'
            cmd1 = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_path_cmd]
            res1 = subprocess.run(cmd1, capture_output=True, text=True, timeout=10)

            # Exclusão de Processo
            ps_proc_cmd = 'Add-MpPreference -ExclusionProcess "pythonw.exe", "python.exe"'
            cmd2 = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_proc_cmd]
            res2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=10)

            if res1.returncode == 0 and res2.returncode == 0:
                print("   [✓] Exclusões no Windows Defender registradas com sucesso.")
                return True
            else:
                print("   [!] Para registrar exclusões no Defender, execute o instalador como Administrador.")
                return False
        except Exception as e:
            logging.debug(f"[SHIELD HELPER] Defender Exclusion: {e}")
            return False

    @classmethod
    def apply_all_protections(cls, base_dir: str):
        """Aplica todas as proteções contra bloqueios de antivírus e firewall."""
        print("\n" + "=" * 65)
        print("🛡️  BLINDAGEM CONTRA BLOQUEIOS DE ANTIVÍRUS E FIREWALL...")
        print("=" * 65)
        
        cls.unblock_project_files(base_dir)
        cls.configure_windows_firewall()
        cls.configure_defender_exclusions(base_dir)
        print("=" * 65)

if __name__ == "__main__":
    base = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    AntivirusAndFirewallShield.apply_all_protections(base)
