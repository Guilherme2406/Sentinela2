# uninstaller.py
import os
import sys
import shutil
import psutil
import logging

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

from sentinel_core.autostart_manager import WindowsAutoStartManager

def print_banner():
    print("\n" + "=" * 70)
    print("🗑️   ASSISTENTE DE DESINSTALAÇÃO DO SENTINEL XDR SOVEREIGN")
    print("=" * 70 + "\n")

def terminate_sentinel_processes():
    print("🛑 [1/4] Encerrando processos e serviços do Sentinela em execução...")
    terminated_count = 0
    current_pid = os.getpid()

    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if proc.pid == current_pid:
                continue
            cmdline = proc.info.get('cmdline') or []
            cmd_str = " ".join(cmdline).lower()

            if any(name in cmd_str for name in ("tray_app.pyw", "sentinela_service.py", "sentinel_api.py", "main.py")):
                proc.terminate()
                terminated_count += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
            pass

    print(f"   ✓ {terminated_count} processo(s) do Sentinela encerrado(s).")

def remove_system_integration():
    print("\n⚙️  [2/4] Removendo inicialização automática do Windows e regras de Firewall...")
    success, msg = WindowsAutoStartManager.disable_autostart()
    print(f"   ✓ {msg}")

    # Remove regras de Firewall criadas na instalação
    for rule in ("SENTINEL_XDR_DASHBOARD", "SENTINEL_XDR_TARPIT", "SENTINEL_XDR_HONEYPOT"):
        os.system(f'netsh advfirewall firewall delete rule name="{rule}" >nul 2>&1')
    print("   ✓ Regras de Firewall limpas.")

    print("\n🖥️  [3/4] Removendo atalhos do sistema...")
    desktop_dir = os.path.join(os.environ["USERPROFILE"], "Desktop")
    desktop_shortcut = os.path.join(desktop_dir, "SENTINEL XDR.lnk")
    if os.path.exists(desktop_shortcut):
        try:
            os.remove(desktop_shortcut)
            print("   ✓ Atalho da Área de Trabalho removido.")
        except Exception as e:
            print(f"   ! Não foi possível remover o atalho: {e}")
    else:
        print("   ✓ Nenhum atalho residual na Área de Trabalho.")

def handle_data_cleanup():
    print("\n💾 [4/4] GERENCIAMENTO DE DADOS SALVOS & QUARENTENA:")
    print("-" * 70)
    print("O que você deseja fazer com o histórico de logs, quarentena e cofres?")
    print("  [1] PRESERVAR dados salvos (Mantém logs, quarentena e cofres de rollback)")
    print("  [2] EXCLUSÃO TOTAL / PURGE (Apaga permanentemente logs, cofre e quarentena)")
    print("-" * 70)

    while True:
        choice = input("👉 Escolha uma opção [1 ou 2] (Padrão: 1): ").strip()
        if choice in ("1", ""):
            print("\n   🛡️  [PRESERVADO] Seus dados em 'sentinel_events.db', 'quarantine/' e 'sentinel_vault/' foram mantidos com segurança.")
            break
        elif choice == "2":
            confirm = input("\n⚠️  ATENÇÃO: Isso apagará permanentemente todos os eventos e arquivos na quarentena! Confirma? [S/N]: ").strip().upper()
            if confirm in ("S", "SIM", "Y", "YES"):
                data_files = [
                    os.path.join(BASE_DIR, "sentinel_events.db"),
                    os.path.join(BASE_DIR, "sentinel.key"),
                    os.path.join(BASE_DIR, "sentinel_daemon.log")
                ]
                data_dirs = [
                    os.path.join(BASE_DIR, "quarantine"),
                    os.path.join(BASE_DIR, "sentinel_vault"),
                    os.path.join(BASE_DIR, "restored"),
                    os.path.join(BASE_DIR, "canary_traps")
                ]
                
                for f in data_files:
                    if os.path.exists(f):
                        try:
                            os.remove(f)
                        except Exception:
                            pass
                
                for d in data_dirs:
                    if os.path.exists(d):
                        try:
                            shutil.rmtree(d, ignore_errors=True)
                        except Exception:
                            pass

                print("   🧹 [PURGE] Todos os logs, arquivos em quarentena e chaves foram excluídos permanentemente.")
            else:
                print("   🛡️  Ação cancelada. Dados preservados.")
            break
        else:
            print("Opção inválida. Digite 1 para Manter ou 2 para Apagar.")

def run_uninstallation():
    print_banner()
    terminate_sentinel_processes()
    remove_system_integration()
    handle_data_cleanup()

    print("\n" + "=" * 70)
    print("✅ DESINSTALAÇÃO CONCLUÍDA COM SUCESSO!")
    print("=" * 70)
    print("• O Sentinela XDR foi desvinculado da inicialização do Windows.")
    print("• Todos os serviços em segundo plano foram interrompidos.")
    print("=" * 70 + "\n")
    
    input("Pressione ENTER para finalizar...")

if __name__ == "__main__":
    run_uninstallation()
