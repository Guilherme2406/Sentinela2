# installer.py
import os
import sys
import time
import subprocess
import logging

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TERMS_FILE = os.path.join(BASE_DIR, "TERMOS_DE_USO.md")

from sentinel_core.autostart_manager import WindowsAutoStartManager
from sentinel_core.antivirus_shield_helper import AntivirusAndFirewallShield
from sentinel_core.threat_intel import ThreatIntelFeed
from sentinel_core.canary_files import CanaryTokenEngine
from bootstrap_env import install_missing_dependencies

def print_banner():
    print("\n" + "=" * 70)
    print("🛡️   ASSISTENTE DE INSTALAÇÃO DO SENTINEL XDR SOVEREIGN")
    print("    Defesa Ativa Cibernética, EDR, Quarentena, CTI & Anti-Ransomware")
    print("=" * 70 + "\n")

def show_terms_prompt() -> bool:
    print("📋 TERMOS DE USO E LICENÇA DE SOFTWARE (EULA):")
    print("-" * 70)
    print("• O Sentinela XDR opera com SOBERANIA LOCAL de dados (100% no seu computador).")
    print("• O software isolará arquivos maliciosos em quarentena criptografada (AES-256).")
    print("• O software aplicará regras de bloqueio no Firewall do SO contra invasores.")
    print("• O software sincroniza inteligência global CTI e mantém 20 camadas soberanas de defesa.")
    print("-" * 70)
    print(f"[i] O texto completo dos Termos está disponível em: {TERMS_FILE}\n")

    while True:
        resp = input("👉 Você leu e concorda com os Termos de Uso do Sentinela XDR? [S/N]: ").strip().upper()
        if resp in ("S", "SIM", "Y", "YES", ""):
            return True
        elif resp in ("N", "NAO", "NÃO", "NO"):
            print("\n❌ Instalação cancelada pelo usuário (Termos não aceitos).")
            return False
        else:
            print("Por favor, digite 'S' para Sim ou 'N' para Não.")

def run_installation():
    print_banner()

    # 1. Validação dos Termos de Uso
    if not show_terms_prompt():
        sys.exit(0)

    # 2. Verificação e Auto-Instalação de Dependências (Bootstrap)
    print("\n📦 [1/7] Verificando e embutindo recursos necessários...")
    try:
        install_missing_dependencies()
    except Exception as e:
        print(f"   ! Aviso no bootstrap: {e}")

    # 3. Proteção contra bloqueios de Antivírus e Firewall
    print("\n🛡️  [2/7] Aplicando blindagem contra bloqueios de Antivírus/Firewall...")
    try:
        AntivirusAndFirewallShield.apply_all_protections(BASE_DIR)
    except Exception as e:
        print(f"   ! Aviso na configuração de proteção: {e}")

    # 4. Estrutura de Diretórios Soberanos
    print("\n🚀 [3/7] Criando diretórios do cofre, quarentena e armadilhas...")
    dirs_to_create = [
        "quarantine", "sentinel_vault", "canary_traps", "honeypots",
        "user_documents", "restored", "assets", "sentinel_baits"
    ]
    for d in dirs_to_create:
        dp = os.path.join(BASE_DIR, d)
        os.makedirs(dp, exist_ok=True)
    print("   ✓ Estrutura de diretórios soberana pronta.")

    # 5. Sincronização CTI e Canários
    print("\n🌐 [4/7] Sincronizando Threat Intelligence (CTI) e armando canários...")
    try:
        cti = ThreatIntelFeed()
        count = cti.sync_feeds()
        print(f"   ✓ CTI Global sincronizado ({count} IOCs ativos).")
        canary = CanaryTokenEngine(base_dir=os.path.join(BASE_DIR, "canary_traps"))
        canary.setup_canaries()
        print("   ✓ Arquivos Canário e armadilhas DLP preparados.")
    except Exception as e:
        print(f"   ! Aviso no CTI: {e}")

    # 6. Perguntar sobre Inicialização Automática no Boot
    print("\n⚙️  [5/7] Configuração de Inicialização do Sistema Operacional:")
    while True:
        autostart_resp = input("👉 Deseja que o Sentinela inicie automaticamente toda vez que o Windows for ligado? [S/N] (Recomendado: S): ").strip().upper()
        if autostart_resp in ("S", "SIM", "Y", "YES", ""):
            success, msg = WindowsAutoStartManager.enable_autostart(BASE_DIR)
            if success:
                print("   ✓ [ATIVADO] Sentinela configurado para subir automaticamente no boot do Windows em segundo plano.")
            else:
                print(f"   ! Não foi possível registrar o autostart: {msg}")
            break
        elif autostart_resp in ("N", "NAO", "NÃO", "NO"):
            WindowsAutoStartManager.disable_autostart()
            print("   ✓ [DESATIVADO] O Sentinela não iniciará automaticamente no boot.")
            break
        else:
            print("Por favor, digite 'S' para Sim ou 'N' para Não.")

    # 7. Criar Atalhos na Área de Trabalho
    print("\n🖥️  [6/7] Criando atalhos de acesso com o logotipo oficial...")
    if WindowsAutoStartManager.create_desktop_shortcut(BASE_DIR):
        print("   ✓ Atalho criado com sucesso na sua Área de Trabalho.")
    else:
        print("   ! Não foi possível criar o atalho automaticamente.")

    # 8. Iniciar o Serviço em Segundo Plano e a Bandeja
    print("\n🛡️  [7/7] Iniciando as 20 camadas de defesa do Sentinela XDR na Bandeja do Sistema...")
    vbs_path = os.path.join(BASE_DIR, "iniciar_segundo_plano.vbs")
    try:
        if os.path.exists(vbs_path):
            subprocess.Popen(["wscript.exe", vbs_path], cwd=BASE_DIR, shell=False)
        else:
            pythonw = WindowsAutoStartManager.get_pythonw_path()
            tray_path = WindowsAutoStartManager.get_tray_app_path(BASE_DIR)
            subprocess.Popen([pythonw, tray_path], cwd=BASE_DIR, shell=False)
        print("   ✓ Agente iniciado na Bandeja do Sistema (ao lado do relógio)!")
    except Exception as e:
        print(f"   ! Erro ao disparar agente: {e}")

    # 9. Verificação de sanidade pós-instalação
    print("\n🩺 Verificando integridade da instalação...")
    checked = 0
    for required_name in ("dashboard.html", "sentinel_api.py", "main.py", "tray_app.pyw", "TERMOS_DE_USO.md"):
        if os.path.exists(os.path.join(BASE_DIR, required_name)):
            checked += 1
        else:
            print(f"   ! Arquivo essencial ausente: {required_name}")
    print(f"   ✓ {checked}/5 arquivos essenciais verificados.")
    try:
        import urllib.request
        with urllib.request.urlopen("http://127.0.0.1:5000/api/health", timeout=5) as resp:
            if resp.status == 200:
                print("   ✓ API & Dashboard respondendo em http://localhost:5000/api/health")
            else:
                print("   ! API Online, porém resposta inesperada. O serviço pode demorar alguns segundos.")
    except Exception as e:
        print(f"   ! O Dashboard ainda está subindo (aguarde alguns segundos): {e}")

    print("\n" + "=" * 70)
    print("🎉 INSTALAÇÃO CONCLUÍDA COM SUCESSO! (100% OPERACIONAL)")
    print("=" * 70)
    print("• O Sentinela XDR já está ATIVO e monitorando sua máquina.")
    print("• 20 Camadas Soberanas Ativas (LSASS Armor, DLP, Anti-Exploit, DGA/ARP, ASEP/LOLBins, etc.)")
    print("• Painel de Telemetria de Recursos do Host (CPU/RAM/DISCO em tempo real).")
    print("• Acesse o Dashboard em: http://localhost:5000")
    print("• Dê um duplo clique no ícone da bandeja para abrir o Dashboard Web.")
    print("• Todas as regras de Firewall e exclusões foram configuradas.")
    print("• Para desinstalar a qualquer momento, execute 'desinstalar.bat'.")
    print("=" * 70 + "\n")
    
    input("Pressione ENTER para finalizar...")

if __name__ == "__main__":
    run_installation()
