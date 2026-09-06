# sentinel_core/sentinel_cli.py
import os
import sys

from typing import Optional
from sentinel_core.logger import SecurityEventLogger
from sentinel_core.crypto_vault import CryptoVault
from sentinel_core.auto_response import AutoResponseEngine
from sentinel_core.threat_detector import ThreatDetector

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

def find_project_root() -> str:
    candidates = [
        os.getcwd(),
        os.path.dirname(__file__),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..")),
    ]
    for path in candidates:
        if os.path.exists(os.path.join(path, "sentinel_events.db")) or os.path.exists(os.path.join(path, "main.py")):
            return os.path.abspath(path)
    return os.getcwd()

ROOT_DIR = find_project_root()
DB_PATH = os.path.join(ROOT_DIR, "sentinel_events.db")
KEY_PATH = os.path.join(ROOT_DIR, "sentinel.key")
QUARANTINE_PATH = os.path.join(ROOT_DIR, "quarantine")

logger = SecurityEventLogger(DB_PATH)
vault = CryptoVault(KEY_PATH)
soar = AutoResponseEngine(logger, vault, quarantine_dir=QUARANTINE_PATH)
detector = ThreatDetector(logger)

def show_menu():
    print("\n" + "=" * 65)
    print("🛡️   SENTINELA SECURITY ENGINE (XDR / SIEM / SOAR) - CLI")
    print("=" * 65)
    print(" [1]  Visualizar todos os eventos recentes")
    print(" [2]  Filtrar eventos por severidade (INFO, WARNING, HIGH, CRITICAL)")
    print(" [3]  Filtrar eventos por categoria (FIM, PROCESS, NETWORK, SYSTEM, MALWARE)")
    print(" [4]  Resumo de estatísticas e métricas do SIEM")
    print(" [5]  [SOAR] Isolar arquivo suspeito na quarentena")
    print(" [6]  [SOAR] Listar / Restaurar arquivos da quarentena")
    print(" [7]  [SOAR] Encerrar processo suspeito por PID")
    print(" [8]  [DETECTOR] Analisar arquivo por Hash SHA-256 / IOC")
    print(" [9]  [EDR] Varredura e Auto-Remediação de Processos Suspeitos")
    print(" [10] [FIREWALL] Listar e Gerenciar IPs Banidos no SO")
    print(" [11] [IA] Análise Preditiva de Entropia de Shannon / Zero-Day")
    print(" [12] [SYSMON] Diagnóstico e Instalação da Telemetria de Kernel")
    print(" [13] Limpar banco de dados de eventos")
    print(" [0]  Sair")
    print("=" * 65)


def list_events(severity: Optional[str] = None, category: Optional[str] = None):
    events = logger.get_filtered_events(severity=severity, category=category, limit=50)
    print(f"\n📊 --- EXIBINDO {len(events)} EVENTOS RECENTES ---")
    if not events:
        print("Nenhum registro encontrado para os filtros selecionados.")
    else:
        for r in events:
            sev = r['severity']
            badge = f"[{sev}]"
            if sev == "CRITICAL":
                badge = f"🔴 [{sev}]"
            elif sev == "HIGH":
                badge = f"🟠 [{sev}]"
            elif sev == "WARNING":
                badge = f"🟡 [{sev}]"
            else:
                badge = f"🟢 [{sev}]"

            print(f"[{r['id']}] {r['timestamp']} | {badge:<12} | Cat: {r['category']:<14} | Alvo: {r['target']}")
            print(f"    ↳ {r['description']}")
            print("-" * 65)

def show_stats():
    stats = logger.get_stats()
    print("\n📈 --- ESTATÍSTICAS DE SEGURANÇA (SIEM) ---")
    print(f"Total de registros de auditoria: {stats['total_events']}")
    
    print("\n🔹 Por Severidade:")
    for sev, count in (stats.get('by_severity') or {}).items():
        print(f"  • {sev:<10}: {count}")
        
    print("\n🔹 Por Categoria:")
    for cat, count in (stats.get('by_category') or {}).items():
        print(f"  • {cat:<18}: {count}")

def isolate_file_cli():
    fpath = input("\nDigite o caminho do arquivo a ser isolado na quarentena: ").strip().strip('"')
    if not fpath:
        print("❌ Caminho inválido.")
        return
    success = soar.isolate_file(fpath)
    if success:
        print(f"✅ Arquivo '{fpath}' criptografado e movido para a quarentena com sucesso!")
    else:
        print(f"❌ Falha ao isolar arquivo '{fpath}'.")

def manage_quarantine_cli():
    items = soar.list_quarantine()
    print(f"\n📦 --- QUARENTENA ({len(items)} arquivos isolados no cofre) ---")
    if not items:
        print("A quarentena está vazia. Nenhum arquivo isolado.")
        return
    for i, item in enumerate(items, 1):
        print(f"[{i}] {item.get('original_name', item['name'])} (Cifrado: {item['name']}) | {item['size']} bytes | {item['modified']}")
    
    print("\nOpções:")
    print("  [R] Restaurar / Liberar arquivo para a pasta 'restored/'")
    print("  [D] Excluir definitivamente do cofre")
    print("  [V] Voltar")
    act = input("Escolha uma ação (R/D/V): ").strip().upper()

    if act == 'R':
        num = input("Digite o número do arquivo a restaurar: ").strip()
        if num.isdigit():
            idx = int(num) - 1
            if 0 <= idx < len(items):
                target_item = items[idx]
                dest = input("Digite o caminho de destino (ou Enter para padrão 'restored/'): ").strip()
                success, restored_path = soar.restore_file(target_item['name'], restore_to_path=dest if dest else None)
                if success:
                    detector.add_whitelist(target_item['name'])
                    if restored_path:
                        detector.add_whitelist(restored_path)
                    print(f"✅ Arquivo liberado com sucesso para '{restored_path}' e adicionado à Whitelist!")
                else:
                    print("❌ Erro ao restaurar arquivo.")
            else:
                print("❌ Número inválido.")
    elif act == 'D':
        num = input("Digite o número do arquivo a excluir definitivamente: ").strip()
        if num.isdigit():
            idx = int(num) - 1
            if 0 <= idx < len(items):
                target_item = items[idx]
                ok = soar.delete_quarantined_file(target_item['name'])
                if ok:
                    print(f"🗑️ Arquivo '{target_item['name']}' excluído definitivamente.")
                else:
                    print("❌ Falha ao excluir arquivo.")
            else:
                print("❌ Número inválido.")


def kill_process_cli():
    pid_str = input("\nDigite o PID do processo a ser finalizado: ").strip()
    if not pid_str.isdigit():
        print("❌ PID deve ser um número inteiro.")
        return
    success = soar.kill_process_by_pid(int(pid_str))
    if success:
        print(f"✅ Processo PID {pid_str} finalizado com sucesso!")
    else:
        print(f"❌ Não foi possível finalizar o PID {pid_str}.")

def scan_file_cli():
    fpath = input("\nDigite o caminho do arquivo para escanear: ").strip().strip('"')
    if not fpath:
        print("❌ Caminho não informado.")
        return
    res = detector.scan_file(fpath)
    print("\n🔍 --- RESULTADO DA ANÁLISE DE AMEAÇA ---")
    print(f"Status      : {res.get('status')}")
    print(f"Hash SHA-256: {res.get('hash', 'N/A')}")
    if res.get("status") == "MALWARE_DETECTED":
        print("🚨 ALERTA: Assinatura de Malware detectada!")
        print(f"Descrição  : {res.get('description')}")
        iso = input("Deseja isolar este arquivo na quarentena agora? (s/N): ").strip().lower()
        if iso == 's':
            soar.isolate_file(fpath)
            print("✅ Arquivo enviado para a quarentena.")
    elif res.get("status") == "SUSPICIOUS":
        print(f"⚠️ AVISO: {res.get('description')}")
    else:
        print("🟢 Arquivo limpo de acordo com as assinaturas de IOC.")

def edr_scan_cli():
    from sentinel_core.process_guard import EDRProcessGuard
    edr = EDRProcessGuard(logger=logger)
    print("\n🔍 Executando varredura profunda de processos (EDR Guard)...")
    threats = edr.scan_active_processes()
    if not threats:
        print("🟢 Nenhum processo suspeito de Ransomware/Wiper/Dump detectado.")
    else:
        print(f"🚨 INTERCEPTADOS {len(threats)} PROCESSOS SUSPEITOS:")
        for t in threats:
            print(f"  • PID: {t['pid']} | Nome: {t['name']} | Palavra-chave: {t['keyword']}")
        auto_kill = input("Deseja executar auto-remediação forçada (encerrar processos)? (s/N): ").strip()
        if auto_kill.lower() == 's':
            killed = edr.auto_remediate()
            print(f"⚡ {killed} processos neutralizados com sucesso!")

def firewall_cli():
    from sentinel_core.firewall_manager import OSFirewallManager
    fw = OSFirewallManager(logger=logger)
    banned = fw.get_banned_list()
    print(f"\n🧱 --- FIREWALL DO SO: {len(banned)} IPs BLOQUEADOS ---")
    for b in banned:
        print(f"  • IP: {b['ip']} | Motivo: {b['reason']} | Data: {b['timestamp']}")
    
    act = input("\n[1] Banir novo IP  [2] Desbanir IP  [0] Voltar: ").strip()
    if act == '1':
        ip = input("Digite o IP a banir: ").strip()
        reason = input("Motivo do bloqueio: ").strip() or "Bloqueio manual via CLI"
        if fw.block_ip(ip, reason):
            print(f"✅ IP {ip} adicionado à lista de bloqueio do Firewall!")
        else:
            print("❌ Falha ao banir IP.")
    elif act == '2':
        ip = input("Digite o IP a desbanir: ").strip()
        if fw.unblock_ip(ip):
            print(f"🔓 IP {ip} liberado com sucesso!")
        else:
            print("❌ IP não encontrado na lista de bloqueios.")

def ai_entropy_cli():
    from sentinel_core.ai_predictor import ZeroDayAIPredictor
    predictor = ZeroDayAIPredictor(logger=logger)
    payload = input("\nDigite ou cole o texto/payload a analisar: ").strip()
    if not payload:
        payload = "\\x90\\x90\\x90\\xeb\\x02\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68"
    rate = float(input("Informe a taxa de requisições/s simulada [padrão: 25.0]: ").strip() or "25.0")
    res = predictor.analyze_request("185.220.101.5", payload, rate)
    print("\n🤖 --- RESULTADO DA ANÁLISE IA ZERO-DAY ---")
    print(f"  • Entropia de Shannon: {res['payload_entropy']} bits/byte")
    print(f"  • Score de Risco IA:   {res['risk_score']} / 1.0")
    print(f"  • Predição Zero-Day:   {'🚨 DETECTADA' if res['zero_day_predicted'] else '🟢 SEGURO'}")
    if res['flags']:
        print(f"  • Flags Acionadas:     {', '.join(res['flags'])}")

def sysmon_cli():
    from sentinel_core.sysmon_installer import SysmonInstallerManager
    mgr = SysmonInstallerManager(project_root=ROOT_DIR)
    status = mgr.get_status()
    print("\n🔍 --- STATUS DO MICROSOFT SYSMON ---")
    print(f"  • Plataforma Windows:   {'SIM' if status['platform_windows'] else 'NÃO'}")
    print(f"  • Privilégio Admin:     {'SIM' if status['is_admin'] else 'NÃO (Usuário Comum)'}")
    print(f"  • Serviço Instalado:    {'SIM (' + str(status['service_name']) + ')' if status['service_installed'] else 'NÃO'}")
    print(f"  • Serviço em Execução:  {'🟢 ATIVO' if status['service_running'] else '🔴 PARADO'}")
    print(f"  • Canal EventLog Ativo: {'🟢 SIM' if status['channel_active'] else '🔴 INATIVO'}")
    print(f"  • Config Endurecida:    {'PRESENTE' if status['config_exists'] else 'AUSENTE'}")
    print(f"  • Recomendação:         {status['recommendation']}")

    act = input("\n[1] Instalar / Atualizar Configuração Endurecida  [2] Copiar Comando PowerShell  [0] Voltar: ").strip()
    if act == '1':
        print("\n[*] Iniciando orquestração do Sysmon...")
        res = mgr.install()
        if res.get("status") == "success":
            print("✅ Sysmon configurado com sucesso!")
        elif res.get("code") == "ELEVATION_REQUIRED":
            print(f"⚠️ {res['message']}")
            print("Execute o comando abaixo em um PowerShell elevado (Administrador):")
            print(f"  👉 {res['recommended_command']}")
        else:
            print(f"❌ Falha: {res.get('message', res)}")
    elif act == '2':
        print("\nExecute no PowerShell como Administrador:")
        print(f"  👉 {mgr.get_install_command()}")

def clear_db():
    confirm = input("⚠️ Tem certeza que deseja apagar TODOS os registros de log? (s/N): ").strip()
    if confirm.lower() == 's':
        count = logger.clear_events()
        print(f"✅ Banco de dados limpo com sucesso! ({count} registros apagados)")

def main():
    while True:
        try:
            show_menu()
            choice = input("Escolha uma opção: ").strip()
            
            if choice == '1':
                list_events()
            elif choice == '2':
                sev = input("Informe a severidade (INFO / WARNING / HIGH / CRITICAL): ").strip()
                list_events(severity=sev)
            elif choice == '3':
                cat = input("Informe a categoria (FIM / PROCESS_NEW / PROCESS_SUSPICIOUS / NETWORK / SYSTEM / MALWARE): ").strip()
                list_events(category=cat)
            elif choice == '4':
                show_stats()
            elif choice == '5':
                isolate_file_cli()
            elif choice == '6':
                manage_quarantine_cli()
            elif choice == '7':
                kill_process_cli()
            elif choice == '8':
                scan_file_cli()
            elif choice == '9':
                edr_scan_cli()
            elif choice == '10':
                firewall_cli()
            elif choice == '11':
                ai_entropy_cli()
            elif choice == '12':
                sysmon_cli()
            elif choice == '13':
                clear_db()
            elif choice == '0':
                print("Encerrando painel CLI do Sentinela. Até mais!")
                break
            else:
                print("Opção inválida! Tente novamente.")
        except KeyboardInterrupt:
            print("\nOperação cancelada pelo usuário.")

            break
        except Exception as e:
            print(f"❌ Ocorreu um erro: {e}")

if __name__ == "__main__":
    main()

