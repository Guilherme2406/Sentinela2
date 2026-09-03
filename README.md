# 🛡️ SENTINEL XDR SOVEREIGN — Plataforma de Ciberdefesa Ativa Local

O **Sentinela XDR** é uma suíte soberana de segurança cibernética de alta performance, projetada para fornecer proteção contínua em tempo real para endpoints Windows com **100% de soberania local de dados** (sem dependência de nuvem pública e em total conformidade com LGPD/GDPR).

---

## 📁 Estrutura e Organização de Arquivos do Projeto

```
Sentinela2/
├── 🚀 Scripts de Inicialização e Instalação
│   ├── instalar.bat                   # Instalador de 2-cliques (Abre o Assistente Gráfico)
│   ├── instalar_como_administrador.bat # Instalador com elevação de privilégios de Admin
│   ├── iniciar.bat                    # Inicia a API, serviços e o ícone na bandeja do Windows
│   ├── iniciar_cli.bat                # Inicia o modo terminal interativo
│   ├── desinstalar.bat                # Desinstalador de 2-cliques
│   └── iniciar_segundo_plano.vbs      # Execução 100% silenciosa do serviço (sem tela preta)
│
├── 🖥️ Interfaces de Usuário & Frontend
│   ├── gui_installer.pyw              # Assistente Gráfico Moderno de Instalação (PyQt6 Dark Theme)
│   ├── tray_app.pyw                   # Aplicativo nativo da Bandeja do Sistema (System Tray)
│   ├── dashboard.html                 # Dashboard Web Cyber-Defense SPA (Leaflet 3D Radar, SIEM, Modais)
│   ├── sentinel_api.py                # Backend REST API Flask com 30+ endpoints de segurança
│   └── main.py / sentinel_cli.py      # Console interativo CLI
│
├── 🧠 sentinel_core/                  # Núcleo de Motores de Defesa Ativa (53 Módulos)
│   ├── identity_credential_guard.py   # LSASS Armor & Proteção Anti-Dumping / Potato PrivEsc
│   ├── dlp_exfiltration_guard.py      # DLP, Clipboard Snooper & Bloqueio de Exfiltração/USB
│   ├── execution_anti_exploit_guard.py# Anti-Exploit, Anti-Hollowing & Office Child Shield
│   ├── network_perimeter_guard.py     # Perímetro Local, DGA C2 Armor & ARP MITM Defender
│   ├── posture_persistence_guard.py   # ASEP Hunter, LOLBins Monitor & CIS System Hardening
│   ├── ztna_engine.py                 # Motor CARTA Zero-Trust (Postura Adaptativa Contínua)
│   ├── fim.py                         # File Integrity Monitor (Hashes SHA-256 contínuos)
│   ├── process_guard.py               # EDR Process Guard & Heurística Anti-Wiper
│   ├── threat_intel.py                # Cyber Threat Intelligence (Feeds Globais & IOCs)
│   ├── post_quantum_shield.py         # Escudo Pós-Quântico NIST (ML-KEM-1024 & Dilithium)
│   ├── zero_trust_wfp.py              # Microsegmentação de Rede WFP (Bloqueio Lateral SMB/RDP)
│   ├── live_memory_forensics.py       # Forense de Memória RAM (Cobalt Strike & Reflective DLL)
│   ├── ai_anomaly_detector.py         # Motor de IA (Isolation Forest Zero-Day)
│   ├── ai_predictor.py                # Analisador Estocástico de Entropia de Shannon
│   ├── soar_playbook_engine.py        # Orquestração SOAR e Playbooks Automáticos
│   ├── crypto_vault.py / quarantine_vault.py # Cofre Criptográfico AES-256
│   ├── anti_ransomware_rollback.py    # Snapshots Imutáveis & Rollback 1-Clique
│   ├── canary_files.py / honeyfiles.py# Arquivos Canário e Iscas de Decepção
│   ├── honeytoken_deception.py        # Iscas Honeytoken (AWS, DB, SSH)
│   ├── honeypot.py                    # Honeypots de Rede (Portas Falsas 2222, etc.)
│   ├── tarpit_engine.py / tarpit.py   # Cyber Tarpit Defense (Poço de Lentidão na Porta 8888)
│   ├── network_ids.py                 # Radar NIDS de Intrusão em Rede
│   ├── firewall_manager.py            # Integração Direta com Firewall do SO (netsh)
│   ├── ueba_graph_engine.py           # Análise Comportamental UEBA (Insider Threats)
│   ├── yara_pe_analyzer.py            # Analisador Forense de Binários PE & YARA
│   ├── kernel_etw_monitor.py          # Monitor de Eventos de Kernel ETW Ring 0
│   └── logger.py                      # Security Event Logger (Banco SQLite Local)
│
├── 🌐 multiagent/                      # Camada Multi-Host — XDR Federado (Hub & Agentes)
│   ├── config.py                       # Papéis do nó (hub | agent | off) e parâmetros do cluster
│   ├── registry.py                     # Registro de hosts, telemetria agregada e correlação cross-host
│   ├── bus.py                          # Barramento thread-safe de eventos locais para o hub
│   ├── agent.py                        # Cliente remoto (heartbeat, telemetria e envio de eventos)
│   └── server.py                       # Blueprint Flask do hub central (ingestão e consultas)
│
├── 🗄️ Diretórios de Dados Soberanos
│   ├── quarantine/                    # Arquivos maliciosos isolados e cifrados em AES-256
│   ├── sentinel_vault/                # Snapshots imutáveis para recuperação anti-ransomware
│   ├── canary_traps/                  # Arquivos canário armados contra invasores
│   ├── sentinel_baits/                # Iscas honeytoken de credenciais
│   ├── honeypots/                     # Logs e armadilhas de decepção de rede
│   ├── user_documents/                # Pasta de arquivos monitorados pelo rollback
│   ├── restored/                      # Arquivos restaurados com segurança da quarentena
│   └── assets/                        # Ícones (.ico, .png) e logotipo oficial
│
└── ⚙️ Configuração, Testes e Utilitários
    ├── test_suite.py                  # Suite de Testes Automatizados Unitários (70 testes OK)
    ├── smoke_test_engines.py          # Smoke test de todos os endpoints dos motores (Flask test client)
    ├── setup_project.py               # Verificador de integridade estrutural do ambiente
    ├── bootstrap_env.py               # Auto-instalador resiliente de dependências
    ├── requirements.txt               # Dependências Python (Flask, PyQt6, scikit-learn, etc.)
    ├── TERMOS_DE_USO.md               # Licença de Software e Termos de Soberania (EULA)
    ├── sentinel.key                   # Chave criptográfica master gerada localmente
    ├── sentinel_events.db             # Banco de dados SQLite de eventos e SIEM
    └── sentinel_runtime.json          # Estado de execução em tempo real (Porta e PID)
```

---

## 🛡️ As 20 Camadas de Proteção Ativa

1. **Identity & Credential Guard (LSASS Armor):** Proteção cirúrgica de memória contra Mimikatz, dumping de SAM/SYSTEM, Potato PrivEsc e stealers.
2. **DLP & Exfiltration Armor:** Prevenção contra vazamento de dados (LGPD/PCI-DSS), validação Módulo 11 (CPF/CNPJ), algoritmo de Luhn (Cartões) e Write-Protect em USB.
3. **Motor de Execução & Anti-Exploit:** Bloqueio de injeção em processos legítimos (Process Hollowing), Office/PDF Child Shield, detecção de DLL Sideloading e blindagem contra bypass de AMSI/ETW.
4. **Perímetro Local, DGA & Anti-MITM:** Detecção de Man-in-the-Middle (ARP Spoofing no Gateway), bloqueio de C2 via DGA (entropia de Shannon), interceptação de DNS Tunneling e auditoria do arquivo hosts.
5. **Postura, Persistência & LOLBins Guard:** Caça ativa a pontos de persistência oculta (ASEP em chaves Run, IFEO Debugger, pastas Startup), bloqueio de abuso de binários do Windows (*LOLBins*: Certutil, BITSAdmin, MSHTA) e auditoria CIS de Hardening (UAC, RDP NLA, Defender).
6. **ZTNA CARTA Engine:** Avaliação contínua de risco do dispositivo com auto-isolamento de rede.
7. **File Integrity Monitor (FIM):** Monitoramento contínuo por hashes SHA-256.
8. **EDR Process Guard:** Heurística de processos suspeitos e auto-remediação.
9. **Cyber Threat Intelligence (CTI):** Sincronização de feeds globais de IOCs e IPs maliciosos.
10. **Escudo Pós-Quântico NIST (PQC):** Criptografia ML-KEM-1024 e assinaturas Dilithium.
11. **Microsegmentação Zero-Trust (WFP):** Bloqueio de movimentação lateral de ransomware (SMB/RDP).
12. **Forense de Memória RAM:** Varredura em tempo real contra injeções de DLL e Cobalt Strike.
13. **Motor de IA (Isolation Forest Zero-Day):** Modelo não-supervisionado contra anomalias.
14. **Motor SOAR Autônomo & Shadow Mode:** Quarentena instantânea AES-256 e resposta automática.
15. **Decepção Ativa (Canários & Honeypots):** Iscas armadas em pastas sensíveis.
16. **Cyber Tarpit Defense (Porta 8888):** Retenção e lentidão forçada para invasores de rede.
17. **Radar de Intrusão em Rede (NIDS):** Telemetria e detecção de varreduras de porta.
18. **Firewall do Kernel OS Manager:** Regras sincronizadas diretamente com o Firewall do Windows.
19. **Rollback 1-Clique & Vault AES-256:** Snapshots imutáveis para reverter ransomware.
20. **Análise Comportamental UEBA:** Detecção de desvios e ameaças internas (*Insider Threats*).

---

## 🚀 Como Utilizar

### 1. Instalação:
* Dê um duplo clique em **`instalar.bat`** para abrir o assistente gráfico de instalação.

### 2. Acesso ao Painel Dashboard:
* O painel estará disponível no navegador em **`http://localhost:5000`**.
* Ou clique duas vezes no ícone do escudo ao lado do relógio do Windows na bandeja do sistema.

### 3. Modo Multi-Host (XDR Federado):
* Transforme o Sentinela em um XDR federado: um nó central (**hub**) coordena N agentes remotos que enviam heartbeat, telemetria e eventos de segurança em tempo real, com correlação cross-host entre máquinas.
* Configure o papel de cada nó no arquivo `multiagent_config.json`:
```json
{
  "role": "agent",
  "agent_id": "nome-do-no",
  "hub_url": "http://IP-DO-HUB:5000",
  "token": "token-compartilhado-opcional"
}
```
* No servidor central utilize `"role": "hub"`; com `"role": "off"` (padrão) a camada permanece inerte.
* Regras de correlação cross-host: IOC compartilhado em múltiplos hosts (movimentação lateral), interrupção em massa de agentes (possível Wiper) e surto coordenado de incidentes.
* No dashboard, o botão **Multi-Host** exibe a frota em tempo real, o status do agente local e as correlações detectadas (com alerta tático via SSE).

### 4. Testes Automatizados:
* Para validar a integridade de todos os motores:
```bash
python test_suite.py
```
