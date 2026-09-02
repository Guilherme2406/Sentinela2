# TERMOS DE USO E ACORDO DE LICENÇA DE USUÁRIO FINAL (EULA)
## SENTINEL XDR | Sovereign Cyber Defense Center

**Versão 2.4 — 2026**

---

### 1. ACEITAÇÃO DOS TERMOS
Ao instalar, executar ou utilizar o **SENTINEL XDR** ("Software"), você ("Usuário" ou "Organização") concorda expressamente em ficar vinculado aos termos e condições estabelecidos neste documento. Se você não concordar com todos os termos aqui descritos, não instale nem utilize este software.

---

### 2. ESCOPO E FINALIDADE DO SOFTWARE
O **SENTINEL XDR** é uma solução soberana de detecção e resposta a ameaças (XDR / EDR / SIEM / SOAR) destinada exclusivamente a:
1. **Monitoramento e Defesa Cibernética Local:** Auditoria de integridade de arquivos (FIM), inspeção de tráfego de rede host e monitoramento de processos em execução.
2. **Contramedidas de Defesa Ativa:** Bloqueio de conexões maliciosas no Firewall do Sistema Operacional, armadilhas de decepção (*honeytokens/canary files*), e isolamento de arquivos perigosos em quarentena criptografada (AES-256).
3. **Resiliência Anti-Ransomware:** Criação de snapshots imutáveis em cofre local para recuperação de desastres (*Rollback 1-Clique*).
4. **Proteção de Identidade, DLP e Perímetro:** Blindagem de memória LSASS contra roubo de credenciais (Mimikatz), prevenção contra vazamento de dados confidenciais (DLP Módulo 11 CPF/CNPJ e controle de escrita USB), escudo anti-exploit (Anti-Hollowing/AMSI) e caça a persistências furtivas (ASEP/LOLBins).

---

### 3. PRIVACIDADE E SOBERANIA DE DADOS (LGPD / GDPR)
* **Soberania Local:** Todos os dados, hashes, relatórios de telemetria e registros de log (`sentinel_events.db`, `sentinel_daemon.log`) são armazenados e processados **exclusivamente na sua própria máquina**.
* **Zero Coleta Externa de Dados Pessoais:** O software não envia seus documentos, senhas pessoais ou arquivos confidenciais para servidores de terceiros na nuvem.
* **Inteligência de Ameaças:** Consultas externas limitam-se à verificação de geolocalização de endereços IP de atacantes identificados e sincronização de feeds públicos de IOCs (Threat Intelligence).

---

### 4. CONSENTIMENTO PARA CONTRAMEDIDAS AUTOMATIZADAS (SOAR)
O Usuário reconhece e autoriza o Software a executar as seguintes ações autônomas necessárias para a proteção do sistema:
1. **Quarentena e Criptografia:** Mover e criptografar arquivos identificados como maliciosos para a pasta `quarantine/`.
2. **Encerramento de Processos:** Interromper processos suspeitos que apresentem anomalias graves de ransomware ou injeção de memória.
3. **Regras de Firewall:** Criar regras locais de bloqueio de pacotes de rede para IPs invasores no Windows Defender Firewall.
4. **Armadilhas de Decepção:** Criar arquivos canário (`canary_traps/`) para detecção preventiva de cryptolockers.

---

### 5. ISENÇÃO DE RESPONSABILIDADE E GARANTIA
* O Software é fornecido *"no estado em que se encontra"* (*"AS IS"*), sem garantias explícitas ou implícitas de adequação a um propósito específico ou infalibilidade absoluta.
* Em conformidade com as normas universais de cibersegurança, o desenvolvedor não se responsabiliza por eventuais danos indiretos, perda de dados ou lucros cessantes decorrentes de ataques cibernéticos sofisticados, falhas de hardware ou configurações inadequadas do sistema.
* É responsabilidade do Usuário manter backups periódicos adicionais de seus arquivos críticos.

---

### 6. RETENÇÃO E EXCLUSÃO DE DADOS NA DESINSTALAÇÃO
Na ocasião da desinstalação do Software através do assistente de desinstalação oficial (`uninstaller.py` / `desinstalar.bat`), o Usuário terá o direito de escolher entre:
* **Manter Dados:** Preservar históricos de eventos, quarentena e cópias de segurança para auditorias futuras.
* **Exclusão Total (*Purge*):** Destruição completa de todos os dados locais associados ao Software.

---

**SENTINEL XDR — Sovereign Cyber Defense Architecture**  
*Desenvolvido para Máxima Resiliência e Proteção do Host.*
