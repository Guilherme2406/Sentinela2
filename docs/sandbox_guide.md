# 🧪 Guia de Detonação e Análise em Sandbox Local — Sentinela XDR

Este guia técnico descreve o procedimento padronizado e seguro para análise comportamental de artefatos suspeitos e execução controlada em ambiente de contenção (Sandbox), integrado ao pipeline de detecção do **Sentinela2**.

---

## 1. Topologia de Isolamento Recomendada

Nunca execute amostras desconhecidas ou maliciosas no host de desenvolvimento/produção fora de um envelope de contenção. Utilize uma das três opções abaixo:

| Mecanismo | Nível de Isolamento | Caso de Uso Recomendado |
|---|---|---|
| **Windows Sandbox (WSB)** | Hyper-V Lightweight Container | Detonação rápida descartável (Zero vestígios no host) |
| **Sandboxie-Plus** | Kernel Filter Isolation (Ring 3/0) | Testes rápidos de processos sem reinicialização |
| **VM Hyper-V / VirtualBox** | Hipervisor Completo (Host-Only Network) | Análise forense avançada e engenharia reversa |

---

## 2. Configuração do Windows Sandbox (.wsb) com Sentinela

Crie o arquivo `sentinel_detonation_sandbox.wsb` com a seguinte política de segurança:

```xml
<Configuration>
  <Networking>Default</Networking>
  <MappedFolders>
    <!-- Pasta compartilhada em modo READ-ONLY para carregar a amostra -->
    <MappedFolder>
      <HostFolder>C:\Users\Casa\Desktop\JarvisProjects\Sentinela2\test_corpus</HostFolder>
      <SandboxFolder>C:\Samples</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -ExecutionPolicy Bypass -Command "Write-Host 'Sandbox pronta para teste forense do Sentinela.'"</Command>
  </LogonCommand>
</Configuration>
```

---

## 3. Fluxo Operacional de Detonação

1. **Geração do Hash e Metadados (Ground Truth):**
   ```powershell
   python -c "import hashlib; print(hashlib.sha256(open('amostra.bin','rb').read()).hexdigest())"
   ```

2. **Detonação Supervisionada:**
   - Execute o artefato dentro da sandbox.
   - Monitore a árvore de processos (`ProcessTree`), chamadas de injeção (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`) e resolução DNS (DGA).

3. **Coleta de Telemetria via Sentinela XDR:**
   - O **Sysmon Collector** (Event IDs 1, 8, 10, 11, 22) e o **Native ETW Live Consumer** capturam o comportamento em tempo real.
   - O motor **DynamicFileScanner** avalia a entropia e as assinaturas YARA do binário gerado.

4. **Contenção e Resposta SOAR:**
   - O Sentinela isola imediatamente o arquivo em quarentena militar (`sentinel_vault/quarantine/`).
   - Se houver modificação de arquivos de usuário, o **Rollback Anti-Ransomware de 1-Clique** restaura a versão íntegra através do snapshot prévio.

---

## 4. Checklist de Segurança Pós-Detonação

- [x] O artefato foi confinado exclusivamente no contêiner ou VM isolada.
- [x] O tráfego de rede para a Internet foi inspecionado ou redirecionado para o **Tarpit/Sinkhole** do Sentinela.
- [x] Nenhuma chave de criptografia ou credencial primária do host foi exposta.
- [x] O relatório de telemetria foi registrado no log de auditoria global (`audit_actions.db`).
