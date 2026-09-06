# sentinel_core/process_guard.py
import os
import sys
import time
import logging
import subprocess
from typing import List, Dict, Any, Optional

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

class EDRProcessGuard:
    """
    Endpoint Detection & Response (EDR) Process Guard — Modo Brutal / Hardened.
    Monitora a árvore de processos do SO, detectando comportamentos de Ransomware,
    tentativas de deleção de cópias de sombra (VSS), dump de credenciais LSASS,
    ataques Living-off-the-Land (LOLBins) e executando neutralização forçada da árvore de processos.
    """

    # Assinaturas Comportamentais Críticas de Ransomware & Invasores
    CRITICAL_SIGNATURES = [
        # Ransomware / Destruição de Backups e Shadow Copies
        {"rule": "VSS_DELETION", "keywords": ["vssadmin", "delete", "shadows"], "severity": "CRITICAL"},
        {"rule": "WMIC_SHADOW_KILL", "keywords": ["wmic", "shadowcopy", "delete"], "severity": "CRITICAL"},
        {"rule": "WBADMIN_CATALOG_DELETE", "keywords": ["wbadmin", "delete", "catalog"], "severity": "CRITICAL"},
        {"rule": "BCDEDIT_RECOVERY_TAMPER", "keywords": ["bcdedit", "recoveryenabled", "no"], "severity": "CRITICAL"},
        {"rule": "BCDEDIT_BOOT_IGNORE", "keywords": ["bcdedit", "bootstatuspolicy", "ignoreallfailures"], "severity": "CRITICAL"},
        {"rule": "EVENTLOG_WIPING", "keywords": ["wevtutil", "cl", "security"], "severity": "CRITICAL"},
        
        # Dump de Credenciais & Roubo de Senhas
        {"rule": "MIMIKATZ_LSASS_DUMP", "keywords": ["mimikatz"], "severity": "CRITICAL"},
        {"rule": "PROCDUMP_LSASS", "keywords": ["procdump", "lsass"], "severity": "CRITICAL"},
        {"rule": "COMSVCS_MINIDUMP", "keywords": ["comsvcs.dll", "minidump"], "severity": "CRITICAL"},
        
        # LOLBins / Downloaders Ocultos / Obfuscated Shell
        {"rule": "POWERSHELL_ENCODED", "keywords": ["powershell", "-enc"], "severity": "HIGH"},
        {"rule": "POWERSHELL_HIDDEN_EXEC", "keywords": ["powershell", "-w", "hidden", "-enc"], "severity": "CRITICAL"},
        {"rule": "CERTUTIL_PAYLOAD_DOWNLOAD", "keywords": ["certutil", "-urlcache", "-split"], "severity": "HIGH"},
        {"rule": "BITSADMIN_TRANSFER", "keywords": ["bitsadmin", "/transfer"], "severity": "HIGH"},
        {"rule": "MSHTA_INLINE_PAYLOAD", "keywords": ["mshta", "http"], "severity": "HIGH"},
        {"rule": "RUNDLL32_JAVASCRIPT", "keywords": ["rundll32", "javascript:"], "severity": "CRITICAL"}
    ]

    SYSTEM_PROTECTED_PROCESSES = {
        "lsass.exe", "csrss.exe", "smss.exe", "wininit.exe", 
        "services.exe", "svchost.exe", "system", "idle", "explorer.exe"
    }

    def __init__(self, logger=None):
        self.logger = logger
        self.monitored_pids: set = set()
        self.terminated_history: List[Dict[str, Any]] = []

    def _log(self, level: str, category: str, action: str, msg: str):
        try:
            if self.logger:
                self.logger.log_event(level, category, action, msg)
        except Exception:
            pass
        logging.info(f"[{category}] {msg}")

    def scan_active_processes(self) -> List[Dict[str, Any]]:
        """Varre a lista de processos buscando assinaturas comportamentais e comandos suspeitos."""
        threats_found = []

        if not HAS_PSUTIL:
            self._log("WARNING", "EDR_GUARD", "MISSING_DEP", "Biblioteca 'psutil' não encontrada. Instale para EDR nativo.")
            return threats_found

        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
            try:
                pinfo = proc.info
                pname = (pinfo['name'] or "").lower()

                # Ignora processos protegidos do próprio Windows
                if pname in self.SYSTEM_PROTECTED_PROCESSES or pinfo['pid'] <= 4:
                    continue

                cmdline_tokens = [t.lower() for t in (pinfo['cmdline'] or [])]
                cmdline_str = " ".join(cmdline_tokens)

                # 1. Checagem por matriz de assinaturas de alta precisão
                for sig in self.CRITICAL_SIGNATURES:
                    keywords = sig["keywords"]
                    # Verifica se todas as palavras-chave da regra estão presentes na linha de comando
                    if all(kw in cmdline_str for kw in keywords) or (len(keywords) == 1 and keywords[0] in pname):
                        threat_info = {
                            "pid": pinfo['pid'],
                            "name": pinfo['name'],
                            "cmdline": cmdline_str,
                            "rule": sig["rule"],
                            "severity": sig["severity"],
                            "timestamp": time.time()
                        }
                        threats_found.append(threat_info)
                        self._log(
                            sig["severity"], "EDR_GUARD", "SUSPICIOUS_PROC", 
                            f"Processo hostil interceptado pelo EDR: PID {pinfo['pid']} ({pname}) - Regra: {sig['rule']}"
                        )
                        break

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return threats_found

    def terminate_process(self, pid: int, reason: str = "Ameaça EDR detectada") -> bool:
        """Encerra um processo e toda sua árvore de subprocessos com força total (Kill Process Tree)."""
        try:
            if HAS_PSUTIL:
                parent = psutil.Process(pid)
                # Encerra recursivamente todos os filhos para não deixar processos zumbis/trojans soltos
                for child in parent.children(recursive=True):
                    try:
                        child.kill()
                    except Exception:
                        pass
                parent.kill()
            else:
                if sys.platform == "win32":
                    subprocess.run(f"taskkill /F /PID {pid} /T", shell=True, capture_output=True)
                else:
                    subprocess.run(f"kill -9 {pid}", shell=True, capture_output=True)

            event = {
                "pid": pid,
                "reason": reason,
                "status": "TERMINATED",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            self.terminated_history.append(event)
            self._log("CRITICAL", "EDR_GUARD", "PROCESS_KILLED", f"Árvore de execução neutralizada: PID {pid}. Motivo: {reason}")
            return True

        except Exception as e:
            self._log("ERROR", "EDR_GUARD", "KILL_FAILED", f"Falha ao encerrar PID {pid}: {e}")
            return False

    def auto_remediate(self) -> int:
        """Varre e extermina automaticamente processos com assinaturas hostis ativas."""
        threats = self.scan_active_processes()
        killed_count = 0
        for threat in threats:
            if threat["severity"] in ["CRITICAL", "HIGH"]:
                success = self.terminate_process(threat["pid"], reason=f"Auto-Remediação EDR: {threat['rule']}")
                if success:
                    killed_count += 1
        return killed_count

    def get_edr_threats(self) -> List[Dict[str, Any]]:
        """Retorna as ameaças ativas em tempo real."""
        return self.scan_active_processes()

    def start_reactive_watcher(self, auto_kill: bool = True) -> bool:
        """
        Inicia escuta reativa de processos via WMI no Windows (latência < 1s).
        Intercepta instantaneamente a criação de novos processos sem depender de polling demorado.
        """
        if sys.platform != "win32":
            return False

        if getattr(self, "_wmi_watcher_running", False):
            return True

        self._wmi_watcher_running = True
        
        def _wmi_loop():
            try:
                import pythoncom
                import win32com.client
                pythoncom.CoInitialize()
                try:
                    wmi = win32com.client.GetObject("winmgmts:\\\\.\\root\\cimv2")
                    watcher = wmi.ExecNotificationQuery(
                        "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"
                    )
                    self._log("INFO", "EDR_GUARD", "REACTIVE_WMI_ACTIVE", "Escudo reativo WMI de processos ativado em tempo real.")
                    
                    while getattr(self, "_wmi_watcher_running", False):
                        try:
                            event = watcher.NextEvent(1000)
                            proc = event.TargetInstance
                            pid = int(proc.ProcessId)
                            pname = str(proc.Name or "").lower()
                            cmdline = str(getattr(proc, "CommandLine", "") or "").lower()
                            
                            if pname in self.SYSTEM_PROTECTED_PROCESSES or pid <= 4:
                                continue
                                
                            for sig in self.CRITICAL_SIGNATURES:
                                keywords = sig["keywords"]
                                if all(kw in cmdline for kw in keywords) or (len(keywords) == 1 and keywords[0] in pname):
                                    self._log(
                                        sig["severity"], "EDR_GUARD", "REACTIVE_DETECT",
                                        f"⚡ [WMI INSTANTÂNEO] Processo hostil interceptado no nascimento: PID {pid} ({pname}) - Regra: {sig['rule']}"
                                    )
                                    if auto_kill and sig["severity"] in ["CRITICAL", "HIGH"]:
                                        self.terminate_process(pid, reason=f"WMI Auto-Kill EDR: {sig['rule']}")
                                    break
                        except Exception:
                            # Timeout normal do NextEvent (1s) ou erro transitório
                            continue
                finally:
                    pythoncom.CoUninitialize()
            except Exception as e:
                self._log("DEBUG", "EDR_GUARD", "WMI_ERROR", f"Watcher WMI indisponível, operando via polling padrão: {e}")

        import threading
        t = threading.Thread(target=_wmi_loop, name="SentinelWMIProcessWatcher", daemon=True)
        t.start()
        return True

    def stop_reactive_watcher(self):
        """Para a escuta reativa de processos WMI."""
        self._wmi_watcher_running = False

    def get_process_tree(
        self,
        focus_pid: Optional[int] = None,
        mode: str = "user_apps",
        search: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Gera a árvore de linhagem de processos hierárquica (Process Tree Graph).
        Permite ao dashboard renderizar o grafo de incidente no estilo CrowdStrike / SentinelOne.
        Modos:
          - 'threats': Apenas processos suspeitos/maliciosos e suas cadeias.
          - 'user_apps': A árvore interativa que parte de explorer.exe (aplicativos, shells, scripts).
          - 'sentinel': A árvore de processos do Sentinela e seus componentes.
          - 'all': Visão consolidada de processos com ramificações ativas.
        """
        nodes = []
        links = []
        if not HAS_PSUTIL:
            return {"status": "success", "mode": mode, "count": 0, "threats_count": 0, "nodes": nodes, "links": links}

        proc_dict = {}
        children_map = {}
        threat_pids = set()

        for p in psutil.process_iter(['pid', 'ppid', 'name', 'cmdline', 'cpu_percent', 'memory_percent', 'username']):
            try:
                info = p.info
                pid = info['pid']
                if pid <= 0:
                    continue
                cmd_list = info['cmdline'] or []
                cmd_str = " ".join(cmd_list) if isinstance(cmd_list, list) else str(cmd_list)
                pname = (info['name'] or f"PID-{pid}").strip()
                ppid = info.get('ppid') or 0

                is_threat = False
                severity = "LOW"
                threat_rule = ""
                for sig in self.CRITICAL_SIGNATURES:
                    if all(k in cmd_str.lower() for k in sig["keywords"]):
                        is_threat = True
                        severity = sig["severity"]
                        threat_rule = sig["rule"]
                        threat_pids.add(pid)
                        break

                proc_dict[pid] = {
                    "id": str(pid),
                    "pid": pid,
                    "ppid": ppid,
                    "name": pname,
                    "cmdline": cmd_str[:250],
                    "cpu": round(info.get('cpu_percent') or 0.0, 1),
                    "ram": round(info.get('memory_percent') or 0.0, 1),
                    "user": str(info.get('username') or "SYSTEM"),
                    "is_threat": is_threat,
                    "severity": severity,
                    "threat_rule": threat_rule
                }

                if ppid not in children_map:
                    children_map[ppid] = []
                children_map[ppid].append(pid)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        def get_all_descendants(root_pid: int, collected: set, max_depth: int = 5):
            if max_depth <= 0 or root_pid not in children_map:
                return
            for child in children_map[root_pid]:
                if child not in collected:
                    collected.add(child)
                    get_all_descendants(child, collected, max_depth - 1)

        def get_all_ancestors(leaf_pid: int, collected: set, max_depth: int = 6):
            curr = leaf_pid
            depth = 0
            while curr in proc_dict and depth < max_depth:
                collected.add(curr)
                parent = proc_dict[curr]['ppid']
                if parent in collected or parent <= 0:
                    break
                curr = parent
                depth += 1

        selected_pids = set()

        if focus_pid and focus_pid in proc_dict:
            get_all_ancestors(focus_pid, selected_pids)
            get_all_descendants(focus_pid, selected_pids)
        elif search and search.strip():
            query = search.strip().lower()
            matching = [
                pid for pid, item in proc_dict.items()
                if query in item['name'].lower() or query in item['cmdline'].lower() or query == str(pid)
            ]
            for m in matching[:10]:
                get_all_ancestors(m, selected_pids)
                get_all_descendants(m, selected_pids)
        elif mode == "threats":
            if threat_pids:
                for tp in threat_pids:
                    get_all_ancestors(tp, selected_pids)
                    get_all_descendants(tp, selected_pids)
            else:
                # Se não houver ameaças ativas, cai para user_apps
                mode = "user_apps"

        if not selected_pids and mode == "user_apps":
            explorer_pids = [pid for pid, item in proc_dict.items() if item['name'].lower() == 'explorer.exe']
            for exp_pid in explorer_pids:
                selected_pids.add(exp_pid)
                get_all_descendants(exp_pid, selected_pids, max_depth=4)

        if not selected_pids and mode == "sentinel":
            my_pid = os.getpid()
            get_all_ancestors(my_pid, selected_pids)
            get_all_descendants(my_pid, selected_pids)

        if not selected_pids:
            sorted_parents = sorted(children_map.items(), key=lambda x: len(x[1]), reverse=True)
            for parent_pid, ch_list in sorted_parents[:5]:
                if parent_pid in proc_dict:
                    selected_pids.add(parent_pid)
                    get_all_descendants(parent_pid, selected_pids, max_depth=3)
                else:
                    for ch in ch_list[:8]:
                        selected_pids.add(ch)

        # Limita de forma inteligente para não quebrar a renderização gráfica
        if len(selected_pids) > 60:
            priority_pids = set()
            for pid in selected_pids:
                if proc_dict.get(pid, {}).get('is_threat'):
                    priority_pids.add(pid)
                    get_all_ancestors(pid, priority_pids)
            remaining = list(selected_pids - priority_pids)
            selected_pids = priority_pids.union(set(remaining[:60 - len(priority_pids)]))

        for pid in selected_pids:
            if pid in proc_dict:
                nodes.append(proc_dict[pid])
                ppid = proc_dict[pid]['ppid']
                if ppid in selected_pids:
                    links.append({"source": str(ppid), "target": str(pid)})

        return {
            "status": "success",
            "mode": mode,
            "count": len(nodes),
            "threats_count": sum(1 for n in nodes if n["is_threat"]),
            "nodes": nodes,
            "links": links
        }

    def get_process_lineage(self, pid: int) -> Dict[str, Any]:
        """
        Reconstrói a linhagem forense completa de um processo:
        Ancestrais diretos (pai, avô, etc.), processo alvo e filhos em execução.
        """
        if not HAS_PSUTIL:
            return {"status": "error", "message": "psutil não disponível"}

        try:
            target_proc = psutil.Process(pid)
            target_info = {
                "pid": target_proc.pid,
                "ppid": target_proc.ppid(),
                "name": target_proc.name(),
                "cmdline": " ".join(target_proc.cmdline()) if target_proc.cmdline() else "",
                "status": target_proc.status(),
                "cpu_percent": target_proc.cpu_percent(interval=None),
                "memory_rss_mb": round(target_proc.memory_info().rss / (1024 * 1024), 2),
                "create_time": target_proc.create_time()
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return {"status": "error", "message": f"Processo PID {pid} não encontrado ou acesso negado"}

        # Coleta ancestrais em ordem ascendente
        ancestors = []
        curr = target_proc
        visited = {pid}
        while True:
            try:
                parent = curr.parent()
                if not parent or parent.pid in visited or parent.pid <= 0:
                    break
                visited.add(parent.pid)
                ancestors.append({
                    "pid": parent.pid,
                    "ppid": parent.ppid(),
                    "name": parent.name(),
                    "cmdline": " ".join(parent.cmdline()) if parent.cmdline() else ""
                })
                curr = parent
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break

        # Coleta filhos imediatos
        children = []
        try:
            for ch in target_proc.children(recursive=False):
                try:
                    children.append({
                        "pid": ch.pid,
                        "name": ch.name(),
                        "cmdline": " ".join(ch.cmdline()) if ch.cmdline() else "",
                        "status": ch.status()
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        # Análise heurística de ofuscação do comando alvo
        try:
            from sentinel_core.command_obfuscation_classifier import CommandObfuscationClassifier
            classifier = CommandObfuscationClassifier()
            obfuscation = classifier.analyze_command(target_info["cmdline"])
        except Exception:
            obfuscation = {"score": 0.0, "is_obfuscated": False, "indicators": []}

        return {
            "status": "success",
            "target": target_info,
            "ancestors": list(reversed(ancestors)),  # do mais antigo até o pai imediato
            "children": children,
            "obfuscation_analysis": obfuscation,
            "lineage_depth": len(ancestors) + 1
        }


