"""
Sentinela XDR - Motor de Controle de Acesso Baseado em Papéis (RBAC)
Classificação em 3 Níveis: Admin, Suporte, Usuário Normal.
Matriz de permissões dinâmicas: 'O que pode ser visto' e 'O que pode ser mexido'.
"""

import os
import json
import time
import hashlib
import secrets
import logging
from typing import Dict, Any, List, Optional, Set

logger = logging.getLogger("SentinelaRBAC")


class RBACEngine:
    """Motor central de autorização, autenticação e matriz de permissões."""

    CONFIG_FILE = "rbac_config.json"

    # Definição padrão das permissões
    DEFAULT_PERMISSIONS_CATALOG = {
        "views": {
            "view_overview": {"name": "Visão Geral (NOC/SOC)", "desc": "Acessar painel central, KPIs e telemetria básica."},
            "view_edr": {"name": "EDR & Linhagem de Processos", "desc": "Visualizar a árvore de processos e grafo de ataque."},
            "view_network": {"name": "Rede, Perímetro & CTI", "desc": "Visualizar mapa global, regras WFP e feeds de CTI."},
            "view_telemetry": {"name": "Telemetria Avançada Zabbix", "desc": "Visualizar métricas temporais e Functions Engine."},
            "view_fleet": {"name": "Frota Multi-Host", "desc": "Visualizar nós e estações remotas conectadas."},
            "view_logs": {"name": "Logs Forenses & Auditoria SIEM", "desc": "Acessar stream de logs e exportador de relatórios."},
            "view_settings": {"name": "Configurações Globais", "desc": "Acessar painel de configurações do sistema e webhooks."},
            "view_subsystems": {"name": "Gaveta de Módulos", "desc": "Abrir gaveta de subsistemas e acessar modais táticos."},
            "view_amsi_guard": {"name": "AMSI Script Guard", "desc": "Visualizar telemetria e inspeção de scripts fileless."},
            "view_vss_shield": {"name": "Anti-Ransomware VSS Shield", "desc": "Visualizar bloqueios de Shadow Copies e integridade de boot."},
            "view_rwx_hunter": {"name": "Memory RWX Hunter", "desc": "Visualizar anomalias de memória e caça a Beacons."},
            "view_cisa_kev": {"name": "Auditoria CISA KEV", "desc": "Visualizar postura contra vulnerabilidades ativas."},
            "view_stix_cti": {"name": "STIX 2.1 & MISP Feeds", "desc": "Visualizar base de inteligência de ameaças global."},
            "view_cloud_k8s": {"name": "Cloud & Container Guard", "desc": "Visualizar postura de Docker, K8s e nuvem."},
            "view_mini_nids": {"name": "Mini-NIDS & DPI", "desc": "Visualizar inspeção profunda de pacotes."},
            "view_sigma_compiler": {"name": "Compilador Sigma", "desc": "Visualizar regras universais Sigma compiladas."},
            "view_native_etw": {"name": "Native Kernel ETW", "desc": "Visualizar telemetria Ring 0 do Windows."},
            "view_forensics_dumper": {"name": "Live Forensics Dumper", "desc": "Visualizar e gerar dumps cirúrgicos de memória."},
            "view_itdr_kerberos": {"name": "ITDR & Kerberos Guard", "desc": "Visualizar auditoria de Active Directory."},
            "view_honeyfiles": {"name": "Decoy Honeyfiles", "desc": "Visualizar armadilhas de arquivo anti-ransomware."},
            "view_lolbas_guard": {"name": "LOLBAS Blocker", "desc": "Visualizar controle de binários do sistema."}
        },
        "actions": {
            "act_kill_process": {"name": "Derrubar Processos (Kill PID)", "desc": "Finalizar processos hostis no host local ou remoto."},
            "act_firewall_ban": {"name": "Banir/Desbanir IPs", "desc": "Adicionar ou revogar bloqueios no firewall de Kernel/WFP."},
            "act_change_posture": {"name": "Alterar Postura Tática", "desc": "Comutar entre modo Padrão, Elevado e Lockdown."},
            "act_trigger_scan": {"name": "Disparar Varredura Manual", "desc": "Iniciar escaneamento de arquivos e memória RAM."},
            "act_rollback": {"name": "Reversão Anti-Ransomware", "desc": "Restaurar snapshots imutáveis de arquivos."},
            "act_quarantine": {"name": "Manipular Quarentena", "desc": "Excluir ou restaurar artefatos do cofre isolado."},
            "act_isolate_host": {"name": "Isolamento Remoto de Frota", "desc": "Isolar computadores infectados da rede corporativa."},
            "act_config_webhooks": {"name": "Configurar Webhooks/Alertas", "desc": "Alterar credenciais e destinos de notificações corporativas."},
            "act_manage_rbac": {"name": "Gerenciar Permissões e Usuários", "desc": "Alterar matriz de acesso e cadastrar novos operadores."},
            "act_sync_stix": {"name": "Sincronizar Feeds STIX/MISP", "desc": "Disparar download e consolidação de novos IOCs mundiais."},
            "act_remediate_cisa_kev": {"name": "Remediar Vulnerabilidades KEV", "desc": "Aplicar correções e mitigação de fraquezas no host."},
            "act_audit_cloud": {"name": "Auditar Nuvem & K8s", "desc": "Disparar auditoria de containers e metadados."},
            "act_audit_nids": {"name": "Auditoria de Rede NIDS", "desc": "Inspecionar tráfego de rede e pacotes."},
            "act_compile_sigma": {"name": "Compilar Regra Sigma", "desc": "Adicionar ou compilar regras Sigma YAML."},
            "act_dump_forensics": {"name": "Gerar Dump Forense", "desc": "Extrair artefatos cirúrgicos de memória de processos."},
            "act_audit_itdr": {"name": "Auditar Identidade", "desc": "Disparar checagem de ataques Kerberos/AD."},
            "act_check_honeyfiles": {"name": "Verificar Honeyfiles", "desc": "Disparar checagem de integridade das iscas."},
            "act_configure_lolbas": {"name": "Configurar LOLBAS", "desc": "Alterar modo de bloqueio de binários."},
            "act_view_soc": {"name": "Visualizar Fila SOC", "desc": "Acessar fila de alertas, KPIs e métricas do SOC."},
            "act_manage_soc": {"name": "Gerenciar Alertas SOC", "desc": "Atribuir, conter, investigar e encerrar casos na fila SOC."},
            "act_view_audit": {"name": "Consultar Auditoria", "desc": "Ler o trilho global de ações dos operadores."}
        }
    }

    # Matriz inicial por papel
    DEFAULT_ROLE_MATRIX = {
        "ADMIN": {
            "name": "Administrador Soberano",
            "badge_color": "var(--accent-cyan)",
            "views": [
                "view_overview", "view_edr", "view_network", "view_telemetry",
                "view_fleet", "view_logs", "view_settings", "view_subsystems",
                "view_amsi_guard", "view_vss_shield", "view_rwx_hunter", "view_cisa_kev", "view_stix_cti"
            ],
            "actions": [
                "act_kill_process", "act_firewall_ban", "act_change_posture",
                "act_trigger_scan", "act_rollback", "act_quarantine",
                "act_isolate_host", "act_config_webhooks", "act_manage_rbac",
                "act_sync_stix", "act_remediate_cisa_kev"
            ]
        },
        "SUPPORT": {
            "name": "Analista de Suporte / SOC",
            "badge_color": "var(--accent-warning)",
            "views": [
                "view_overview", "view_edr", "view_network", "view_telemetry",
                "view_fleet", "view_logs", "view_subsystems",
                "view_amsi_guard", "view_vss_shield", "view_rwx_hunter", "view_cisa_kev", "view_stix_cti"
            ],
            "actions": [
                "act_trigger_scan", "act_quarantine", "act_kill_process",
                "act_isolate_host", "act_sync_stix"
            ]
        },
        "USER": {
            "name": "Usuário Normal / Viewer",
            "badge_color": "var(--text-muted)",
            "views": [
                "view_overview", "view_logs", "view_cisa_kev"
            ],
            "actions": ["act_trigger_scan"]
        },
        "SOC_ANALYST": {
            "name": "Analista SOC (Tier 1/2)",
            "badge_color": "var(--accent-warning)",
            "views": ["view_overview", "view_logs", "view_subsystems", "view_edr", "view_network"],
            "actions": ["act_view_soc", "act_manage_soc", "act_trigger_scan", "act_quarantine"]
        },
        "SOC_MANAGER": {
            "name": "Gerente SOC (Tier 3)",
            "badge_color": "var(--accent-green)",
            "views": [
                "view_overview", "view_edr", "view_network", "view_telemetry",
                "view_fleet", "view_logs", "view_subsystems", "view_rwx_hunter", "view_cisa_kev"
            ],
            "actions": [
                "act_view_soc", "act_manage_soc", "act_view_audit", "act_trigger_scan",
                "act_quarantine", "act_kill_process", "act_isolate_host"
            ]
        }
    }

    def __init__(self, logger_instance=None):
        self.logger = logger_instance
        self.users: Dict[str, Dict[str, Any]] = {}
        self.role_matrix: Dict[str, Dict[str, Any]] = {}
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.active_user_id: str = "admin"  # Usuário padrão de sessão local

        self._load_config()
        self._log("INFO", "RBAC_INIT", "INIT", f"Motor RBAC operacional ({len(self.users)} usuários, {len(self.role_matrix)} papéis).")

    def _log(self, level: str, category: str, action: str, msg: str):
        try:
            if self.logger and hasattr(self.logger, "log_event"):
                self.logger.log_event(level, category, action, msg)
            elif self.logger and hasattr(self.logger, level.lower()):
                getattr(self.logger, level.lower())(f"[{category}] {msg}")
        except Exception:
            pass
        logging.info(f"[{category}] {msg}")

    @staticmethod
    def _hash_password(password: str, salt: str, iterations: int = 210_000) -> str:
        """Deriva a senha usando PBKDF2-HMAC-SHA256 (key stretching).

        Formato armazenado: ``pbkdf2$<iterations>$<salt-hex>$<digest-hex>``.
        Hashes legados (sha256 simples) continuam sendo verificados com fallback.
        """
        from hashlib import pbkdf2_hmac
        digest = pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations).hex()
        return f"pbkdf2${iterations}${salt}${digest}"

    @classmethod
    def _verify_password(cls, password: str, record: Dict[str, Any]) -> bool:
        """Verifica a senha suportando hashes PBKDF2 e legados (sha256 direto)."""
        import hmac as _hmac
        stored = record.get("password_hash", "")
        salt = record.get("salt", "")
        if not stored or not salt:
            return False
        if stored.startswith("pbkdf2$"):
            try:
                _, iter_str, stored_salt, digest_hex = stored.split("$", 3)
                iterations = int(iter_str)
                computed = cls._hash_password(password, stored_salt, iterations=iterations).split("$", 3)[3]
                return _hmac.compare_digest(computed, digest_hex)
            except Exception:
                return False
        # Fallback: hash legado sha256(password + salt)
        legacy = hashlib.sha256((password + salt).encode("utf-8")).hexdigest()
        return _hmac.compare_digest(legacy, stored)

    def validate_session(self, token: str) -> Optional[Dict[str, Any]]:
        """Retorna a sessão ativa para o token informado, se válida."""
        if not token:
            return None
        session = self.active_sessions.get(token)
        if session is None:
            return None
        # Sessões locais expiram após 12 horas de inatividade
        if session.get("created_at") and (time.time() - session["created_at"]) > 12 * 3600:
            self.active_sessions.pop(token, None)
            return None
        return session

    def _load_config(self):
        """Carrega a configuração persistida do disco ou inicializa padrão corporativo."""
        if os.path.exists(self.CONFIG_FILE):
            try:
                with open(self.CONFIG_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.users = data.get("users", {})
                    self.role_matrix = data.get("role_matrix", {})
                    self.active_user_id = data.get("active_user_id", "admin")
                    return
            except Exception as e:
                self._log("WARNING", "RBAC_LOAD", "ERROR", f"Falha ao ler {self.CONFIG_FILE}: {e}")

        # Configuração padrão caso não exista arquivo
        self.role_matrix = json.loads(json.dumps(self.DEFAULT_ROLE_MATRIX))
        
        # Criação dos 3 usuários padrão
        admin_salt = secrets.token_hex(8)
        support_salt = secrets.token_hex(8)
        user_salt = secrets.token_hex(8)

        self.users = {
            "admin": {
                "id": "admin",
                "username": "Administrador",
                "role": "ADMIN",
                "salt": admin_salt,
                "password_hash": self._hash_password("admin123", admin_salt),
                "created_at": time.time()
            },
            "suporte": {
                "id": "suporte",
                "username": "Analista Suporte",
                "role": "SUPPORT",
                "salt": support_salt,
                "password_hash": self._hash_password("suporte123", support_salt),
                "created_at": time.time()
            },
            "usuario": {
                "id": "usuario",
                "username": "Usuário Normal",
                "role": "USER",
                "salt": user_salt,
                "password_hash": self._hash_password("usuario123", user_salt),
                "created_at": time.time()
            }
        }
        self._save_config()

    def _save_config(self):
        """Persiste usuários e matriz de permissões no disco."""
        try:
            with open(self.CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump({
                    "users": self.users,
                    "role_matrix": self.role_matrix,
                    "active_user_id": self.active_user_id,
                    "updated_at": time.time()
                }, f, indent=2)
        except Exception as e:
            self._log("ERROR", "RBAC_SAVE", "ERROR", f"Erro ao salvar {self.CONFIG_FILE}: {e}")

    # -------------------------------------------------------------
    # GESTÃO DE SESSÕES E AUTENTICAÇÃO
    # -------------------------------------------------------------
    def get_current_user(self) -> Dict[str, Any]:
        """Retorna as informações completas do usuário ativo na sessão."""
        user = self.users.get(self.active_user_id) or self.users.get("admin")
        if not user:
            user = {"id": "admin", "username": "Administrador", "role": "ADMIN"}
        
        role = user.get("role", "USER")
        role_def = self.role_matrix.get(role, self.DEFAULT_ROLE_MATRIX.get(role, {}))
        
        return {
            "id": user.get("id"),
            "username": user.get("username"),
            "role": role,
            "role_name": role_def.get("name", role),
            "badge_color": role_def.get("badge_color", "#fff"),
            "views": role_def.get("views", []),
            "actions": role_def.get("actions", []),
            "is_admin": role == "ADMIN"
        }

    def switch_profile(self, role_or_id: str) -> Dict[str, Any]:
        """Alterna rapidamente o perfil ativo (Admin, Suporte, Usuário) para visualização e testes."""
        target_role = role_or_id.upper()
        found_user = None
        for uid, udata in self.users.items():
            if udata.get("role") == target_role or uid == role_or_id.lower():
                found_user = uid
                break
        
        if found_user:
            self.active_user_id = found_user
            self._save_config()
            self._log("INFO", "RBAC_SWITCH", "SUCCESS", f"Sessão alterada para usuário '{found_user}' (Papel: {target_role}).")
            return {"status": "success", "user": self.get_current_user()}
        
        return {"status": "error", "message": f"Nenhum usuário com perfil '{role_or_id}' encontrado."}

    def authenticate(self, username_or_id: str, password: str) -> Optional[Dict[str, Any]]:
        """Autentica usuário e senha gerando um token de sessão."""
        target = username_or_id.lower()
        user_record = None
        for uid, udata in self.users.items():
            if uid.lower() == target or udata.get("username", "").lower() == target:
                user_record = udata
                break
        
        if not user_record:
            return None
        
        if not self._verify_password(password, user_record):
            return None

        # Upgrade transparente: re-hash legado (sha256 simples) para PBKDF2 na próxima
        # autenticação bem-sucedida, preservando compatibilidade com configs existentes.
        stored_hash = user_record.get("password_hash", "")
        if not stored_hash.startswith("pbkdf2$"):
            new_salt = secrets.token_hex(8)
            user_record["salt"] = new_salt
            user_record["password_hash"] = self._hash_password(password, new_salt)
            self._save_config()

        token = secrets.token_hex(24)
        session_data = {
            "token": token,
            "user_id": user_record["id"],
            "role": user_record["role"],
            "created_at": time.time()
        }
        self.active_sessions[token] = session_data
        self.active_user_id = user_record["id"]
        self._save_config()
        return session_data

    # -------------------------------------------------------------
    # CHECAGEM DE PERMISSÕES (VER & MEXER)
    # -------------------------------------------------------------
    def has_permission(self, perm_key_or_role: str, role: Optional[str] = None, *, action: Optional[str] = None, **kwargs) -> bool:
        """
        Verifica se um papel (ou usuário ativo) possui permissão para ver ou agir.
        Suporta:
          - has_permission(perm_key, role=role)
          - has_permission(perm_key, role)
          - has_permission(role, action)
          - has_permission(role, action=action)
          - has_permission(perm_key)
        """
        if action is not None:
            eff_role = perm_key_or_role.upper()
            eff_action = action
        elif role is not None:
            if perm_key_or_role.upper() in self.role_matrix or perm_key_or_role.upper() in ("ADMIN", "SUPPORT", "USER", "OPERATOR", "ANALYST", "AUDITOR", "VIEWER"):
                eff_role = perm_key_or_role.upper()
                eff_action = role
            else:
                eff_action = perm_key_or_role
                eff_role = role.upper()
        else:
            eff_action = perm_key_or_role
            eff_role = self.get_current_user().get("role", "USER").upper()

        role_map = {
            "OPERATOR": "SUPPORT",
            "ANALYST": "SUPPORT",
            "AUDITOR": "USER",
            "VIEWER": "USER"
        }
        effective_role = role_map.get(eff_role, eff_role)

        if effective_role == "ADMIN":
            return True

        role_def = self.role_matrix.get(effective_role, self.DEFAULT_ROLE_MATRIX.get(effective_role))
        if not role_def:
            return False

        views = role_def.get("views", [])
        actions = role_def.get("actions", [])
        return (eff_action in views) or (eff_action in actions)



    # -------------------------------------------------------------
    # MATRIZ DE PERMISSÕES & GESTÃO DE ACESSO PELO ADMIN
    # -------------------------------------------------------------
    def get_permissions_matrix(self) -> Dict[str, Any]:
        """Retorna a matriz completa de permissões e catálogo para o Centro de Controle."""
        return {
            "catalog": self.DEFAULT_PERMISSIONS_CATALOG,
            "roles": self.role_matrix,
            "current_user": self.get_current_user()
        }

    def update_role_permissions(self, role: str, views: List[str], actions: List[str], requester_role: str = "ADMIN") -> bool:
        """Atualiza dinamicamente as permissões de visualização e ação de um papel."""
        if requester_role != "ADMIN":
            self._log("WARNING", "RBAC_UNAUTHORIZED", "DENIED", "Tentativa não-autorizada de alterar matriz RBAC.")
            return False
        
        role_key = role.upper()
        if role_key not in self.role_matrix:
            return False
        
        # Admin sempre mantém permissão de gerenciar rbac
        if role_key == "ADMIN" and "act_manage_rbac" not in actions:
            actions.append("act_manage_rbac")
            
        self.role_matrix[role_key]["views"] = list(set(views))
        self.role_matrix[role_key]["actions"] = list(set(actions))
        self._save_config()
        self._log("INFO", "RBAC_MATRIX_UPDATE", role_key, f"Permissões do papel '{role_key}' atualizadas pelo Administrador.")
        return True

    def create_user(self, user_id: str, username: str, password: str, role: str, requester_role: str = "ADMIN") -> Dict[str, Any]:
        """Cria um novo operador no sistema."""
        if requester_role != "ADMIN":
            return {"status": "error", "message": "Apenas Administradores podem criar novos usuários."}
        
        clean_id = user_id.lower().strip()
        if clean_id in self.users:
            return {"status": "error", "message": f"Usuário '{clean_id}' já existe."}
        
        role_key = role.upper()
        if role_key not in self.role_matrix:
            return {"status": "error", "message": f"Papel '{role}' inválido."}
        
        salt = secrets.token_hex(8)
        self.users[clean_id] = {
            "id": clean_id,
            "username": username,
            "role": role_key,
            "salt": salt,
            "password_hash": self._hash_password(password, salt),
            "created_at": time.time()
        }
        self._save_config()
        self._log("INFO", "RBAC_USER_CREATED", clean_id, f"Novo operador '{clean_id}' ({role_key}) cadastrado com sucesso.")
        return {"status": "success", "user": {"id": clean_id, "username": username, "role": role_key}}

    def list_users(self) -> List[Dict[str, Any]]:
        """Lista os operadores cadastrados sem expor hashes de senha."""
        return [
            {
                "id": u["id"],
                "username": u.get("username", u["id"]),
                "role": u.get("role", "USER"),
                "created_at": u.get("created_at", 0)
            }
            for u in self.users.values()
        ]
