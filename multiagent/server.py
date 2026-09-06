# multiagent/server.py
"""Servidor Multi-Host (papel "hub") — Blueprint Flask do Sentinela XDR.

Expõe endpoints de ingestão (heartbeat/telemetria/eventos) que agentes
remotos consomem, e endpoints de consulta que alimentam o dashboard central.
"""
from __future__ import annotations

import os
import json
import time
import hmac
import sqlite3
import logging
import threading
from typing import Any, Callable, Dict, List, Optional

from flask import Blueprint, jsonify, request

from multiagent.config import MultiAgentConfig
from multiagent.registry import AgentRegistry

logger = logging.getLogger("SENTINEL-MULTIAGENT")

bp = Blueprint("multiagent", __name__)

#: Instância global injetada via init_app
_server_instances: Dict[str, Optional["MultiAgentServer"]] = {"instance": None}


def _auth_required(config: MultiAgentConfig) -> bool:
    """Valida o token compartilhado (se configurado). Retorna True se permitido."""
    token = config.token or ""
    if not token:
        return True
    provided = request.headers.get("X-Sentinel-Token", "")
    return hmac.compare_digest(str(provided), str(token))


def _register_server(server: "MultiAgentServer") -> None:
    _server_instances["instance"] = server


class MultiAgentServer:
    """Coordena ingestão de agentes e correlação cross-host."""

    def __init__(self, config: MultiAgentConfig):
        self.config = config
        self.registry = AgentRegistry(
            offline_timeout=max(10.0, config.offline_timeout),
            state_dir=config.state_dir,
            max_events_per_host=config.max_events_per_host,
        )
        self.event_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None
        self.correlation_callback: Optional[Callable[[Dict[str, Any]], None]] = None
        self._correlation_history: List[Dict[str, Any]] = []
        self._correlation_lock = threading.Lock()
        self._dedup: Dict[str, float] = {}

        self.registry.event_listeners.append(self._on_remote_event)
        self.registry.correlation_listeners.append(self._on_correlation)

        # Gestão Centralizada de Políticas de Frota e Isolamento Remoto
        self.fleet_policies: Dict[str, Any] = {
            "defense_mode": "STANDARD",
            "usb_policy": "READ_ONLY",
            "sigma_active": True,
            "quarantine_threshold": 80.0
        }
        self.host_policies: Dict[str, Dict[str, Any]] = {}
        self.isolated_hosts: set = set()

        vault_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "sentinel_vault"
        )
        os.makedirs(vault_dir, exist_ok=True)
        self.soc_events_db = os.path.join(vault_dir, "soc_events.db")
        self._init_soc_db()

    def get_effective_policy(self, agent_id: str) -> Dict[str, Any]:
        policy = dict(self.fleet_policies)
        if agent_id in self.host_policies:
            policy.update(self.host_policies[agent_id])
        return policy

    def isolate_host(self, agent_id: str) -> bool:
        self.isolated_hosts.add(agent_id)
        logger.warning(f"🛑 [MULTIAGENT] Host '{agent_id}' marcado para ISOLAMENTO REMOTO.")
        return True

    def unisolate_host(self, agent_id: str) -> bool:
        if agent_id in self.isolated_hosts:
            self.isolated_hosts.remove(agent_id)
            logger.info(f"🟢 [MULTIAGENT] Host '{agent_id}' liberado do isolamento remoto.")
            return True
        return False

    # ------------------------------------------------------------------
    def init_app(self, app: Any) -> None:
        _register_server(self)
        app.register_blueprint(bp, url_prefix="/api/multiagent")
        self.registry.load_state()
        logger.info(
            f"[MULTIAGENT] Hub ativo: aceitando agentes em /api/multiagent/* "
            f"(token={'habilitado' if self.config.token else 'desabilitado'})."
        )

    def _auth(self) -> bool:
        return _auth_required(self.config)

    def _handle_heartbeat(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        rec = self.registry.register(payload)
        return {
            "status": "success",
            "agent_id": rec.agent_id,
            "policy": self.get_effective_policy(rec.agent_id),
            "isolated": rec.agent_id in self.isolated_hosts
        }

    def _handle_telemetry(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        agent_id = str(payload.get("agent_id", ""))
        rec = self.registry.update_telemetry(agent_id, payload.get("metrics") or {})
        if rec is None:
            return {"status": "error", "message": "Host não registrado"}
        return {"status": "success", "agent_id": agent_id}

    # ------------------------------------------------------------------
    # Callbacks internos
    def _init_soc_db(self):
        try:
            with sqlite3.connect(self.soc_events_db) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS remote_soc_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        agent_id TEXT NOT NULL,
                        event_type TEXT,
                        severity TEXT DEFAULT 'INFO',
                        source TEXT,
                        timestamp REAL,
                        payload TEXT
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_remote_time ON remote_soc_events(timestamp)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_remote_agent ON remote_soc_events(agent_id)")
                conn.commit()
        except Exception as e:
            logger.debug(f"[MULTIAGENT] Falha ao inicializar soc_events.db: {e}")

    def _persist_soc_event(self, agent_id: str, event: Dict[str, Any]) -> None:
        try:
            now = time.time()
            ts = float(event.get("timestamp") or now)
            sev = str(event.get("severity") or "INFO").upper()
            etype = str(event.get("event_type") or event.get("type") or "REMOTE_TELEMETRY")
            src = str(event.get("source") or "AGENT_REMOTE")
            payload_str = json.dumps(event, ensure_ascii=False)
            with sqlite3.connect(self.soc_events_db) as conn:
                conn.execute(
                    "INSERT INTO remote_soc_events (agent_id, event_type, severity, source, timestamp, payload) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (agent_id, etype, sev, src, ts, payload_str)
                )
                conn.commit()
        except Exception as e:
            logger.debug(f"[MULTIAGENT] Falha ao persistir evento soc: {e}")

    # ------------------------------------------------------------------
    def _on_remote_event(self, agent_id: str, event: Dict[str, Any]) -> None:
        self._persist_soc_event(agent_id, event)
        if self.event_callback:
            try:
                self.event_callback(agent_id, event)
            except Exception as e:
                logger.debug(f"[MULTIAGENT] Callback de evento falhou: {e}")

    def _on_correlation(self, alert: Dict[str, Any]) -> None:
        self._bump_correlation(alert)

    def _bump_correlation(self, alert: Dict[str, Any]) -> None:
        dedup_key = f"{alert['rule']}:{alert.get('ioc','')}:{','.join(alert.get('hosts',[]))}"
        now = time.time()
        with self._correlation_lock:
            if self._dedup_ttl(dedup_key, now):
                return
            self._correlation_history.append(alert)
            if len(self._correlation_history) > 100:
                self._correlation_history = self._correlation_history[-100:]
        if self.correlation_callback:
            try:
                self.correlation_callback(alert)
            except Exception as e:
                logger.debug(f"[MULTIAGENT] Callback de correlação falhou: {e}")

    def _dedup_ttl(self, key: str, now: float, ttl: float = 300.0) -> bool:
        if key in self._dedup and (now - self._dedup[key]) < ttl:
            return True
        self._dedup[key] = now
        return False

    def get_correlations(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._correlation_lock:
            return list(reversed(self._correlation_history[-limit:]))

    def status_summary(self) -> Dict[str, Any]:
        hosts = self.registry.list_hosts()
        return {
            "status": "success",
            "role": self.config.role,
            "hosts_count": len(hosts),
            "online_count": self.registry.online_count(),
            "hosts": hosts,
            "correlations": self.get_correlations(30),
            "events_count": sum(h.get("events_count", 0) for h in hosts),
        }

    def _handle_events(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        agent_id = str(payload.get("agent_id", ""))
        events = payload.get("events") or []
        added = 0
        for ev in events:
            if isinstance(ev, dict):
                rec = self.registry.add_event(agent_id, ev)
                if rec is not None:
                    added += 1
        # Força correlação a cada lote de eventos
        if added:
            alerts = self.registry.evaluate_correlations(
                window=self.config.incident_window,
                mass_offline_threshold=self.config.mass_offline_threshold,
            )
            for alert in alerts:
                self._bump_correlation(alert)
        return {"status": "success", "events_added": added}


# ==================================================================
# ROTAS FLASK (Blueprint)
# ==================================================================
@bp.route("/heartbeat", methods=["POST"])
def multiagent_heartbeat():
    server = _server_instances.get("instance")
    if server is None or not server._auth():
        return jsonify({"status": "error", "message": "Não autorizado"}), 401
    result = server._handle_heartbeat(request.get_json(silent=True) or {})
    return jsonify(result), 200


@bp.route("/telemetry", methods=["POST"])
def multiagent_telemetry():
    server = _server_instances.get("instance")
    if server is None or not server._auth():
        return jsonify({"status": "error", "message": "Não autorizado"}), 401
    result = server._handle_telemetry(request.get_json(silent=True) or {})
    return jsonify(result), 200


@bp.route("/events", methods=["POST"])
def multiagent_events():
    server = _server_instances.get("instance")
    if server is None or not server._auth():
        return jsonify({"status": "error", "message": "Não autorizado"}), 401
    result = server._handle_events(request.get_json(silent=True) or {})
    return jsonify(result), 200


@bp.route("/status", methods=["GET"])
def multiagent_status():
    server = _server_instances.get("instance")
    if server is None:
        return jsonify({"status": "error", "message": "Hub não inicializado"}), 404
    return jsonify(server.status_summary()), 200


@bp.route("/hosts", methods=["GET"])
def multiagent_hosts():
    server = _server_instances.get("instance")
    if server is None:
        return jsonify({"status": "error", "message": "Hub não inicializado"}), 404
    return jsonify({"status": "success", "hosts": server.registry.list_hosts()}), 200


@bp.route("/events/list", methods=["GET"])
def multiagent_events_list():
    server = _server_instances.get("instance")
    if server is None:
        return jsonify({"status": "error", "message": "Hub não inicializado"}), 404
    limit = request.args.get("limit", default=200, type=int)
    return jsonify({"status": "success", "events": server.registry.get_all_events(limit)}), 200


@bp.route("/correlations", methods=["GET"])
def multiagent_correlations():
    server = _server_instances.get("instance")
    if server is None:
        return jsonify({"status": "error", "message": "Hub não inicializado"}), 404
    return jsonify({"status": "success", "correlations": server.get_correlations()}), 200


@bp.route("/hosts/<agent_id>/remove", methods=["POST"])
def multiagent_remove_host(agent_id: str):
    server = _server_instances.get("instance")
    if server is None:
        return jsonify({"status": "error", "message": "Hub não inicializado"}), 404
    removed = server.registry.remove_host(agent_id)
    return jsonify({"status": "success" if removed else "not_found", "removed": removed}), 200


@bp.route("/policies", methods=["GET"])
def multiagent_get_policies():
    server = _server_instances.get("instance")
    if server is None:
        return jsonify({"status": "error", "message": "Hub não inicializado"}), 404
    return jsonify({
        "status": "success",
        "fleet_policies": server.fleet_policies,
        "host_policies": server.host_policies,
        "isolated_hosts": list(server.isolated_hosts)
    }), 200


@bp.route("/policies", methods=["POST"])
def multiagent_update_policies():
    server = _server_instances.get("instance")
    if server is None or not server._auth():
        return jsonify({"status": "error", "message": "Não autorizado"}), 401
    data = request.get_json(silent=True) or {}
    agent_id = data.get("agent_id")
    updates = data.get("policy") or data
    # Remove chaves de controle
    cleaned = {k: v for k, v in updates.items() if k not in ("agent_id", "policy")}
    if agent_id:
        if agent_id not in server.host_policies:
            server.host_policies[agent_id] = {}
        server.host_policies[agent_id].update(cleaned)
    else:
        server.fleet_policies.update(cleaned)
    return jsonify({
        "status": "success",
        "fleet_policies": server.fleet_policies,
        "host_policies": server.host_policies
    }), 200


@bp.route("/hosts/<agent_id>/isolate", methods=["POST"])
def multiagent_isolate_host_endpoint(agent_id: str):
    server = _server_instances.get("instance")
    if server is None or not server._auth():
        return jsonify({"status": "error", "message": "Não autorizado"}), 401
    server.isolate_host(agent_id)
    return jsonify({"status": "success", "agent_id": agent_id, "isolated": True}), 200


@bp.route("/hosts/<agent_id>/unisolate", methods=["POST"])
def multiagent_unisolate_host_endpoint(agent_id: str):
    server = _server_instances.get("instance")
    if server is None or not server._auth():
        return jsonify({"status": "error", "message": "Não autorizado"}), 401
    unisolated = server.unisolate_host(agent_id)
    return jsonify({"status": "success", "agent_id": agent_id, "isolated": False, "unisolated": unisolated}), 200


@bp.route("/soc/events", methods=["GET"])
def multiagent_soc_events_endpoint():
    """Consulta histórico central de eventos remotos (SIEM-lite) com janela em horas."""
    server = _server_instances.get("instance")
    if server is None or not server._auth():
        return jsonify({"status": "error", "message": "Não autorizado"}), 401

    try:
        hours = float(request.args.get("hours", 24))
    except (ValueError, TypeError):
        hours = 24.0

    limit = max(1, min(int(request.args.get("limit", 100)), 500))
    since = time.time() - (hours * 3600)
    events = []

    try:
        with sqlite3.connect(server.soc_events_db) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM remote_soc_events WHERE timestamp >= ? ORDER BY timestamp DESC LIMIT ?",
                (since, limit)
            ).fetchall()
            for r in rows:
                d = dict(r)
                if d.get("payload"):
                    try:
                        d["payload"] = json.loads(d["payload"])
                    except Exception:
                        pass
                events.append(d)
    except Exception as e:
        logger.debug(f"[MULTIAGENT] Falha ao consultar eventos soc: {e}")

    return jsonify({"status": "success", "total": len(events), "hours": hours, "events": events}), 200