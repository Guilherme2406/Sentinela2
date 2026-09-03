# multiagent/server.py
"""Servidor Multi-Host (papel "hub") — Blueprint Flask do Sentinela XDR.

Expõe endpoints de ingestão (heartbeat/telemetria/eventos) que agentes
remotos consomem, e endpoints de consulta que alimentam o dashboard central.
"""
from __future__ import annotations

import time
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
    return provided == token


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

        # Eventos recebidos -> propagados para dashboard (SSE) e log central
        self.registry.event_listeners.append(self._on_remote_event)
        self.registry.correlation_listeners.append(self._on_correlation)

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
        return {"status": "success", "agent_id": rec.agent_id}

    def _handle_telemetry(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        agent_id = str(payload.get("agent_id", ""))
        rec = self.registry.update_telemetry(agent_id, payload.get("metrics") or {})
        if rec is None:
            return {"status": "error", "message": "Host não registrado"}
        return {"status": "success", "agent_id": agent_id}

    # ------------------------------------------------------------------
    # Callbacks internos
    # ------------------------------------------------------------------
    def _on_remote_event(self, agent_id: str, event: Dict[str, Any]) -> None:
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