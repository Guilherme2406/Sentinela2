# multiagent/registry.py
"""Registro central de hosts remotos do hub do Sentinela Multi-Host.

Gerencia estados de conectividade (online/offline), telemetria agregada,
eventos por host e alarmes de correlação cross-host — tudo thread-safe.
"""
from __future__ import annotations

import os
import json
import time
import socket
import logging
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("SENTINEL-MULTIAGENT")


def _hostname() -> str:
    try:
        return socket.gethostname().split(".")[0].lower() or "unknown"
    except Exception:
        return "unknown"


@dataclass
class HostRecord:
    """Estado agregado de um agente remoto registrado no hub."""

    agent_id: str
    hostname: str = ""
    ip: str = ""
    platform: str = ""
    version: str = ""
    layers_active: int = 0
    defense_mode: str = "STANDARD"
    first_seen: float = field(default_factory=time.time)
    last_heartbeat: float = field(default_factory=time.time)
    last_telemetry: float = 0.0
    online: bool = True
    uptime: float = 0.0
    metrics: Dict[str, Any] = field(default_factory=dict)
    events: List[Dict[str, Any]] = field(default_factory=list)
    events_count: int = 0
    engine_status: Dict[str, str] = field(default_factory=dict)

    def is_online(self, timeout: float = 20.0) -> bool:
        return (time.time() - self.last_heartbeat) <= timeout

    def to_dict(self, timeout: float = 20.0, max_events: int = 30) -> Dict[str, Any]:
        self.online = self.is_online(timeout)
        return {
            "agent_id": self.agent_id,
            "hostname": self.hostname or self.agent_id,
            "ip": self.ip,
            "platform": self.platform,
            "version": self.version,
            "layers_active": self.layers_active,
            "defense_mode": self.defense_mode,
            "online": self.online,
            "first_seen": self.first_seen,
            "last_heartbeat": self.last_heartbeat,
            "last_telemetry": self.last_telemetry,
            "uptime": round(self.uptime, 1),
            "metrics": self.metrics,
            "events": self.events[-max_events:],
            "events_count": self.events_count,
            "engine_status": self.engine_status,
        }


class AgentRegistry:
    """Thread-safe coleção de HostRecords com persistência opcional."""

    def __init__(self, offline_timeout: float = 20.0, state_dir: str = "", max_events_per_host: int = 200):
        self._hosts: Dict[str, HostRecord] = {}
        self._lock = threading.RLock()
        self.offline_timeout = offline_timeout
        self.max_events_per_host = max_events_per_host
        self.state_dir = state_dir or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "multiagent_state"
        )
        #: callbacks [OnHostEvent] -> None (para propagar para SSE/logger)
        self.event_listeners: List[Callable[[str, Dict[str, Any]], None]] = []
        self.correlation_listeners: List[Callable[[Dict[str, Any]], None]] = []
        self._state_save_lock = threading.Lock()

    # ------------------------------------------------------------------
    # CRUD de hosts
    # ------------------------------------------------------------------
    def register(self, payload: Dict[str, Any]) -> HostRecord:
        """Registra/atualiza um heartbeat de um agente remoto."""
        agent_id = str(payload.get("agent_id") or payload.get("hostname") or _hostname())
        with self._lock:
            now = time.time()
            rec = self._hosts.get(agent_id)
            is_new = rec is None
            if rec is None:
                rec = HostRecord(agent_id=agent_id)
                self._hosts[agent_id] = rec

            if is_new:
                rec.first_seen = now
                rec.hostname = str(payload.get("hostname") or agent_id)
                rec.ip = str(payload.get("ip") or "")
                rec.platform = str(payload.get("platform") or "")
                rec.version = str(payload.get("version") or "")
                rec.layers_active = int(payload.get("layers_active") or 0)
                rec.defense_mode = str(payload.get("defense_mode") or "STANDARD")
                engine = payload.get("engine_status")
                if isinstance(engine, dict):
                    rec.engine_status = engine
                logger.info(f"[MULTI-AGENT] Novo host registrado: '{agent_id}' ({rec.ip}).")
            else:
                # Atualiza campos que podem mudar entre heartbeats
                if payload.get("hostname"):
                    rec.hostname = str(payload["hostname"])
                if payload.get("ip"):
                    rec.ip = str(payload["ip"])
                if payload.get("platform"):
                    rec.platform = str(payload["platform"])
                if payload.get("version"):
                    rec.version = str(payload["version"])
                if payload.get("layers_active") is not None:
                    rec.layers_active = int(payload["layers_active"])
                if payload.get("defense_mode"):
                    rec.defense_mode = str(payload["defense_mode"])
                engine = payload.get("engine_status")
                if isinstance(engine, dict):
                    rec.engine_status = engine

            rec.last_heartbeat = now
            rec.uptime = float(payload.get("uptime") or 0.0)
            rec.online = True

            self._persist()
            return rec

    def update_telemetry(self, agent_id: str, metrics: Dict[str, Any]) -> Optional[HostRecord]:
        with self._lock:
            rec = self._hosts.get(agent_id)
            if rec is None:
                return None
            rec.metrics = dict(metrics or {})
            rec.last_telemetry = time.time()
            return rec

    def add_event(self, agent_id: str, event: Dict[str, Any]) -> Optional[HostRecord]:
        """Adiciona um evento de segurança recebido de um agente remoto."""
        with self._lock:
            rec = self._hosts.get(agent_id)
            if rec is None:
                return None
            event = dict(event)
            event.setdefault("timestamp", time.strftime("%Y-%m-%d %H:%M:%S"))
            event.setdefault("agent_id", agent_id)
            rec.events.append(event)
            rec.events_count += 1
            if len(rec.events) > self.max_events_per_host:
                rec.events = rec.events[-self.max_events_per_host:]

        # Notifica listeners (SSE / logger central do hub) fora do lock
        for listener in list(self.event_listeners):
            try:
                listener(agent_id, event)
            except Exception:
                pass

        self._persist()
        return rec

    # ------------------------------------------------------------------
    # Consultas
    # ------------------------------------------------------------------
    def get(self, agent_id: str) -> Optional[HostRecord]:
        with self._lock:
            rec = self._hosts.get(agent_id)
            if rec is not None:
                rec.online = rec.is_online(self.offline_timeout)
            return rec

    def list_hosts(self) -> List[Dict[str, Any]]:
        with self._lock:
            now = time.time()
            results = []
            for rec in self._hosts.values():
                rec.online = (now - rec.last_heartbeat) <= self.offline_timeout
                results.append(rec.to_dict(self.offline_timeout))
            return sorted(results, key=lambda h: h["hostname"].lower())

    @property
    def host_count(self) -> int:
        with self._lock:
            return len(self._hosts)

    def online_count(self, timeout: Optional[float] = None) -> int:
        to = timeout if timeout is not None else self.offline_timeout
        with self._lock:
            now = time.time()
            return sum(1 for r in self._hosts.values() if (now - r.last_heartbeat) <= to)

    def get_all_events(self, limit: int = 200) -> List[Dict[str, Any]]:
        """Eventos de todos os hosts, ordenados por recência (do mais recente)."""
        with self._lock:
            all_events: List[Dict[str, Any]] = []
            for rec in self._hosts.values():
                all_events.extend(rec.events)
            all_events.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
            return all_events[:limit]

    def remove_host(self, agent_id: str) -> bool:
        with self._lock:
            existed = self._hosts.pop(agent_id, None) is not None
            if existed:
                self._persist()
            return existed

    # ------------------------------------------------------------------
    # Persistência de estado (hub)
    # ------------------------------------------------------------------
    def _persist(self) -> None:
        try:
            os.makedirs(self.state_dir, exist_ok=True)
            data = {
                "hosts": [h.to_dict(self.offline_timeout, max_events=10) for h in self._hosts.values()],
                "saved_at": time.time(),
            }
            path = os.path.join(self.state_dir, "multiagent_state.json")
            with self._state_save_lock:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            logger.debug(f"[MULTI-AGENT] Falha na persistência de estado: {e}")

    def load_state(self) -> int:
        """Carrega hosts previamente conhecidos (agora offline até novo heartbeat)."""
        path = os.path.join(self.state_dir, "multiagent_state.json")
        if not os.path.exists(path):
            return 0
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            loaded = 0
            for h in data.get("hosts", []):
                aid = h.get("agent_id")
                if not aid:
                    continue
                rec = HostRecord(
                    agent_id=aid,
                    hostname=h.get("hostname", aid),
                    ip=h.get("ip", ""),
                    platform=h.get("platform", ""),
                    version=h.get("version", ""),
                    layers_active=int(h.get("layers_active") or 0),
                    first_seen=float(h.get("first_seen", time.time())),
                    last_heartbeat=float(h.get("last_heartbeat", time.time())),
                    uptime=float(h.get("uptime") or 0.0),
                    metrics=dict(h.get("metrics") or {}),
                    online=False,
                )
                rec.events_count = int(h.get("events_count") or 0)
                rec.events = [dict(e) for e in (h.get("events") or []) if isinstance(e, dict)]
                rec.engine_status = dict(h.get("engine_status") or {})
                rec.defense_mode = str(h.get("defense_mode") or "STANDARD")
                rec.last_telemetry = float(h.get("last_telemetry") or 0.0)
                self._hosts[aid] = rec
                loaded += 1
            logger.info(f"[MULTI-AGENT] Estado restaurado: {loaded} host(s) conhecido(s).")
            return loaded
        except Exception as e:
            logger.debug(f"[MULTI-AGENT] Falha ao carregar estado: {e}")
            return 0

    # ------------------------------------------------------------------
    # Correlação cross-host (motor XDR)
    # ------------------------------------------------------------------
    def evaluate_correlations(self, window: float = 120.0, mass_offline_threshold: int = 3) -> List[Dict[str, Any]]:
        """Detecta padrões de ataque entre múltiplos hosts.

        Regras implementadas:
          1. MESMO IOC observado em >= 2 hosts diferentes (movimentação lateral).
          2. >= N hosts simultaneamente offline (interrupção em massa / Wiper).
          3. Surto de eventos CRITICAL/HIGH em >= 2 hosts na mesma janela.
        """
        import re
        alerts: List[Dict[str, Any]] = []
        now = time.time()

        with self._lock:
            # 1. IOC compartilhado
            ioc_map: Dict[str, set] = {}
            for rec in self._hosts.values():
                for ev in rec.events:
                    ioc = self._extract_ioc(ev)
                    if not ioc:
                        continue
                    ioc_map.setdefault(ioc, set()).add(rec.agent_id)

            for ioc, hosts in ioc_map.items():
                if len(hosts) >= 2:
                    alerts.append({
                        "rule": "SHARED_IOC_MULTIHOST",
                        "severity": "CRITICAL",
                        "ioc": ioc,
                        "hosts": sorted(hosts),
                        "description": f"IOC '{ioc}' observado em {len(hosts)} hosts distintos — possível movimentação lateral ou ataque coordenado.",
                        "detected_at": now,
                    })

            # 2. Interrupção em massa
            cutoff_hb = now - self.offline_timeout
            offline_hosts = [r.agent_id for r in self._hosts.values() if r.last_heartbeat < cutoff_hb]
            if len(offline_hosts) >= mass_offline_threshold:
                alerts.append({
                    "rule": "MASS_OFFLINE",
                    "severity": "DISASTER",
                    "ioc": "",
                    "hosts": sorted(offline_hosts),
                    "description": f"{len(offline_hosts)} hosts simultaneamente offline — possível interrupção em massa ou Wiper ativo.",
                    "detected_at": now,
                })

            # 3. Surto de incidentes coordenados
            critical_hosts: Dict[str, set] = {}
            cutoff_ts = now - window
            for rec in self._hosts.values():
                for ev in rec.events:
                    try:
                        ev_ts = time.mktime(time.strptime(str(ev.get("timestamp", "")), "%Y-%m-%d %H:%M:%S"))
                    except Exception:
                        ev_ts = rec.last_heartbeat
                    sev = str(ev.get("severity") or ev.get("level") or "").upper()
                    if sev in ("CRITICAL", "HIGH", "DISASTER") and ev_ts >= cutoff_ts:
                        cat = str(ev.get("category") or "INCIDENT")
                        critical_hosts.setdefault(cat, set()).add(rec.agent_id)

            for cat, hosts in critical_hosts.items():
                if len(hosts) >= 2:
                    alerts.append({
                        "rule": "COORDINATED_INCIDENT",
                        "severity": "HIGH",
                        "ioc": "",
                        "hosts": sorted(hosts),
                        "description": f"Surto de incidentes '{cat}' em {len(hosts)} hosts dentro de {int(window)}s — possível ataque coordenado.",
                        "detected_at": now,
                    })

        for alert in alerts:
            for listener in list(self.correlation_listeners):
                try:
                    listener(alert)
                except Exception:
                    pass
        return alerts

    @staticmethod
    def _extract_ioc(event: Dict[str, Any]) -> str:
        """Extrai um IOC simples (IP público ou hash SHA-256) de um evento."""
        import re
        text = " ".join(
            str(event.get(k, "")) for k in ("target", "description", "ip", "source_ip", "details")
        )
        m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", text)
        if m:
            ip = m.group(1)
            if ip.startswith(("127.", "10.", "192.168.", "169.254.")):
                return ""
            return ip
        m = re.search(r"([a-fA-F0-9]{64})", text)
        if m:
            return m.group(1)
        return ""