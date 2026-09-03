# multiagent/agent.py
"""Cliente Multi-Host (papel "agent").

Coleta heartbeat, telemetria e eventos locais do Sentinela e os envia
periodicamente ao hub central via HTTP JSON com token compartilhado.
Roda em thread daemon — falhas de rede não derrubam o nó local.
"""
from __future__ import annotations

import time
import socket
import logging
import threading
from typing import Any, Dict, Optional

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

from multiagent.config import MultiAgentConfig
from multiagent.bus import MultiAgentEventBus

logger = logging.getLogger("SENTINEL-MULTIAGENT")

SENTINEL_VERSION = "2.1.0-MULTIHOST"


class MultiAgentClient:
    """Thread daemon que sincroniza este host com o hub central."""

    def __init__(self, config: MultiAgentConfig, event_bus: Optional[MultiAgentEventBus] = None):
        self.config = config
        self.bus = event_bus or MultiAgentEventBus()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.heartbeat = False
        self.heartbeat_ok = False
        self.last_error = ""
        self.sync_count = 0
        self.layers_active = 0
        self.telemetry_provider: Optional[Any] = None

    # ------------------------------------------------------------------
    # API pública
    # ------------------------------------------------------------------
    def set_telemetry_provider(self, provider: Any) -> None:
        """Registra um provedor de telemetria (ex.: feed de métricas do host)."""
        self.telemetry_provider = provider

    def push_local_event(self, severity: str, category: str, target: str, description: str, **extra: Any) -> None:
        """Enfileira um evento local para sincronização com o hub (usado pelo hook do logger)."""
        self.bus.push(severity, category, target, description, **extra)

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._run_loop, daemon=True, name="SentinelMultiAgentClient"
        )
        self._thread.start()
        logger.info(
            f"[MULTI-AGENT] Cliente ativado: reportando como '{self.config.agent_id}' "
            f"para {self.config.hub_url}."
        )

    def stop(self) -> None:
        self._running = False
        try:
            self._stop_event.set()
        except Exception:
            pass
        logger.info("[MULTIAGENT] Cliente encerrado.")

    @property
    def running(self) -> bool:
        return self._running and (self._thread is not None and self._thread.is_alive())

    # ------------------------------------------------------------------
    # Loop principal
    # ------------------------------------------------------------------
    def _run_loop(self) -> None:
        last_tel = 0.0
        while self._running:
            try:
                now = time.time()
                ok = self._post("/api/multiagent/heartbeat", self._build_heartbeat())
                if ok:
                    self.heartbeat = True
                    self.last_error = ""
                    self.sync_count += 1
                    if now - last_tel >= self.config.telemetry_interval:
                        self._send_telemetry()
                        last_tel = now
                    events = self.bus.drain()
                    if events:
                        self._send_events(events)
                else:
                    self.heartbeat = False
            except Exception as e:
                self.heartbeat = False
                self.last_error = str(e)[:200]
                logger.debug(f"[MULTIAGENT] Falha no ciclo: {e}")
            try:
                self._stop_event.wait(self.config.heartbeat_interval)
            except Exception:
                break

    # ------------------------------------------------------------------
    # Payloads
    # ------------------------------------------------------------------
    def _build_heartbeat(self) -> Dict[str, Any]:
        import platform
        payload = {
            "agent_id": self.config.agent_id,
            "hostname": socket.gethostname(),
            "ip": self._local_ip(),
            "platform": f"{platform.system()} {platform.release()}",
            "version": SENTINEL_VERSION,
            "layers_active": self.layers_active or self._count_layers(),
            "defense_mode": self._get_defense_mode(),
            "uptime": time.time() - self._boot_ts(),
            "engine_status": self._get_engine_status(),
        }
        return payload

    def _send_telemetry(self) -> None:
        metrics = self._collect_metrics()
        if metrics:
            self._post("/api/multiagent/telemetry", {
                "agent_id": self.config.agent_id,
                "metrics": metrics,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            })

    def _send_events(self, events: Any) -> None:
        self._post("/api/multiagent/events", {
            "agent_id": self.config.agent_id,
            "events": list(events),
        })

    # ------------------------------------------------------------------
    # Coleta local de telemetria (provedor injetado ou fallback psutil)
    # ------------------------------------------------------------------
    def _collect_metrics(self) -> Dict[str, Any]:
        metrics: Dict[str, Any] = {}
        try:
            import psutil
            metrics["cpu_util"] = round(float(psutil.cpu_percent(interval=None)), 1)
            metrics["memory_util"] = round(float(psutil.virtual_memory().percent), 1)
            metrics["processes"] = len(psutil.pids())
            try:
                metrics["connections"] = len(psutil.net_connections())
            except Exception:
                metrics["connections"] = 0
        except Exception:
            pass

        if self.telemetry_provider is not None:
            try:
                extra = self.telemetry_provider()
                if isinstance(extra, dict):
                    metrics.update(extra)
            except Exception as e:
                logger.debug(f"[MULTIAGENT] Provedor de telemetria falhou: {e}")

        # Métricas operacionais mínimas para o dashboard do hub
        metrics.setdefault("layers_active", self.layers_active or 20)
        metrics.setdefault("defense_mode", self._get_defense_mode())
        return metrics

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _local_ip() -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.3)
            try:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
            finally:
                s.close()
        except Exception:
            return "127.0.0.1"

    @staticmethod
    def _boot_ts() -> float:
        try:
            import psutil
            return psutil.boot_time()
        except Exception:
            return time.time()

    def _count_layers(self) -> int:
        try:
            from sentinel_api import telemetry_collector_instance
            if telemetry_collector_instance:
                items = telemetry_collector_instance.collect_all()
                for it in items:
                    if it.item_id == "sentinel.active_layers.count":
                        return int(it.value)
        except Exception:
            pass
        return 20

    def _get_defense_mode(self) -> str:
        try:
            import sentinel_api as _api
            return str(getattr(_api, "current_defense_mode", "STANDARD"))
        except Exception:
            return "STANDARD"

    def _get_engine_status(self) -> Dict[str, str]:
        status: Dict[str, str] = {}
        try:
            from sentinel_api import get_engine_status
            status = get_engine_status() if callable(get_engine_status) else {}
        except Exception:
            pass
        return status

    # ------------------------------------------------------------------
    # Transporte HTTP
    # ------------------------------------------------------------------
    def _post(self, path: str, payload: Dict[str, Any]) -> bool:
        if requests is None:  # pragma: no cover
            return False
        url = self.config.hub_url.rstrip("/") + path
        headers = {"Content-Type": "application/json", "X-Sentinel-Token": self.config.token or ""}
        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=6)
            return resp.status_code < 400
        except Exception as e:
            self.last_error = str(e)[:200]
            return False