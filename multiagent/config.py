# multiagent/config.py
"""Configuração do modo Multi-Host do Sentinela XDR.

Papéis suportados:
    - "hub":  este host é o coordenador central (recebe agentes, correlaciona e exibe).
    - "agent": este host reporta-se a um hub remoto (envia heartbeat/telemetria/eventos).
    - "off":  multi-host desabilitado (comportamento padrão atual).
"""
from __future__ import annotations

import os
import json
import socket
import logging
import threading
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional

logger = logging.getLogger("SENTINEL-MULTIAGENT")


def default_config_path() -> str:
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, "multiagent_config.json")


@dataclass
class MultiAgentConfig:
    """Configuração completa do modo multi-host."""

    #: Papel deste nó: "hub" | "agent" | "off"
    role: str = "off"

    #: Identificador deste nó (padrão: hostname)
    agent_id: str = ""

    #: Endereço do hub central (usado quando role == "agent")
    hub_url: str = "http://localhost:5000"

    #: Token compartilhado de autenticação mínima entre hub e agentes
    token: str = ""

    #: Intervalo (segundos) do heartbeat dos agentes remotos
    heartbeat_interval: float = 5.0

    #: Intervalo (segundos) do envio de telemetria
    telemetry_interval: float = 10.0

    #: Tempo (segundos) sem heartbeat para considerar o host offline
    offline_timeout: float = 20.0

    #: Diretório de persistência de estado do hub
    state_dir: str = ""

    #: Limite de eventos mantidos no hub por host
    max_events_per_host: int = 200

    #: Limiar de hosts simultaneamente offline para gerar alarme de interrupção em massa
    mass_offline_threshold: int = 3

    #: Janela (segundos) para correlação de surto de incidentes entre hosts
    incident_window: float = 60.0

    def __post_init__(self) -> None:
        if not self.agent_id:
            self.agent_id = socket.gethostname().split(".")[0].lower() or "sentinel-node"
        if not self.state_dir:
            base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.state_dir = os.path.join(base, "multiagent_state")

    # ------------------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MultiAgentConfig":
        valid = {k: v for k, v in (data or {}).items() if hasattr(cls, k)}
        return cls(**valid)

    @property
    def enabled(self) -> bool:
        return self.role in ("hub", "agent")


def _ensure_dir(path: str) -> None:
    try:
        os.makedirs(path, exist_ok=True)
    except Exception:
        pass


def load_config(path: Optional[str] = None) -> MultiAgentConfig:
    """Carrega a configuração multi-host do arquivo JSON (criando o padrão se ausente)."""
    cfg_path = path or default_config_path()
    if os.path.exists(cfg_path):
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            cfg = MultiAgentConfig.from_dict(data)
            logger.info(f"[MULTI-AGENT] Config carregada de {cfg_path} (papel: {cfg.role}).")
            return cfg
        except Exception as e:
            logger.warning(f"[MULTI-AGENT] Erro ao ler config {cfg_path}: {e}. Usando padrão.")
    cfg = MultiAgentConfig()
    _persist(cfg, cfg_path)
    return cfg


def _persist(cfg: "MultiAgentConfig", path: Optional[str] = None) -> None:
    cfg_path = path or default_config_path()
    try:
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(cfg.to_dict(), f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.warning(f"[MULTI-AGENT] Erro ao salvar config em {cfg_path}: {e}")


def save_config(cfg: "MultiAgentConfig", path: Optional[str] = None) -> None:
    """Persiste a configuração multi-host no disco (thread-safe)."""
    _lock = threading.Lock()
    with _lock:
        _persist(cfg, path)
    logger.info(f"[MULTI-AGENT] Config salva (papel: {cfg.role}).")