# multiagent/__init__.py
"""Pacote Multi-Host do Sentinela XDR.

Transforma o Sentinela em um XDR real: um nó central ("hub") coordena
N agentes remotos ("agent") que enviam heartbeat, telemetria e eventos
de segurança em tempo real, com correlação cross-host entre máquinas.
"""
from __future__ import annotations

from multiagent.config import MultiAgentConfig, load_config, default_config_path
from multiagent.registry import AgentRegistry, HostRecord
from multiagent.bus import MultiAgentEventBus
from multiagent.agent import MultiAgentClient
from multiagent.server import MultiAgentServer

__all__ = [
    "MultiAgentConfig",
    "load_config",
    "default_config_path",
    "AgentRegistry",
    "HostRecord",
    "MultiAgentEventBus",
    "MultiAgentClient",
    "MultiAgentServer",
]

__version__ = "1.0.0"