# multiagent/bus.py
"""Barramento de eventos local do agente multi-host.

Desacopla o logger/loop do Sentinela do envio de rede: eventos de segurança
locais entram numa fila e são descarregados em batch para o hub a cada ciclo.
"""
from __future__ import annotations

import time
import threading
import logging
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("SENTINEL-MULTIAGENT")


class MultiAgentEventBus:
    """Fila thread-safe de eventos locais aguardando sincronização com o hub."""

    def __init__(self, max_pending: int = 1000, flush_size: int = 25):
        self._queue: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self.max_pending = max_pending
        self.flush_size = flush_size
        self._listeners: List[Callable[[List[Dict[str, Any]]], None]] = []

    def push(self, severity: str, category: str, target: str, description: str, **extra: Any) -> None:
        """Enfileira um evento local para envio ao hub."""
        event = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "severity": str(severity).upper(),
            "category": str(category).upper(),
            "target": str(target),
            "description": str(description),
        }
        event.update(extra)
        with self._lock:
            self._queue.append(event)
            if len(self._queue) > self.max_pending:
                # Descarta o mais antigo para evitar crescimento infinito
                self._queue.pop(0)

    def drain(self, max_items: Optional[int] = None) -> List[Dict[str, Any]]:
        """Extrai (e remove) os eventos pendentes da fila."""
        limit = max_items if max_items is not None else self.flush_size
        with self._lock:
            if not self._queue:
                return []
            batch = self._queue[:limit]
            del self._queue[:limit]
            return batch

    def __len__(self) -> int:
        with self._lock:
            return len(self._queue)

    @property
    def pending(self) -> int:
        return len(self)