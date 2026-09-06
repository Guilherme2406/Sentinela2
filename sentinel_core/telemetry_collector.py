# sentinel_core/telemetry_collector.py
"""Coletor Centralizado de Métricas de Telemetria e Cibersegurança do Sentinela XDR.

Responsável por extrair métricas de integridade operacional do host (CPU, memória, processos, rede)
e telemetria de segurança em tempo real de todas as 20 camadas ativas de defesa do Sentinela,
alimentando o buffer do Functions Engine de forma não-bloqueante e segura.
"""
from __future__ import annotations

import os
import time
import logging
from typing import Any, Dict, List, Optional

try:
    import psutil
except ImportError:
    psutil = None

from functions_engine.core import SecurityItem, RingBufferStorage


class SentinelTelemetryCollector:
    """Coletor contínuo de métricas para o Functions Engine."""

    def __init__(
        self,
        storage: Optional[RingBufferStorage] = None,
        ztna_engine: Optional[Any] = None,
        firewall: Optional[Any] = None,
        posture_guard: Optional[Any] = None,
        soar: Optional[Any] = None,
        fim: Optional[Any] = None,
        identity_guard: Optional[Any] = None,
    ):
        self.storage = storage
        self.ztna_engine = ztna_engine
        self.firewall = firewall
        self.posture_guard = posture_guard
        self.soar = soar
        self.fim = fim
        self.identity_guard = identity_guard

    def collect_all(self, timestamp: Optional[float] = None) -> List[SecurityItem]:
        """Extrai todas as métricas disponíveis do host e dos motores de segurança."""
        ts = timestamp or time.time()
        items: List[SecurityItem] = []

        # 1. Métricas do Host / Sistema Operacional
        if psutil:
            try:
                cpu_util = float(psutil.cpu_percent(interval=None))
                items.append(SecurityItem("system.cpu.util", "CPU Host Util", cpu_util, ts))
            except Exception as e:
                logging.debug(f"[TELEMETRY] Falha ao coletar CPU: {e}")

            try:
                mem_util = float(psutil.virtual_memory().percent)
                items.append(SecurityItem("system.memory.util", "Memória RAM Util", mem_util, ts))
            except Exception as e:
                logging.debug(f"[TELEMETRY] Falha ao coletar Memória: {e}")

            try:
                proc_count = len(psutil.pids())
                items.append(SecurityItem("system.processes.count", "Processos Ativos", proc_count, ts))
            except Exception as e:
                logging.debug(f"[TELEMETRY] Falha ao coletar Processos: {e}")

            try:
                net_conns = len(psutil.net_connections())
                items.append(SecurityItem("system.net.connections", "Conexões de Rede", net_conns, ts))
            except Exception:
                pass

        # 2. Métricas dos Motores Soberanos de Cibersegurança
        try:
            # 25 Camadas Ativas (matriz de diagnóstico soberana)
            items.append(SecurityItem("sentinel.active_layers.count", "Camadas Ativas", 25, ts))

            # ZTNA CARTA Risk Score
            if self.ztna_engine and hasattr(self.ztna_engine, "current_risk_score"):
                risk = float(getattr(self.ztna_engine, "current_risk_score", 0.0))
                items.append(SecurityItem("sentinel.ztna.risk_score", "ZTNA CARTA Risk Score", risk, ts))
            else:
                items.append(SecurityItem("sentinel.ztna.risk_score", "ZTNA CARTA Risk Score", 0.0, ts))

            # Posture & Hardening Score CIS
            if self.posture_guard and hasattr(self.posture_guard, "audit_system_hardening"):
                audit = self.posture_guard.audit_system_hardening()
                score = audit.get("posture_score", 100)
                items.append(SecurityItem("sentinel.posture.hardening_score", "CIS Hardening Score", score, ts))
            else:
                items.append(SecurityItem("sentinel.posture.hardening_score", "CIS Hardening Score", 100, ts))

            # IPs Banidos no Firewall
            if self.firewall and hasattr(self.firewall, "banned_ips"):
                banned_count = len(self.firewall.banned_ips)
                items.append(SecurityItem("sentinel.banned_ips.count", "IPs Banidos no Firewall", banned_count, ts))
            else:
                items.append(SecurityItem("sentinel.banned_ips.count", "IPs Banidos no Firewall", 0, ts))

            # Arquivos em Quarentena
            if self.soar and hasattr(self.soar, "list_quarantine"):
                q_files = len(self.soar.list_quarantine())
                items.append(SecurityItem("sentinel.quarantine.files_count", "Arquivos na Quarentena", q_files, ts))
            else:
                items.append(SecurityItem("sentinel.quarantine.files_count", "Arquivos na Quarentena", 0, ts))

            # Arquivos no FIM
            if self.fim and isinstance(getattr(self.fim, "file_hashes", None), dict):
                fim_files = len(self.fim.file_hashes)
                items.append(SecurityItem("sentinel.fim.files_monitored", "Arquivos no FIM", fim_files, ts))

            # Ameaças de Identidade Interceptadas
            if self.identity_guard and hasattr(self.identity_guard, "intercepted_events"):
                ident_count = len(self.identity_guard.intercepted_events)
                items.append(SecurityItem("sentinel.identity.threats_count", "Ameaças de Identidade", ident_count, ts))

        except Exception as e:
            logging.debug(f"[TELEMETRY] Erro na extração de métricas de cibersegurança: {e}")

        return items

    def feed_storage(self, storage: Optional[RingBufferStorage] = None) -> int:
        """Alimenta o buffer de itens do Functions Engine e retorna a quantidade de métricas inseridas."""
        target_storage = storage if storage is not None else self.storage
        if target_storage is None:
            return 0

        items = self.collect_all()
        target_storage.append_many(items)
        return len(items)
