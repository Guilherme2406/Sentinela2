# functions_engine/functions/time_functions.py
"""Funções de tempo e data do Sentinela XDR.

Implementa: date, dayofmonth, dayofweek, now, time.
"""
from __future__ import annotations

import time as time_module
from datetime import datetime, timezone
from typing import Any

from functions_engine.core import (
    FunctionError,
    FunctionErrorType,
    SentinelaFunction,
)
from functions_engine.registry import registry


def _get_dt(timestamp: Any, tz_offset: int = 0) -> datetime:
    """Converte um timestamp Unix em datetime com offset de timezone."""
    if timestamp is None:
        ts = time_module.time()
    else:
        try:
            ts = float(timestamp)
        except (TypeError, ValueError):
            raise FunctionError(
                f"timestamp inválido: {timestamp!r}",
                FunctionErrorType.PARAMETER,
            )
    return datetime.fromtimestamp(ts, tz=timezone.utc)


@registry.register
class NowFunction(SentinelaFunction):
    """Retorna o timestamp Unix atual em segundos."""

    name = "now"
    description = "Retorna o timestamp Unix atual em segundos."
    category = "tempo"
    params = []
    return_type = float

    def evaluate(self, *args: Any) -> float:
        return self.context.now


@registry.register
class DateFunction(SentinelaFunction):
    """Retorna a data atual no formato YYYY-MM-DD (ou formato personalizado)."""

    name = "date"
    description = "Retorna a data atual no formato YYYY-MM-DD (ou formato personalizado)."
    category = "tempo"
    params = ["format"]
    return_type = str

    def evaluate(self, format_str: Any = "%Y-%m-%d") -> str:
        dt = _get_dt(None, self.context.timezone_offset)
        return dt.strftime(str(format_str))


@registry.register
class DayOfMonthFunction(SentinelaFunction):
    """Retorna o dia do mês (1-31) de um timestamp."""

    name = "dayofmonth"
    description = "Retorna o dia do mês (1-31) de um timestamp."
    category = "tempo"
    params = ["timestamp"]
    return_type = int

    def evaluate(self, timestamp: Any = None) -> int:
        dt = _get_dt(timestamp, self.context.timezone_offset)
        return dt.day


@registry.register
class DayOfWeekFunction(SentinelaFunction):
    """Retorna o dia da semana (1=Segunda, 7=Domingo) de um timestamp."""

    name = "dayofweek"
    description = "Retorna o dia da semana (1=Segunda, 7=Domingo) de um timestamp."
    category = "tempo"
    params = ["timestamp"]
    return_type = int

    def evaluate(self, timestamp: Any = None) -> int:
        dt = _get_dt(timestamp, self.context.timezone_offset)
        # Python: Monday=0, Sunday=6 -> Zabbix: Monday=1, Sunday=7
        return dt.weekday() + 1


@registry.register
class TimeFunction(SentinelaFunction):
    """Retorna a hora atual no formato HH:MM:SS (ou formato personalizado)."""

    name = "time"
    description = "Retorna a hora atual no formato HH:MM:SS (ou formato personalizado)."
    category = "tempo"
    params = ["format"]
    return_type = str

    def evaluate(self, format_str: Any = "%H:%M:%S") -> str:
        dt = _get_dt(None, self.context.timezone_offset)
        return dt.strftime(str(format_str))