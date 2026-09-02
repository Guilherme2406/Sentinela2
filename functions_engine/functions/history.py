# functions_engine/functions/history.py
"""Funções de histórico do Sentinela XDR.

Implementa as 16 funções de histórico estilo Zabbix:
last, change, count, first, nodata, percentile, rate, changecount,
fuzzytime, find, counteq, monoinc, monodec, logeventid, logseverity, logsource.
"""
from __future__ import annotations

import math
from typing import Any

from functions_engine.core import (
    FunctionError,
    FunctionErrorType,
    SentinelaFunction,
)
from functions_engine.registry import registry


@registry.register
class LastFunction(SentinelaFunction):
    """Retorna o último valor (mais recente) de um item."""

    name = "last"
    description = "Retorna o último valor (mais recente) de um item."
    category = "histórico"
    params = ["item_id"]
    return_type = float

    def evaluate(self, item_id: str, *args: Any) -> Any:
        self._require_min_args((item_id,), 1, self.name)
        history = self._get_history(str(item_id), limit=1)
        if not history:
            raise FunctionError(
                f"Nenhum dado disponível para o item '{item_id}'",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )
        return history[-1].value


@registry.register
class ChangeFunction(SentinelaFunction):
    """Retorna a diferença entre o último e o penúltimo valor de um item."""

    name = "change"
    description = "Retorna a diferença entre o último e o penúltimo valor de um item."
    category = "histórico"
    params = ["item_id"]
    return_type = float

    def evaluate(self, item_id: str, *args: Any) -> Any:
        self._require_min_args((item_id,), 1, self.name)
        history = self._get_history(str(item_id), limit=2)
        if len(history) < 2:
            raise FunctionError(
                f"Dados insuficientes para 'change' do item '{item_id}' (mínimo 2 pontos)",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )
        last_val = self._to_float(history[-1].value)
        prev_val = self._to_float(history[-2].value)
        return last_val - prev_val


@registry.register
class CountFunction(SentinelaFunction):
    """Retorna o número de valores coletados para um item no período."""

    name = "count"
    description = "Retorna o número de valores coletados para um item no período."
    category = "histórico"
    params = ["item_id", "period", "value", "operator"]
    return_type = int

    def evaluate(self, item_id: str, period: Any = None, value: Any = None, operator: str = "=") -> int:
        self._require_min_args((item_id,), 1, self.name)
        end_ts = self.context.now
        start_ts = None
        if period is not None:
            try:
                p = float(period)
                start_ts = end_ts - p if p > 0 else None
            except (TypeError, ValueError):
                start_ts = None

        history = self._get_history(str(item_id), start_ts, end_ts)
        if not history:
            return 0

        if value is None:
            return len(history)

        count = 0
        for item in history:
            try:
                item_val = float(item.value)
                target = float(value)
            except (TypeError, ValueError):
                continue

            if operator in ("=", "=="):
                if item_val == target:
                    count += 1
            elif operator == "!=":
                if item_val != target:
                    count += 1
            elif operator == ">":
                if item_val > target:
                    count += 1
            elif operator == "<":
                if item_val < target:
                    count += 1
            elif operator == ">=":
                if item_val >= target:
                    count += 1
            elif operator == "<=":
                if item_val <= target:
                    count += 1
        return count


@registry.register
class FirstFunction(SentinelaFunction):
    """Retorna o primeiro valor (mais antigo) de um item no período."""

    name = "first"
    description = "Retorna o primeiro valor (mais antigo) de um item no período."
    category = "histórico"
    params = ["item_id", "period"]
    return_type = float

    def evaluate(self, item_id: str, period: Any = None) -> Any:
        self._require_min_args((item_id,), 1, self.name)
        end_ts = self.context.now
        start_ts = None
        if period is not None:
            try:
                p = float(period)
                start_ts = end_ts - p if p > 0 else None
            except (TypeError, ValueError):
                start_ts = None

        history = self._get_history(str(item_id), start_ts, end_ts)
        if not history:
            raise FunctionError(
                f"Nenhum dado disponível para o item '{item_id}'",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )
        return history[0].value


@registry.register
class NoDataFunction(SentinelaFunction):
    """Retorna 1 se não houver dados para o item no período, 0 caso contrário."""

    name = "nodata"
    description = "Retorna 1 se não houver dados para o item no período, 0 caso contrário."
    category = "histórico"
    params = ["item_id", "period"]
    return_type = int

    def evaluate(self, item_id: str, period: Any = None) -> int:
        self._require_min_args((item_id,), 1, self.name)
        end_ts = self.context.now
        start_ts = None
        if period is not None:
            try:
                p = float(period)
                start_ts = end_ts - p if p > 0 else None
            except (TypeError, ValueError):
                start_ts = None

        history = self._get_history(str(item_id), start_ts, end_ts)
        return 1 if not history else 0


@registry.register
class PercentileFunction(SentinelaFunction):
    """Retorna o percentil dos valores de um item no período."""

    name = "percentile"
    description = "Retorna o percentil dos valores de um item no período."
    category = "histórico"
    params = ["item_id", "period", "percentile"]
    return_type = float

    def evaluate(self, item_id: str, period: Any = None, percentile: Any = 95) -> float:
        self._require_min_args((item_id,), 1, self.name)
        end_ts = self.context.now
        start_ts = None
        if period is not None:
            try:
                p = float(period)
                start_ts = end_ts - p if p > 0 else None
            except (TypeError, ValueError):
                start_ts = None

        values = self._numeric_values(str(item_id), start_ts, end_ts)
        if not values:
            raise FunctionError(
                f"Nenhum dado numérico disponível para o item '{item_id}'",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )

        try:
            p = float(percentile)
        except (TypeError, ValueError):
            p = 95.0

        if not 0 <= p <= 100:
            raise FunctionError(
                f"Percentil deve estar entre 0 e 100, recebido: {p}",
                FunctionErrorType.PARAMETER,
                self.name,
            )

        values.sort()
        n = len(values)
        if n == 1:
            return values[0]

        rank = (p / 100.0) * (n - 1)
        lower = int(math.floor(rank))
        upper = int(math.ceil(rank))
        if lower == upper:
            return values[lower]

        weight = rank - lower
        return values[lower] * (1 - weight) + values[upper] * weight


@registry.register
class RateFunction(SentinelaFunction):
    """Retorna a taxa de variação média por segundo entre o primeiro e o último valor."""

    name = "rate"
    description = "Retorna a taxa de variação média por segundo entre o primeiro e o último valor."
    category = "histórico"
    params = ["item_id", "period"]
    return_type = float

    def evaluate(self, item_id: str, period: Any = None) -> float:
        self._require_min_args((item_id,), 1, self.name)
        end_ts = self.context.now
        start_ts = None
        if period is not None:
            try:
                p = float(period)
                start_ts = end_ts - p if p > 0 else None
            except (TypeError, ValueError):
                start_ts = None

        history = self._get_history(str(item_id), start_ts, end_ts)
        if len(history) < 2:
            raise FunctionError(
                f"Dados insuficientes para 'rate' do item '{item_id}' (mínimo 2 pontos)",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )

        first_val = self._to_float(history[0].value)
        last_val = self._to_float(history[-1].value)
        dt = history[-1].timestamp - history[0].timestamp
        if dt <= 0:
            return 0.0
        return (last_val - first_val) / dt


@registry.register
class ChangeCountFunction(SentinelaFunction):
    """Retorna o número de vezes que o valor de um item mudou no período."""

    name = "changecount"
    description = "Retorna o número de vezes que o valor de um item mudou no período."
    category = "histórico"
    params = ["item_id", "period"]
    return_type = int

    def evaluate(self, item_id: str, period: Any = None) -> int:
        self._require_min_args((item_id,), 1, self.name)
        end_ts = self.context.now
        start_ts = None
        if period is not None:
            try:
                p = float(period)
                start_ts = end_ts - p if p > 0 else None
            except (TypeError, ValueError):
                start_ts = None

        history = self._get_history(str(item_id), start_ts, end_ts)
        if len(history) < 2:
            return 0

        changes = 0
        prev = history[0].value
        for item in history[1:]:
            if item.value != prev:
                changes += 1
                prev = item.value
        return changes


@registry.register
class FuzzyTimeFunction(SentinelaFunction):
    """Retorna 1 se o timestamp do último valor está dentro do período, 0 caso contrário."""

    name = "fuzzytime"
    description = "Retorna 1 se o timestamp do último valor está dentro do período, 0 caso contrário."
    category = "histórico"
    params = ["item_id", "period"]
    return_type = int

    def evaluate(self, item_id: str, period: Any = 60) -> int:
        self._require_min_args((item_id,), 1, self.name)
        try:
            max_age = float(period)
        except (TypeError, ValueError):
            max_age = 60.0

        last_item = self.context.storage.last(str(item_id)) if self.context.storage else None
        if last_item is None:
            return 0

        age = self.context.now - last_item.timestamp
        return 1 if age <= max_age else 0


@registry.register
class FindFunction(SentinelaFunction):
    """Retorna o primeiro valor que corresponde ao padrão de busca."""

    name = "find"
    description = "Retorna o primeiro valor que corresponde ao padrão de busca."
    category = "histórico"
    params = ["item_id", "pattern", "period"]
    return_type = Any

    def evaluate(self, item_id: str, pattern: Any = None, period: Any = None) -> Any:
        self._require_min_args((item_id,), 1, self.name)
        end_ts = self.context.now
        start_ts = None
        if period is not None:
            try:
                p = float(period)
                start_ts = end_ts - p if p > 0 else None
            except (TypeError, ValueError):
                start_ts = None

        history = self._get_history(str(item_id), start_ts, end_ts)
        if not history:
            raise FunctionError(
                f"Nenhum dado disponível para o item '{item_id}'",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )

        if pattern is None:
            return history[0].value

        pattern_str = str(pattern)
        for item in history:
            if pattern_str in str(item.value):
                return item.value

        raise FunctionError(
            f"Nenhum valor encontrado correspondendo ao padrão '{pattern}'",
            FunctionErrorType.NOT_FOUND,
            self.name,
        )


@registry.register
class CountEqFunction(SentinelaFunction):
    """Retorna o número de valores iguais ao valor especificado no período."""

    name = "counteq"
    description = "Retorna o número de valores iguais ao valor especificado no período."
    category = "histórico"
    params = ["item_id", "value", "period"]
    return_type = int

    def evaluate(self, item_id: str, value: Any, period: Any = None) -> int:
        self._require_min_args((item_id, value), 2, self.name)
        end_ts = self.context.now
        start_ts = None
        if period is not None:
            try:
                p = float(period)
                start_ts = end_ts - p if p > 0 else None
            except (TypeError, ValueError):
                start_ts = None

        history = self._get_history(str(item_id), start_ts, end_ts)
        count = 0
        for item in history:
            if item.value == value:
                count += 1
        return count


@registry.register
class MonoIncFunction(SentinelaFunction):
    """Retorna 1 se os valores do item são monotonicamente crescentes, 0 caso contrário."""

    name = "monoinc"
    description = "Retorna 1 se os valores do item são monotonicamente crescentes, 0 caso contrário."
    category = "histórico"
    params = ["item_id", "period"]
    return_type = int

    def evaluate(self, item_id: str, period: Any = None) -> int:
        self._require_min_args((item_id,), 1, self.name)
        end_ts = self.context.now
        start_ts = None
        if period is not None:
            try:
                p = float(period)
                start_ts = end_ts - p if p > 0 else None
            except (TypeError, ValueError):
                start_ts = None

        values = self._numeric_values(str(item_id), start_ts, end_ts)
        if len(values) < 2:
            return 1

        for i in range(1, len(values)):
            if values[i] < values[i - 1]:
                return 0
        return 1


@registry.register
class MonoDecFunction(SentinelaFunction):
    """Retorna 1 se os valores do item são monotonicamente decrescentes, 0 caso contrário."""

    name = "monodec"
    description = "Retorna 1 se os valores do item são monotonicamente decrescentes, 0 caso contrário."
    category = "histórico"
    params = ["item_id", "period"]
    return_type = int

    def evaluate(self, item_id: str, period: Any = None) -> int:
        self._require_min_args((item_id,), 1, self.name)
        end_ts = self.context.now
        start_ts = None
        if period is not None:
            try:
                p = float(period)
                start_ts = end_ts - p if p > 0 else None
            except (TypeError, ValueError):
                start_ts = None

        values = self._numeric_values(str(item_id), start_ts, end_ts)
        if len(values) < 2:
            return 1

        for i in range(1, len(values)):
            if values[i] > values[i - 1]:
                return 0
        return 1


@registry.register
class LogEventIdFunction(SentinelaFunction):
    """Retorna o ID do evento de log mais recente que corresponde ao padrão."""

    name = "logeventid"
    description = "Retorna o ID do evento de log mais recente que corresponde ao padrão."
    category = "histórico"
    params = ["item_id", "pattern", "period"]
    return_type = Any

    def evaluate(self, item_id: str, pattern: Any = None, period: Any = None) -> Any:
        self._require_min_args((item_id,), 1, self.name)
        end_ts = self.context.now
        start_ts = None
        if period is not None:
            try:
                p = float(period)
                start_ts = end_ts - p if p > 0 else None
            except (TypeError, ValueError):
                start_ts = None

        history = self._get_history(str(item_id), start_ts, end_ts)
        if not history:
            raise FunctionError(
                f"Nenhum dado disponível para o item '{item_id}'",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )

        pattern_str = str(pattern) if pattern is not None else ""
        for item in reversed(history):
            value_str = str(item.value)
            if pattern_str in value_str:
                tags = item.tags or {}
                if "event_id" in tags:
                    return tags["event_id"]
                parts = value_str.split()
                if parts:
                    return parts[0]
                return item.value
        return None


@registry.register
class LogSeverityFunction(SentinelaFunction):
    """Retorna a severidade do evento de log mais recente que corresponde ao padrão."""

    name = "logseverity"
    description = "Retorna a severidade do evento de log mais recente que corresponde ao padrão."
    category = "histórico"
    params = ["item_id", "pattern", "period"]
    return_type = Any

    def evaluate(self, item_id: str, pattern: Any = None, period: Any = None) -> Any:
        self._require_min_args((item_id,), 1, self.name)
        end_ts = self.context.now
        start_ts = None
        if period is not None:
            try:
                p = float(period)
                start_ts = end_ts - p if p > 0 else None
            except (TypeError, ValueError):
                start_ts = None

        history = self._get_history(str(item_id), start_ts, end_ts)
        if not history:
            raise FunctionError(
                f"Nenhum dado disponível para o item '{item_id}'",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )

        pattern_str = str(pattern) if pattern is not None else ""
        for item in reversed(history):
            value_str = str(item.value)
            if pattern_str in value_str:
                tags = item.tags or {}
                if "severity" in tags:
                    return tags["severity"]
                for sev in ("CRITICAL", "HIGH", "WARNING", "INFO", "LOW"):
                    if sev in value_str.upper():
                        return sev
                return None
        return None


@registry.register
class LogSourceFunction(SentinelaFunction):
    """Retorna a fonte do evento de log mais recente que corresponde ao padrão."""

    name = "logsource"
    description = "Retorna a fonte do evento de log mais recente que corresponde ao padrão."
    category = "histórico"
    params = ["item_id", "pattern", "period"]
    return_type = Any

    def evaluate(self, item_id: str, pattern: Any = None, period: Any = None) -> Any:
        self._require_min_args((item_id,), 1, self.name)
        end_ts = self.context.now
        start_ts = None
        if period is not None:
            try:
                p = float(period)
                start_ts = end_ts - p if p > 0 else None
            except (TypeError, ValueError):
                start_ts = None

        history = self._get_history(str(item_id), start_ts, end_ts)
        if not history:
            raise FunctionError(
                f"Nenhum dado disponível para o item '{item_id}'",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )

        pattern_str = str(pattern) if pattern is not None else ""
        for item in reversed(history):
            value_str = str(item.value)
            if pattern_str in value_str:
                tags = item.tags or {}
                if "source" in tags:
                    return tags["source"]
                return None
        return None
