# functions_engine/functions/aggregation.py
"""Funções de agregação simples do Sentinela XDR.

Implementa: avg, max, min, sum, item_count.
"""
from __future__ import annotations

from typing import Any

from functions_engine.core import (
    FunctionError,
    FunctionErrorType,
    SentinelaFunction,
)
from functions_engine.registry import registry


@registry.register
class AvgFunction(SentinelaFunction):
    """Retorna a média aritmética dos valores de um item no período."""

    name = "avg"
    description = "Retorna a média aritmética dos valores de um item no período."
    category = "agregação"
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

        values = self._numeric_values(str(item_id), start_ts, end_ts)
        if not values:
            raise FunctionError(
                f"Nenhum dado numérico disponível para o item '{item_id}'",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )
        return sum(values) / len(values)


@registry.register
class MaxAggFunction(SentinelaFunction):
    """Retorna o valor máximo dos valores de um item no período."""

    name = "max"
    description = "Retorna o valor máximo dos valores de um item no período."
    category = "agregação"
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

        values = self._numeric_values(str(item_id), start_ts, end_ts)
        if not values:
            raise FunctionError(
                f"Nenhum dado numérico disponível para o item '{item_id}'",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )
        return max(values)


@registry.register
class MinAggFunction(SentinelaFunction):
    """Retorna o valor mínimo dos valores de um item no período."""

    name = "min"
    description = "Retorna o valor mínimo dos valores de um item no período."
    category = "agregação"
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

        values = self._numeric_values(str(item_id), start_ts, end_ts)
        if not values:
            raise FunctionError(
                f"Nenhum dado numérico disponível para o item '{item_id}'",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )
        return min(values)


@registry.register
class SumFunction(SentinelaFunction):
    """Retorna a soma dos valores de um item no período."""

    name = "sum"
    description = "Retorna a soma dos valores de um item no período."
    category = "agregação"
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

        values = self._numeric_values(str(item_id), start_ts, end_ts)
        if not values:
            raise FunctionError(
                f"Nenhum dado numérico disponível para o item '{item_id}'",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )
        return sum(values)


@registry.register
class ItemCountFunction(SentinelaFunction):
    """Retorna o número de valores coletados para um item no período."""

    name = "item_count"
    description = "Retorna o número de valores coletados para um item no período."
    category = "agregação"
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
        return len(history)
