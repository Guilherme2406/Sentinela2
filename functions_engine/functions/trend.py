# functions_engine/functions/trend.py
"""Funções de tendência do Sentinela XDR.

Implementa: trendavg, trendcount, trendmax, trendmin, trendsum,
baselinedev, baselinewma, trendstl.
"""
from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Tuple

from functions_engine.core import (
    FunctionError,
    FunctionErrorType,
    SentinelaFunction,
)
from functions_engine.registry import registry


def _get_period_range(period: Any, now: float) -> Tuple[Optional[float], float]:
    end_ts = now
    start_ts = None
    if period is not None:
            try:
                p = float(period)
                start_ts = end_ts - p if p > 0 else None
            except (TypeError, ValueError):
                start_ts = None
    return start_ts, end_ts


@registry.register
class TrendAvgFunction(SentinelaFunction):
    """Retorna a média dos valores de um item no período (tendência)."""

    name = "trendavg"
    description = "Retorna a média dos valores de um item no período (tendência)."
    category = "tendência"
    params = ["item_id", "period"]
    return_type = float

    def evaluate(self, item_id: str, period: Any = None) -> float:
        self._require_min_args((item_id,), 1, self.name)
        start_ts, end_ts = _get_period_range(period, self.context.now)
        values = self._numeric_values(str(item_id), start_ts, end_ts)
        if not values:
            raise FunctionError(
                f"Nenhum dado numérico disponível para o item '{item_id}'",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )
        return sum(values) / len(values)


@registry.register
class TrendCountFunction(SentinelaFunction):
    """Retorna o número de valores de um item no período (tendência)."""

    name = "trendcount"
    description = "Retorna o número de valores de um item no período (tendência)."
    category = "tendência"
    params = ["item_id", "period"]
    return_type = int

    def evaluate(self, item_id: str, period: Any = None) -> int:
        self._require_min_args((item_id,), 1, self.name)
        start_ts, end_ts = _get_period_range(period, self.context.now)
        history = self._get_history(str(item_id), start_ts, end_ts)
        return len(history)


@registry.register
class TrendMaxFunction(SentinelaFunction):
    """Retorna o valor máximo de um item no período (tendência)."""

    name = "trendmax"
    description = "Retorna o valor máximo de um item no período (tendência)."
    category = "tendência"
    params = ["item_id", "period"]
    return_type = float

    def evaluate(self, item_id: str, period: Any = None) -> float:
        self._require_min_args((item_id,), 1, self.name)
        start_ts, end_ts = _get_period_range(period, self.context.now)
        values = self._numeric_values(str(item_id), start_ts, end_ts)
        if not values:
            raise FunctionError(
                f"Nenhum dado numérico disponível para o item '{item_id}'",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )
        return max(values)


@registry.register
class TrendMinFunction(SentinelaFunction):
    """Retorna o valor mínimo de um item no período (tendência)."""

    name = "trendmin"
    description = "Retorna o valor mínimo de um item no período (tendência)."
    category = "tendência"
    params = ["item_id", "period"]
    return_type = float

    def evaluate(self, item_id: str, period: Any = None) -> float:
        self._require_min_args((item_id,), 1, self.name)
        start_ts, end_ts = _get_period_range(period, self.context.now)
        values = self._numeric_values(str(item_id), start_ts, end_ts)
        if not values:
            raise FunctionError(
                f"Nenhum dado numérico disponível para o item '{item_id}'",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )
        return min(values)


@registry.register
class TrendSumFunction(SentinelaFunction):
    """Retorna a soma dos valores de um item no período (tendência)."""

    name = "trendsum"
    description = "Retorna a soma dos valores de um item no período (tendência)."
    category = "tendência"
    params = ["item_id", "period"]
    return_type = float

    def evaluate(self, item_id: str, period: Any = None) -> float:
        self._require_min_args((item_id,), 1, self.name)
        start_ts, end_ts = _get_period_range(period, self.context.now)
        values = self._numeric_values(str(item_id), start_ts, end_ts)
        if not values:
            raise FunctionError(
                f"Nenhum dado numérico disponível para o item '{item_id}'",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )
        return sum(values)


@registry.register
class BaselineDevFunction(SentinelaFunction):
    """Retorna o desvio padrão (z-score) dos valores de um item em relação à média semanal."""

    name = "baselinedev"
    description = "Retorna o desvio padrão (z-score) dos valores de um item em relação à média semanal."
    category = "tendência"
    params = ["item_id", "period"]
    return_type = float

    def evaluate(self, item_id: str, period: Any = 604800) -> float:
        self._require_min_args((item_id,), 1, self.name)
        start_ts, end_ts = _get_period_range(period, self.context.now)
        values = self._numeric_values(str(item_id), start_ts, end_ts)
        if len(values) < 2:
            raise FunctionError(
                f"Dados insuficientes para 'baselinedev' do item '{item_id}' (mínimo 2 pontos)",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )

        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / (len(values) - 1)
        stddev = math.sqrt(variance)
        if stddev == 0:
            return 0.0

        last_val = values[-1]
        return (last_val - mean) / stddev


@registry.register
class BaselineWmaFunction(SentinelaFunction):
    """Retorna a média móvel ponderada (WMA) dos valores de um item."""

    name = "baselinewma"
    description = "Retorna a média móvel ponderada (WMA) dos valores de um item."
    category = "tendência"
    params = ["item_id", "period"]
    return_type = float

    def evaluate(self, item_id: str, period: Any = None) -> float:
        self._require_min_args((item_id,), 1, self.name)
        start_ts, end_ts = _get_period_range(period, self.context.now)
        values = self._numeric_values(str(item_id), start_ts, end_ts)
        if not values:
            raise FunctionError(
                f"Nenhum dado numérico disponível para o item '{item_id}'",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )

        n = len(values)
        if n == 1:
            return values[0]

        weights = list(range(1, n + 1))
        total_weight = sum(weights)
        wma = sum(v * w for v, w in zip(values, weights)) / total_weight
        return wma


@registry.register
class TrendStlFunction(SentinelaFunction):
    """Retorna a decomposição STL (Seasonal-Trend using Loess) simplificada."""

    name = "trendstl"
    description = "Retorna a decomposição STL (Seasonal-Trend using Loess) simplificada."
    category = "tendência"
    params = ["item_id", "period"]
    return_type = Dict[str, float]

    def evaluate(self, item_id: str, period: Any = None) -> Dict[str, float]:
        self._require_min_args((item_id,), 1, self.name)
        start_ts, end_ts = _get_period_range(period, self.context.now)
        history = self._get_history(str(item_id), start_ts, end_ts)
        if len(history) < 3:
            raise FunctionError(
                f"Dados insuficientes para 'trendstl' do item '{item_id}' (mínimo 3 pontos)",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )

        values = []
        timestamps = []
        for item in history:
            try:
                values.append(float(item.value))
                timestamps.append(item.timestamp)
            except (TypeError, ValueError):
                continue

        if len(values) < 3:
            raise FunctionError(
                f"Dados numéricos insuficientes para 'trendstl' do item '{item_id}'",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )

        # Tendência: média móvel simples (janela 3)
        trend = []
        for i in range(len(values)):
            lo = max(0, i - 1)
            hi = min(len(values), i + 2)
            trend.append(sum(values[lo:hi]) / (hi - lo))

        # Sazonalidade: média por dia da semana (0-6)
        import datetime
        seasonal_means: Dict[int, List[float]] = {}
        for ts, v in zip(timestamps, values):
            dow = datetime.datetime.fromtimestamp(ts).weekday()
            seasonal_means.setdefault(dow, []).append(v)

        seasonal_avg = {
            dow: sum(vals) / len(vals)
            for dow, vals in seasonal_means.items()
        }

        # Resíduo: valor - tendência - sazonalidade
        residuals = []
        for i, (ts, v) in enumerate(zip(timestamps, values)):
            dow = datetime.datetime.fromtimestamp(ts).weekday()
            seasonal = seasonal_avg.get(dow, 0.0)
            residuals.append(v - trend[i] - seasonal)

        return {
            "trend": trend[-1],
            "seasonal": seasonal_avg.get(datetime.datetime.fromtimestamp(timestamps[-1]).weekday(), 0.0),
            "residual": residuals[-1],
            "value": values[-1],
        }
