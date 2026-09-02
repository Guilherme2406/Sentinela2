# functions_engine/functions/predictive.py
"""Funções preditivas do Sentinela XDR.

Implementa: forecast (regressão linear com janela deslizante) e
timeleft (extrapolação linear para atingimento de threshold).
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from functions_engine.core import (
    FunctionError,
    FunctionErrorType,
    SentinelaFunction,
)
from functions_engine.registry import registry


@dataclass
class ForecastResult:
    """Resultado de uma previsão."""

    predicted_value: float
    confidence_interval: Tuple[float, float]
    trend_direction: str  # "UP", "DOWN", "STABLE"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "predicted_value": self.predicted_value,
            "confidence_interval": list(self.confidence_interval),
            "trend_direction": self.trend_direction,
        }


def _linear_regression(
    x: List[float], y: List[float]
) -> Tuple[float, float, float]:
    """Executa regressão linear simples.

    Returns:
        (slope, intercept, r_squared)
    """
    n = len(x)
    if n < 2:
        raise ValueError("Mínimo de 2 pontos para regressão linear")

    mean_x = sum(x) / n
    mean_y = sum(y) / n

    sxx = sum((xi - mean_x) ** 2 for xi in x)
    sxy = sum((xi - mean_x) * (yi - mean_y) for xi, yi in zip(x, y))

    if sxx == 0:
        slope = 0.0
    else:
        slope = sxy / sxx

    intercept = mean_y - slope * mean_x

    # R² (coeficiente de determinação)
    ss_tot = sum((yi - mean_y) ** 2 for yi in y)
    ss_res = sum((yi - (slope * xi + intercept)) ** 2 for xi, yi in zip(x, y))
    r_squared = 1.0 - (ss_res / ss_tot) if ss_tot > 0 else 0.0

    return slope, intercept, r_squared


@registry.register
class ForecastFunction(SentinelaFunction):
    """Previsão por regressão linear com janela deslizante.

    Args:
        item_id: Identificador do item.
        period: Janela de tempo para análise (segundos).
        horizon: Período futuro a prever (segundos).
    """

    name = "forecast"
    description = "Previsão por regressão linear com janela deslizante."
    category = "preditiva"
    params = ["item_id", "period", "horizon"]
    return_type = Dict[str, Any]

    def evaluate(self, item_id: str, period: Any = 3600, horizon: Any = 300) -> Dict[str, Any]:
        self._require_min_args((item_id,), 1, self.name)
        end_ts = self.context.now
        start_ts = None
        if period is not None:
            try:
                p = float(period)
                start_ts = end_ts - p if p > 0 else None
            except (TypeError, ValueError):
                start_ts = None

        try:
            h = float(horizon)
        except (TypeError, ValueError):
            h = 300.0

        history = self._get_history(str(item_id), start_ts, end_ts)
        if len(history) < 3:
            raise FunctionError(
                f"Dados insuficientes para 'forecast' do item '{item_id}' (mínimo 3 pontos)",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )

        # Prepara dados: x = tempo relativo, y = valor
        x: List[float] = []
        y: List[float] = []
        t0 = history[0].timestamp
        for item in history:
            try:
                y.append(float(item.value))
                x.append(item.timestamp - t0)
            except (TypeError, ValueError):
                continue

        if len(x) < 3:
            raise FunctionError(
                f"Dados numéricos insuficientes para 'forecast' do item '{item_id}'",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )

        slope, intercept, r_squared = _linear_regression(x, y)

        # Previsão no horizonte
        last_x = x[-1]
        predicted = slope * (last_x + h) + intercept

        # Intervalo de confiança (aproximado: ± 1.96 * desvio padrão dos resíduos)
        residuals = [yi - (slope * xi + intercept) for xi, yi in zip(x, y)]
        n = len(residuals)
        mean_res = sum(residuals) / n
        var_res = sum((r - mean_res) ** 2 for r in residuals) / max(1, n - 1)
        std_res = math.sqrt(var_res)
        margin = 1.96 * std_res

        # Direção da tendência
        if slope > 0.0001:
            direction = "UP"
        elif slope < -0.0001:
            direction = "DOWN"
        else:
            direction = "STABLE"

        result = ForecastResult(
            predicted_value=predicted,
            confidence_interval=(predicted - margin, predicted + margin),
            trend_direction=direction,
        )
        return result.to_dict()


@registry.register
class TimeLeftFunction(SentinelaFunction):
    """Extrapolação linear para estimar o tempo até atingir um threshold.

    Args:
        item_id: Identificador do item.
        threshold: Valor limite a ser atingido.
        period: Janela de tempo para análise (segundos).
    """

    name = "timeleft"
    description = "Extrapolação linear para estimar o tempo até atingir um threshold."
    category = "preditiva"
    params = ["item_id", "threshold", "period"]
    return_type = float

    def evaluate(self, item_id: str, threshold: Any, period: Any = 3600) -> float:
        self._require_min_args((item_id, threshold), 2, self.name)
        end_ts = self.context.now
        start_ts = None
        if period is not None:
            try:
                p = float(period)
                start_ts = end_ts - p if p > 0 else None
            except (TypeError, ValueError):
                start_ts = None

        try:
            target = float(threshold)
        except (TypeError, ValueError):
            raise FunctionError(
                f"threshold inválido: {threshold!r}",
                FunctionErrorType.PARAMETER,
                self.name,
            )

        history = self._get_history(str(item_id), start_ts, end_ts)
        if len(history) < 3:
            raise FunctionError(
                f"Dados insuficientes para 'timeleft' do item '{item_id}' (mínimo 3 pontos)",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )

        x: List[float] = []
        y: List[float] = []
        t0 = history[0].timestamp
        for item in history:
            try:
                y.append(float(item.value))
                x.append(item.timestamp - t0)
            except (TypeError, ValueError):
                continue

        if len(x) < 3:
            raise FunctionError(
                f"Dados numéricos insuficientes para 'timeleft' do item '{item_id}'",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )

        slope, intercept, _ = _linear_regression(x, y)

        if abs(slope) < 1e-10:
            # Sem tendência: nunca atinge o threshold (ou já está nele)
            last_val = y[-1]
            if (target > last_val and slope >= 0) or (target < last_val and slope <= 0):
                return math.inf
            return 0.0

        # Tempo até atingir o threshold: t = (target - intercept) / slope
        time_to_target = (target - intercept) / slope
        time_remaining = time_to_target - x[-1]

        if time_remaining < 0:
            return 0.0
        return time_remaining