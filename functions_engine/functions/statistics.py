# functions_engine/functions/statistics.py
"""Funções de estatística avançada do Sentinela XDR.

Implementa: kurtosis, mad, skewness, stddevpop, stddevsamp, varpop,
varsamp, sumofsquares, histogram_quantile, bucket_percentile.
"""
from __future__ import annotations

import math
from typing import Any, Dict, List, Optional

from functions_engine.core import (
    FunctionError,
    FunctionErrorType,
    SentinelaFunction,
)
from functions_engine.registry import registry


def _get_values(item_id: str, period: Any, func: SentinelaFunction) -> List[float]:
    """Obtém valores numéricos de um item no período."""
    end_ts = func.context.now
    start_ts = None
    if period is not None:
            try:
                p = float(period)
                start_ts = end_ts - p if p > 0 else None
            except (TypeError, ValueError):
                start_ts = None
    return func._numeric_values(str(item_id), start_ts, end_ts)


@registry.register
class KurtosisFunction(SentinelaFunction):
    """Retorna a curtose (kurtosis) dos valores de um item no período.

    Mede o "achatamento" da distribuição. Distribuição normal tem curtose ≈ 0
    (excesso de curtose).
    """

    name = "kurtosis"
    description = "Retorna a curtose (kurtosis) dos valores de um item no período."
    category = "estatística"
    params = ["item_id", "period"]
    return_type = float

    def evaluate(self, item_id: str, period: Any = None) -> float:
        self._require_min_args((item_id,), 1, self.name)
        values = _get_values(item_id, period, self)
        if len(values) < 4:
            raise FunctionError(
                f"Dados insuficientes para 'kurtosis' do item '{item_id}' (mínimo 4 pontos)",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )

        n = len(values)
        mean = sum(values) / n
        variance = sum((v - mean) ** 2 for v in values) / n
        if variance == 0:
            return 0.0

        m4 = sum((v - mean) ** 4 for v in values) / n
        m2 = variance
        # Excesso de curtose (Fisher): (m4 / m2^2) - 3
        return (m4 / (m2 ** 2)) - 3.0


@registry.register
class MadFunction(SentinelaFunction):
    """Retorna o desvio absoluto mediano (MAD) dos valores de um item no período.

    Medida robusta de dispersão estatística.
    """

    name = "mad"
    description = "Retorna o desvio absoluto mediano (MAD) dos valores de um item no período."
    category = "estatística"
    params = ["item_id", "period"]
    return_type = float

    def evaluate(self, item_id: str, period: Any = None) -> float:
        self._require_min_args((item_id,), 1, self.name)
        values = _get_values(item_id, period, self)
        if not values:
            raise FunctionError(
                f"Nenhum dado numérico disponível para o item '{item_id}'",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )

        sorted_vals = sorted(values)
        n = len(sorted_vals)
        median = sorted_vals[n // 2] if n % 2 == 1 else (sorted_vals[n // 2 - 1] + sorted_vals[n // 2]) / 2

        deviations = sorted(abs(v - median) for v in values)
        n2 = len(deviations)
        mad = deviations[n2 // 2] if n2 % 2 == 1 else (deviations[n2 // 2 - 1] + deviations[n2 // 2]) / 2
        return mad


@registry.register
class SkewnessFunction(SentinelaFunction):
    """Retorna a assimetria (skewness) dos valores de um item no período."""

    name = "skewness"
    description = "Retorna a assimetria (skewness) dos valores de um item no período."
    category = "estatística"
    params = ["item_id", "period"]
    return_type = float

    def evaluate(self, item_id: str, period: Any = None) -> float:
        self._require_min_args((item_id,), 1, self.name)
        values = _get_values(item_id, period, self)
        if len(values) < 3:
            raise FunctionError(
                f"Dados insuficientes para 'skewness' do item '{item_id}' (mínimo 3 pontos)",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )

        n = len(values)
        mean = sum(values) / n
        variance = sum((v - mean) ** 2 for v in values) / n
        if variance == 0:
            return 0.0

        stddev = math.sqrt(variance)
        m3 = sum((v - mean) ** 3 for v in values) / n
        return m3 / (stddev ** 3)


@registry.register
class StdDevPopFunction(SentinelaFunction):
    """Retorna o desvio padrão populacional dos valores de um item no período."""

    name = "stddevpop"
    description = "Retorna o desvio padrão populacional dos valores de um item no período."
    category = "estatística"
    params = ["item_id", "period"]
    return_type = float

    def evaluate(self, item_id: str, period: Any = None) -> float:
        self._require_min_args((item_id,), 1, self.name)
        values = _get_values(item_id, period, self)
        if not values:
            raise FunctionError(
                f"Nenhum dado numérico disponível para o item '{item_id}'",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )

        n = len(values)
        mean = sum(values) / n
        variance = sum((v - mean) ** 2 for v in values) / n
        return math.sqrt(variance)


@registry.register
class StdDevSampFunction(SentinelaFunction):
    """Retorna o desvio padrão amostral dos valores de um item no período."""

    name = "stddevsamp"
    description = "Retorna o desvio padrão amostral dos valores de um item no período."
    category = "estatística"
    params = ["item_id", "period"]
    return_type = float

    def evaluate(self, item_id: str, period: Any = None) -> float:
        self._require_min_args((item_id,), 1, self.name)
        values = _get_values(item_id, period, self)
        if len(values) < 2:
            raise FunctionError(
                f"Dados insuficientes para 'stddevsamp' do item '{item_id}' (mínimo 2 pontos)",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )

        n = len(values)
        mean = sum(values) / n
        variance = sum((v - mean) ** 2 for v in values) / (n - 1)
        return math.sqrt(variance)


@registry.register
class VarPopFunction(SentinelaFunction):
    """Retorna a variância populacional dos valores de um item no período."""

    name = "varpop"
    description = "Retorna a variância populacional dos valores de um item no período."
    category = "estatística"
    params = ["item_id", "period"]
    return_type = float

    def evaluate(self, item_id: str, period: Any = None) -> float:
        self._require_min_args((item_id,), 1, self.name)
        values = _get_values(item_id, period, self)
        if not values:
            raise FunctionError(
                f"Nenhum dado numérico disponível para o item '{item_id}'",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )

        n = len(values)
        mean = sum(values) / n
        return sum((v - mean) ** 2 for v in values) / n


@registry.register
class VarSampFunction(SentinelaFunction):
    """Retorna a variância amostral dos valores de um item no período."""

    name = "varsamp"
    description = "Retorna a variância amostral dos valores de um item no período."
    category = "estatística"
    params = ["item_id", "period"]
    return_type = float

    def evaluate(self, item_id: str, period: Any = None) -> float:
        self._require_min_args((item_id,), 1, self.name)
        values = _get_values(item_id, period, self)
        if len(values) < 2:
            raise FunctionError(
                f"Dados insuficientes para 'varsamp' do item '{item_id}' (mínimo 2 pontos)",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )

        n = len(values)
        mean = sum(values) / n
        return sum((v - mean) ** 2 for v in values) / (n - 1)


@registry.register
class SumOfSquaresFunction(SentinelaFunction):
    """Retorna a soma dos quadrados dos valores de um item no período."""

    name = "sumofsquares"
    description = "Retorna a soma dos quadrados dos valores de um item no período."
    category = "estatística"
    params = ["item_id", "period"]
    return_type = float

    def evaluate(self, item_id: str, period: Any = None) -> float:
        self._require_min_args((item_id,), 1, self.name)
        values = _get_values(item_id, period, self)
        if not values:
            raise FunctionError(
                f"Nenhum dado numérico disponível para o item '{item_id}'",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )
        return sum(v ** 2 for v in values)


@registry.register
class HistogramQuantileFunction(SentinelaFunction):
    """Retorna o quantil estimado a partir de um histograma de buckets.

    Args:
        buckets: Lista de limites de buckets (ex: [10, 20, 30, 40]).
        counts: Lista de contagens acumuladas por bucket.
        quantile: Quantil desejado (0.0 a 1.0).
    """

    name = "histogram_quantile"
    description = "Retorna o quantil estimado a partir de um histograma de buckets."
    category = "estatística"
    params = ["buckets", "counts", "quantile"]
    return_type = float

    def evaluate(self, buckets: Any, counts: Any, quantile: Any = 0.95) -> float:
        self._require_min_args((buckets, counts), 2, self.name)

        try:
            bucket_list = [float(b) for b in buckets]
            count_list = [float(c) for c in counts]
        except (TypeError, ValueError):
            raise FunctionError(
                "buckets e counts devem ser listas de números",
                FunctionErrorType.PARAMETER,
                self.name,
            )

        if len(bucket_list) != len(count_list) or not bucket_list:
            raise FunctionError(
                "buckets e counts devem ter o mesmo tamanho e não podem ser vazios",
                FunctionErrorType.PARAMETER,
                self.name,
            )

        try:
            q = float(quantile)
        except (TypeError, ValueError):
            q = 0.95

        if not 0 <= q <= 1:
            raise FunctionError(
                f"quantile deve estar entre 0 e 1, recebido: {q}",
                FunctionErrorType.PARAMETER,
                self.name,
            )

        total = count_list[-1]
        if total <= 0:
            return 0.0

        target = q * total
        for i, count in enumerate(count_list):
            if count >= target:
                if i == 0:
                    return bucket_list[0] / 2
                prev_count = count_list[i - 1]
                prev_bucket = bucket_list[i - 1]
                bucket = bucket_list[i]
                if count == prev_count:
                    return bucket
                fraction = (target - prev_count) / (count - prev_count)
                return prev_bucket + fraction * (bucket - prev_bucket)

        return bucket_list[-1]


@registry.register
class BucketPercentileFunction(SentinelaFunction):
    """Retorna o percentual de valores que caem em cada bucket de um histograma."""

    name = "bucket_percentile"
    description = "Retorna o percentual de valores que caem em cada bucket de um histograma."
    category = "estatística"
    params = ["item_id", "buckets", "period"]
    return_type = Dict[str, float]

    def evaluate(self, item_id: str, buckets: Any, period: Any = None) -> Dict[str, float]:
        self._require_min_args((item_id, buckets), 2, self.name)
        values = _get_values(item_id, period, self)
        if not values:
            raise FunctionError(
                f"Nenhum dado numérico disponível para o item '{item_id}'",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )

        try:
            bucket_list = [float(b) for b in buckets]
        except (TypeError, ValueError):
            raise FunctionError(
                "buckets deve ser uma lista de números",
                FunctionErrorType.PARAMETER,
                self.name,
            )

        if not bucket_list:
            raise FunctionError(
                "buckets não pode ser vazio",
                FunctionErrorType.PARAMETER,
                self.name,
            )

        bucket_list.sort()
        n = len(values)
        result: Dict[str, float] = {}

        prev_bound = float("-inf")
        for i, bound in enumerate(bucket_list):
            count = sum(1 for v in values if prev_bound <= v < bound)
            result[f"<{bound:g}"] = (count / n) * 100.0
            prev_bound = bound

        # Último bucket: valores >= último limite
        count = sum(1 for v in values if v >= bucket_list[-1])
        result[f">={bucket_list[-1]:g}"] = (count / n) * 100.0

        return result