# functions_engine/functions/foreach.py
"""Funções foreach do Sentinela XDR.

Implementa: avg_foreach, count_foreach, last_foreach, sum_foreach.
Funcionam com agregação wildcard, ex: avg_foreach("system.cpu[core.*]").
"""
from __future__ import annotations

import fnmatch
import re
from typing import Any, Dict, List, Optional

from functions_engine.core import (
    FunctionError,
    FunctionErrorType,
    SecurityItem,
    SentinelaFunction,
)
from functions_engine.registry import registry


def _expand_wildcard(pattern: str, storage) -> List[str]:
    """Expande um padrão wildcard para uma lista de item_ids correspondentes."""
    if storage is None:
        return []

    # Converte o padrão wildcard para regex manualmente
    # (fnmatch.translate trata colchetes como classes de caracteres, o que não queremos)
    regex_parts = []
    for ch in pattern:
        if ch == "*":
            regex_parts.append(".*")
        elif ch == "?":
            regex_parts.append(".")
        elif ch in ".^$+{}()|\\[]":
            regex_parts.append("\\" + ch)
        else:
            regex_parts.append(ch)
    regex_pattern = "^" + "".join(regex_parts) + "$"

    # Obtém todos os item_ids conhecidos do storage
    item_ids = set()
    if hasattr(storage, "_data"):
        item_ids = set(storage._data.keys())
    elif hasattr(storage, "item_ids"):
        item_ids = set(storage.item_ids())

    matched = [iid for iid in item_ids if re.match(regex_pattern, iid)]
    return sorted(matched)


def _get_matching_items(pattern: str, func: SentinelaFunction) -> List[str]:
    """Obtém os item_ids que correspondem ao padrão wildcard."""
    storage = func.context.storage
    if storage is None:
        raise FunctionError(
            "Armazenamento não disponível para funções foreach",
            FunctionErrorType.RESOURCE,
            func.name,
        )
    return _expand_wildcard(str(pattern), storage)


@registry.register
class AvgForeachFunction(SentinelaFunction):
    """Retorna a média dos últimos valores de todos os itens que correspondem ao padrão."""

    name = "avg_foreach"
    description = "Retorna a média dos últimos valores de todos os itens que correspondem ao padrão."
    category = "foreach"
    params = ["pattern"]
    return_type = float

    def evaluate(self, pattern: str) -> float:
        self._require_min_args((pattern,), 1, self.name)
        item_ids = _get_matching_items(pattern, self)
        if not item_ids:
            raise FunctionError(
                f"Nenhum item corresponde ao padrão '{pattern}'",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )

        values = []
        for iid in item_ids:
            last_item = self.context.storage.last(iid)
            if last_item is not None:
                try:
                    values.append(float(last_item.value))
                except (TypeError, ValueError):
                    continue

        if not values:
            raise FunctionError(
                f"Nenhum valor numérico encontrado para o padrão '{pattern}'",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )
        return sum(values) / len(values)


@registry.register
class CountForeachFunction(SentinelaFunction):
    """Retorna o número de itens que correspondem ao padrão wildcard."""

    name = "count_foreach"
    description = "Retorna o número de itens que correspondem ao padrão wildcard."
    category = "foreach"
    params = ["pattern"]
    return_type = int

    def evaluate(self, pattern: str) -> int:
        self._require_min_args((pattern,), 1, self.name)
        item_ids = _get_matching_items(pattern, self)
        return len(item_ids)


@registry.register
class LastForeachFunction(SentinelaFunction):
    """Retorna um dicionário com os últimos valores de todos os itens que correspondem ao padrão."""

    name = "last_foreach"
    description = "Retorna um dicionário com os últimos valores de todos os itens que correspondem ao padrão."
    category = "foreach"
    params = ["pattern"]
    return_type = Dict[str, Any]

    def evaluate(self, pattern: str) -> Dict[str, Any]:
        self._require_min_args((pattern,), 1, self.name)
        item_ids = _get_matching_items(pattern, self)
        if not item_ids:
            raise FunctionError(
                f"Nenhum item corresponde ao padrão '{pattern}'",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )

        result = {}
        for iid in item_ids:
            last_item = self.context.storage.last(iid)
            if last_item is not None:
                result[iid] = last_item.value
        return result


@registry.register
class SumForeachFunction(SentinelaFunction):
    """Retorna a soma dos últimos valores de todos os itens que correspondem ao padrão."""

    name = "sum_foreach"
    description = "Retorna a soma dos últimos valores de todos os itens que correspondem ao padrão."
    category = "foreach"
    params = ["pattern"]
    return_type = float

    def evaluate(self, pattern: str) -> float:
        self._require_min_args((pattern,), 1, self.name)
        item_ids = _get_matching_items(pattern, self)
        if not item_ids:
            raise FunctionError(
                f"Nenhum item corresponde ao padrão '{pattern}'",
                FunctionErrorType.NOT_FOUND,
                self.name,
            )

        total = 0.0
        for iid in item_ids:
            last_item = self.context.storage.last(iid)
            if last_item is not None:
                try:
                    total += float(last_item.value)
                except (TypeError, ValueError):
                    continue
        return total