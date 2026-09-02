# functions_engine/core.py
"""Núcleo do Functions Engine: tipos, interfaces e contratos centrais.

Define o contrato padrão que toda função do Sentinela XDR deve implementar,
bem como as estruturas de dados compartilhadas (SecurityItem, FunctionContext).
"""
from __future__ import annotations

import math
import time
import enum
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Generic, List, Optional, Tuple, Type, TypeVar, Union

# ---------------------------------------------------------------------------
# Tipos utilitários
# ---------------------------------------------------------------------------
Number = Union[int, float]
Numeric = Union[int, float, bool]

T = TypeVar("T")


class FunctionErrorType(enum.Enum):
    """Tipos de erro suportados pelo motor de funções."""

    NOT_SUPPORTED = "not_supported"
    PARAMETER = "parameter"
    RESOURCE = "resource"
    DIVISION_BY_ZERO = "division_by_zero"
    INVALID_VALUE = "invalid_value"
    TIMEOUT = "timeout"
    NOT_FOUND = "not_found"
    INTERNAL = "internal"


class FunctionError(Exception):
    """Exceção padrão lançada por funções do motor."""

    def __init__(
        self,
        message: str,
        error_type: FunctionErrorType = FunctionErrorType.INTERNAL,
        function_name: str = "",
    ):
        super().__init__(message)
        self.message = message
        self.error_type = error_type
        self.function_name = function_name

    def to_dict(self) -> Dict[str, Any]:
        return {
            "error": self.message,
            "type": self.error_type.value,
            "function": self.function_name,
        }

    def __repr__(self) -> str:
        return f"FunctionError({self.error_type.value}: {self.message})"


class ParamType(enum.Enum):
    """Tipos de parâmetros suportados nas assinaturas de funções."""

    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    ARRAY = "array"
    OBJECT = "object"
    ANY = "any"


# ---------------------------------------------------------------------------
# Estruturas de dados centrais
# ---------------------------------------------------------------------------
@dataclass
class SecurityItem:
    """Representa um item de segurança monitorado (métrica).

    Attributes:
        item_id: Identificador único do item (ex: "system.cpu[0,util]")
        name: Nome amigável do item.
        value: Valor atual do item.
        timestamp: Timestamp Unix (segundos) da coleta.
        tags: Metadados adicionais do item.
    """

    item_id: str
    name: str = ""
    value: Any = None
    timestamp: float = field(default_factory=time.time)
    tags: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        if not self.name:
            self.name = self.item_id

    def to_dict(self) -> Dict[str, Any]:
        return {
            "item_id": self.item_id,
            "name": self.name,
            "value": self.value,
            "timestamp": self.timestamp,
            "tags": self.tags,
        }


@dataclass
class FunctionResult:
    """Resultado tipado de uma avaliação de função."""

    value: Any
    function_name: str = ""
    duration_ms: float = 0.0
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "value": self.value,
            "function": self.function_name,
            "duration_ms": round(self.duration_ms, 4),
            "meta": self.meta,
        }


class FunctionContext:
    """Contexto de execução compartilhado entre funções.

    Fornece acesso ao armazenamento de séries temporais, clock e configuração.
    """

    def __init__(
        self,
        storage: Optional["TimeSeriesStorage"] = None,
        clock: Optional[Callable[[], float]] = None,
        timezone_offset: int = 0,
        **kwargs: Any,
    ):
        self.storage = storage
        self._clock = clock or time.time
        self.timezone_offset = timezone_offset
        self.extra: Dict[str, Any] = dict(kwargs)
        self._cache: Dict[str, Any] = {}

    @property
    def now(self) -> float:
        """Timestamp atual em segundos (Unix)."""
        return self._clock()

    def cache_get(self, key: str, default: T = None) -> T:
        return self._cache.get(key, default)

    def cache_set(self, key: str, value: Any) -> None:
        self._cache[key] = value

    def get_history(
        self,
        item_id: str,
        start_ts: Optional[float] = None,
        end_ts: Optional[float] = None,
        limit: int = 1000,
    ) -> List["SecurityItem"]:
        """Recupera o histórico de um item do armazenamento subjacente."""
        if self.storage is None:
            return []
        return self.storage.query(item_id, start_ts, end_ts, limit)


# ---------------------------------------------------------------------------
# Armazenamento de séries temporais (interface)
# ---------------------------------------------------------------------------
class TimeSeriesStorage(ABC):
    """Interface abstrata para armazenamento de séries temporais."""

    @abstractmethod
    def append(self, item: SecurityItem) -> None:
        """Adiciona um novo ponto de dados."""

    @abstractmethod
    def query(
        self,
        item_id: str,
        start_ts: Optional[float] = None,
        end_ts: Optional[float] = None,
        limit: int = 1000,
    ) -> List[SecurityItem]:
        """Consulta pontos de dados de um item no intervalo especificado."""

    @abstractmethod
    def last(self, item_id: str) -> Optional[SecurityItem]:
        """Retorna o último ponto de dados de um item."""

    @abstractmethod
    def count(self, item_id: str) -> int:
        """Retorna a quantidade de pontos armazenados para um item."""

    @abstractmethod
    def clear(self, item_id: Optional[str] = None) -> None:
        """Limpa os dados de um item (ou todos se item_id for None)."""


class RingBufferStorage(TimeSeriesStorage):
    """Armazenamento em memória com buffer circular (anel) por item.

    Fornece acesso O(1) aos valores anteriores e é thread-safe.
    """

    def __init__(self, max_size: int = 10000):
        self.max_size = max(1, max_size)
        self._data: Dict[str, List[SecurityItem]] = {}
        self._lock = threading.RLock()

    def append(self, item: SecurityItem) -> None:
        with self._lock:
            bucket = self._data.setdefault(item.item_id, [])
            bucket.append(item)
            if len(bucket) > self.max_size:
                del bucket[: len(bucket) - self.max_size]

    def query(
        self,
        item_id: str,
        start_ts: Optional[float] = None,
        end_ts: Optional[float] = None,
        limit: int = 1000,
    ) -> List[SecurityItem]:
        with self._lock:
            bucket = self._data.get(item_id, [])
            if not bucket:
                return []

            if start_ts is None and end_ts is None:
                result = list(bucket)
            else:
                result = [
                    it
                    for it in bucket
                    if (start_ts is None or it.timestamp >= start_ts)
                    and (end_ts is None or it.timestamp <= end_ts)
                ]

            if limit and limit > 0 and len(result) > limit:
                result = result[-limit:]
            return result

    def last(self, item_id: str) -> Optional[SecurityItem]:
        with self._lock:
            bucket = self._data.get(item_id)
            return bucket[-1] if bucket else None

    def count(self, item_id: str) -> int:
        with self._lock:
            return len(self._data.get(item_id, []))

    def clear(self, item_id: Optional[str] = None) -> None:
        with self._lock:
            if item_id is None:
                self._data.clear()
            else:
                self._data.pop(item_id, None)

    def __len__(self) -> int:
        """Total de pontos de dados armazenados em todos os itens."""
        with self._lock:
            return sum(len(bucket) for bucket in self._data.values())

    def item_ids(self) -> List[str]:
        """Identificadores únicos de todos os itens com dados armazenados."""
        with self._lock:
            return sorted(self._data.keys())

    def snapshot(self, limit: Optional[int] = None) -> List[SecurityItem]:
        """Retorna uma cópia plana de todos os pontos (opcionalmente limitada)."""
        with self._lock:
            out: List[SecurityItem] = []
            for bucket in self._data.values():
                out.extend(bucket)
            if limit and limit > 0 and len(out) > limit:
                out = out[-limit:]
            return out


# ---------------------------------------------------------------------------
# Classe base das funções
# ---------------------------------------------------------------------------
class SentinelaFunction(ABC):
    """Classe base para todas as funções do Sentinela XDR.

    Cada função deve herdar desta classe e implementar o método `evaluate`.
    O registro automático é feito via `FunctionRegistry.register`.
    """

    #: Nome canônico da função (ex: "last", "avg", "forecast")
    name: str = ""

    #: Descrição curta da função
    description: str = ""

    #: Categoria da função (histórico, matemática, string, etc.)
    category: str = "geral"

    #: Assinatura de parâmetros (nomes)
    params: List[str] = []

    #: Tipo de retorno
    return_type: type = object

    #: Versão da função
    version: str = "1.0.0"

    def __init__(self, context: Optional[FunctionContext] = None):
        self.context = context or FunctionContext()

    @abstractmethod
    def evaluate(self, *args: Any, **kwargs: Any) -> Any:
        """Avalia a função com os argumentos fornecidos."""

    # -- Helpers utilitários -------------------------------------------------
    def _require_context(self) -> FunctionContext:
        if self.context is None:
            raise FunctionError(
                "Contexto não disponível para esta função.",
                FunctionErrorType.RESOURCE,
                self.name,
            )
        return self.context

    def _get_history(
        self,
        item_id: str,
        start_ts: Optional[float] = None,
        end_ts: Optional[float] = None,
        limit: int = 1000,
    ) -> List[SecurityItem]:
        ctx = self._require_context()
        return ctx.get_history(item_id, start_ts, end_ts, limit)

    def _values(
        self,
        item_id: str,
        start_ts: Optional[float] = None,
        end_ts: Optional[float] = None,
        limit: int = 1000,
    ) -> List[Any]:
        """Retorna apenas os valores (em ordem cronológica) de um item."""
        return [
            it.value
            for it in self._get_history(item_id, start_ts, end_ts, limit)
        ]

    def _numeric_values(
        self,
        item_id: str,
        start_ts: Optional[float] = None,
        end_ts: Optional[float] = None,
        limit: int = 1000,
    ) -> List[float]:
        """Retorna apenas valores numéricos (filtrando não-numéricos)."""
        result: List[float] = []
        for v in self._values(item_id, start_ts, end_ts, limit):
            try:
                result.append(float(v))
            except (TypeError, ValueError):
                continue
        return result

    @staticmethod
    def _to_float(value: Any) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            raise FunctionError(
                f"Valor não numérico: {value!r}",
                FunctionErrorType.INVALID_VALUE,
            )

    @staticmethod
    def _require_min_args(args: tuple, n: int, func_name: str = "") -> None:
        if len(args) < n:
            raise FunctionError(
                f"Esperado pelo menos {n} argumento(s), recebido {len(args)}",
                FunctionErrorType.PARAMETER,
                func_name or None,
            )

    @staticmethod
    def _require_max_args(args: tuple, n: int, func_name: str = "") -> None:
        if len(args) > n:
            raise FunctionError(
                f"Esperado no máximo {n} argumento(s), recebido {len(args)}",
                FunctionErrorType.PARAMETER,
                func_name or None,
            )

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self.evaluate(*args, **kwargs)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r} category={self.category!r}>"