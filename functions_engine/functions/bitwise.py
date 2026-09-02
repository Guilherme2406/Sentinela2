# functions_engine/functions/bitwise.py
"""Funções bitwise do Sentinela XDR.

Implementa: bitand, bitlshift, bitnot, bitor, bitrshift, bitxor.
"""
from __future__ import annotations

from typing import Any

from functions_engine.core import (
    FunctionError,
    FunctionErrorType,
    SentinelaFunction,
)
from functions_engine.registry import registry


def _to_int(value: Any, func_name: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        raise FunctionError(
            f"Valor não inteiro: {value!r}",
            FunctionErrorType.INVALID_VALUE,
            func_name,
        )


@registry.register
class BitAndFunction(SentinelaFunction):
    """Retorna o resultado da operação AND bit a bit entre dois inteiros."""

    name = "bitand"
    description = "Retorna o resultado da operação AND bit a bit entre dois inteiros."
    category = "bitwise"
    params = ["a", "b"]
    return_type = int

    def evaluate(self, a: Any, b: Any) -> int:
        self._require_min_args((a, b), 2, self.name)
        return _to_int(a, self.name) & _to_int(b, self.name)


@registry.register
class BitLShiftFunction(SentinelaFunction):
    """Retorna o resultado do deslocamento à esquerda de um inteiro."""

    name = "bitlshift"
    description = "Retorna o resultado do deslocamento à esquerda de um inteiro."
    category = "bitwise"
    params = ["value", "bits"]
    return_type = int

    def evaluate(self, value: Any, bits: Any) -> int:
        self._require_min_args((value, bits), 2, self.name)
        return _to_int(value, self.name) << _to_int(bits, self.name)


@registry.register
class BitNotFunction(SentinelaFunction):
    """Retorna o complemento bit a bit (NOT) de um inteiro."""

    name = "bitnot"
    description = "Retorna o complemento bit a bit (NOT) de um inteiro."
    category = "bitwise"
    params = ["value"]
    return_type = int

    def evaluate(self, value: Any) -> int:
        self._require_min_args((value,), 1, self.name)
        return ~_to_int(value, self.name)


@registry.register
class BitOrFunction(SentinelaFunction):
    """Retorna o resultado da operação OR bit a bit entre dois inteiros."""

    name = "bitor"
    description = "Retorna o resultado da operação OR bit a bit entre dois inteiros."
    category = "bitwise"
    params = ["a", "b"]
    return_type = int

    def evaluate(self, a: Any, b: Any) -> int:
        self._require_min_args((a, b), 2, self.name)
        return _to_int(a, self.name) | _to_int(b, self.name)


@registry.register
class BitRShiftFunction(SentinelaFunction):
    """Retorna o resultado do deslocamento à direita de um inteiro."""

    name = "bitrshift"
    description = "Retorna o resultado do deslocamento à direita de um inteiro."
    category = "bitwise"
    params = ["value", "bits"]
    return_type = int

    def evaluate(self, value: Any, bits: Any) -> int:
        self._require_min_args((value, bits), 2, self.name)
        return _to_int(value, self.name) >> _to_int(bits, self.name)


@registry.register
class BitXorFunction(SentinelaFunction):
    """Retorna o resultado da operação XOR bit a bit entre dois inteiros."""

    name = "bitxor"
    description = "Retorna o resultado da operação XOR bit a bit entre dois inteiros."
    category = "bitwise"
    params = ["a", "b"]
    return_type = int

    def evaluate(self, a: Any, b: Any) -> int:
        self._require_min_args((a, b), 2, self.name)
        return _to_int(a, self.name) ^ _to_int(b, self.name)
