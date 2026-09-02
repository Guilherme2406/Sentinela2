# functions_engine/functions/math_functions.py
"""Funções matemáticas do Sentinela XDR.

Implementa 29 funções matemáticas mapeadas para math.* do Python:
abs, acos, asin, atan, atan2, ceil, cos, cosh, exp, floor, log, log10,
max, min, mod, pow, round, sign, sin, sinh, sqrt, tan, tanh, trunc,
pi, e, inf, nan, random.
"""
from __future__ import annotations

import math
import random
from typing import Any

from functions_engine.core import (
    FunctionError,
    FunctionErrorType,
    SentinelaFunction,
)
from functions_engine.registry import registry


# ---------------------------------------------------------------------------
# Funções trigonométricas
# ---------------------------------------------------------------------------
@registry.register
class AbsFunction(SentinelaFunction):
    """Retorna o valor absoluto de um número."""

    name = "abs"
    description = "Retorna o valor absoluto de um número."
    category = "matemática"
    params = ["value"]
    return_type = float

    def evaluate(self, value: Any) -> float:
        self._require_min_args((value,), 1, self.name)
        return abs(self._to_float(value))


@registry.register
class AcosFunction(SentinelaFunction):
    """Retorna o arco cosseno de um número (em radianos)."""

    name = "acos"
    description = "Retorna o arco cosseno de um número (em radianos)."
    category = "matemática"
    params = ["value"]
    return_type = float

    def evaluate(self, value: Any) -> float:
        self._require_min_args((value,), 1, self.name)
        v = self._to_float(value)
        if not -1 <= v <= 1:
            raise FunctionError(
                f"acos: domínio deve estar entre -1 e 1, recebido: {v}",
                FunctionErrorType.INVALID_VALUE,
                self.name,
            )
        return math.acos(v)


@registry.register
class AsinFunction(SentinelaFunction):
    """Retorna o arco seno de um número (em radianos)."""

    name = "asin"
    description = "Retorna o arco seno de um número (em radianos)."
    category = "matemática"
    params = ["value"]
    return_type = float

    def evaluate(self, value: Any) -> float:
        self._require_min_args((value,), 1, self.name)
        v = self._to_float(value)
        if not -1 <= v <= 1:
            raise FunctionError(
                f"asin: domínio deve estar entre -1 e 1, recebido: {v}",
                FunctionErrorType.INVALID_VALUE,
                self.name,
            )
        return math.asin(v)


@registry.register
class AtanFunction(SentinelaFunction):
    """Retorna o arco tangente de um número (em radianos)."""

    name = "atan"
    description = "Retorna o arco tangente de um número (em radianos)."
    category = "matemática"
    params = ["value"]
    return_type = float

    def evaluate(self, value: Any) -> float:
        self._require_min_args((value,), 1, self.name)
        return math.atan(self._to_float(value))


@registry.register
class Atan2Function(SentinelaFunction):
    """Retorna o arco tangente de y/x (em radianos)."""

    name = "atan2"
    description = "Retorna o arco tangente de y/x (em radianos)."
    category = "matemática"
    params = ["y", "x"]
    return_type = float

    def evaluate(self, y: Any, x: Any) -> float:
        self._require_min_args((y, x), 2, self.name)
        return math.atan2(self._to_float(y), self._to_float(x))


@registry.register
class CosFunction(SentinelaFunction):
    """Retorna o cosseno de um ângulo (em radianos)."""

    name = "cos"
    description = "Retorna o cosseno de um ângulo (em radianos)."
    category = "matemática"
    params = ["value"]
    return_type = float

    def evaluate(self, value: Any) -> float:
        self._require_min_args((value,), 1, self.name)
        return math.cos(self._to_float(value))


@registry.register
class CoshFunction(SentinelaFunction):
    """Retorna o cosseno hiperbólico de um número."""

    name = "cosh"
    description = "Retorna o cosseno hiperbólico de um número."
    category = "matemática"
    params = ["value"]
    return_type = float

    def evaluate(self, value: Any) -> float:
        self._require_min_args((value,), 1, self.name)
        return math.cosh(self._to_float(value))


@registry.register
class SinFunction(SentinelaFunction):
    """Retorna o seno de um ângulo (em radianos)."""

    name = "sin"
    description = "Retorna o seno de um ângulo (em radianos)."
    category = "matemática"
    params = ["value"]
    return_type = float

    def evaluate(self, value: Any) -> float:
        self._require_min_args((value,), 1, self.name)
        return math.sin(self._to_float(value))


@registry.register
class SinhFunction(SentinelaFunction):
    """Retorna o seno hiperbólico de um número."""

    name = "sinh"
    description = "Retorna o seno hiperbólico de um número."
    category = "matemática"
    params = ["value"]
    return_type = float

    def evaluate(self, value: Any) -> float:
        self._require_min_args((value,), 1, self.name)
        return math.sinh(self._to_float(value))


@registry.register
class TanFunction(SentinelaFunction):
    """Retorna a tangente de um ângulo (em radianos)."""

    name = "tan"
    description = "Retorna a tangente de um ângulo (em radianos)."
    category = "matemática"
    params = ["value"]
    return_type = float

    def evaluate(self, value: Any) -> float:
        self._require_min_args((value,), 1, self.name)
        return math.tan(self._to_float(value))


@registry.register
class TanhFunction(SentinelaFunction):
    """Retorna a tangente hiperbólica de um número."""

    name = "tanh"
    description = "Retorna a tangente hiperbólica de um número."
    category = "matemática"
    params = ["value"]
    return_type = float

    def evaluate(self, value: Any) -> float:
        self._require_min_args((value,), 1, self.name)
        return math.tanh(self._to_float(value))


# ---------------------------------------------------------------------------
# Funções exponenciais e logarítmicas
# ---------------------------------------------------------------------------
@registry.register
class ExpFunction(SentinelaFunction):
    """Retorna e elevado à potência do valor."""

    name = "exp"
    description = "Retorna e elevado à potência do valor."
    category = "matemática"
    params = ["value"]
    return_type = float

    def evaluate(self, value: Any) -> float:
        self._require_min_args((value,), 1, self.name)
        return math.exp(self._to_float(value))


@registry.register
class LogFunction(SentinelaFunction):
    """Retorna o logaritmo natural (base e) de um número."""

    name = "log"
    description = "Retorna o logaritmo natural (base e) de um número."
    category = "matemática"
    params = ["value"]
    return_type = float

    def evaluate(self, value: Any) -> float:
        self._require_min_args((value,), 1, self.name)
        v = self._to_float(value)
        if v <= 0:
            raise FunctionError(
                f"log: domínio deve ser > 0, recebido: {v}",
                FunctionErrorType.INVALID_VALUE,
                self.name,
            )
        return math.log(v)


@registry.register
class Log10Function(SentinelaFunction):
    """Retorna o logaritmo na base 10 de um número."""

    name = "log10"
    description = "Retorna o logaritmo na base 10 de um número."
    category = "matemática"
    params = ["value"]
    return_type = float

    def evaluate(self, value: Any) -> float:
        self._require_min_args((value,), 1, self.name)
        v = self._to_float(value)
        if v <= 0:
            raise FunctionError(
                f"log10: domínio deve ser > 0, recebido: {v}",
                FunctionErrorType.INVALID_VALUE,
                self.name,
            )
        return math.log10(v)


@registry.register
class PowFunction(SentinelaFunction):
    """Retorna a base elevada ao expoente."""

    name = "pow"
    description = "Retorna a base elevada ao expoente."
    category = "matemática"
    params = ["base", "exponent"]
    return_type = float

    def evaluate(self, base: Any, exponent: Any) -> float:
        self._require_min_args((base, exponent), 2, self.name)
        return math.pow(self._to_float(base), self._to_float(exponent))


@registry.register
class SqrtFunction(SentinelaFunction):
    """Retorna a raiz quadrada de um número."""

    name = "sqrt"
    description = "Retorna a raiz quadrada de um número."
    category = "matemática"
    params = ["value"]
    return_type = float

    def evaluate(self, value: Any) -> float:
        self._require_min_args((value,), 1, self.name)
        v = self._to_float(value)
        if v < 0:
            raise FunctionError(
                f"sqrt: domínio deve ser >= 0, recebido: {v}",
                FunctionErrorType.INVALID_VALUE,
                self.name,
            )
        return math.sqrt(v)


# ---------------------------------------------------------------------------
# Funções de arredondamento e inteiros
# ---------------------------------------------------------------------------
@registry.register
class CeilFunction(SentinelaFunction):
    """Retorna o menor inteiro maior ou igual ao valor."""

    name = "ceil"
    description = "Retorna o menor inteiro maior ou igual ao valor."
    category = "matemática"
    params = ["value"]
    return_type = int

    def evaluate(self, value: Any) -> int:
        self._require_min_args((value,), 1, self.name)
        return math.ceil(self._to_float(value))


@registry.register
class FloorFunction(SentinelaFunction):
    """Retorna o maior inteiro menor ou igual ao valor."""

    name = "floor"
    description = "Retorna o maior inteiro menor ou igual ao valor."
    category = "matemática"
    params = ["value"]
    return_type = int

    def evaluate(self, value: Any) -> int:
        self._require_min_args((value,), 1, self.name)
        return math.floor(self._to_float(value))


@registry.register
class RoundFunction(SentinelaFunction):
    """Retorna o valor arredondado para o número de casas decimais especificado."""

    name = "round"
    description = "Retorna o valor arredondado para o número de casas decimais especificado."
    category = "matemática"
    params = ["value", "ndigits"]
    return_type = float

    def evaluate(self, value: Any, ndigits: Any = 0) -> float:
        self._require_min_args((value,), 1, self.name)
        try:
            n = int(ndigits)
        except (TypeError, ValueError):
            n = 0
        return round(self._to_float(value), n)


@registry.register
class TruncFunction(SentinelaFunction):
    """Retorna a parte inteira de um número (trunca a parte decimal)."""

    name = "trunc"
    description = "Retorna a parte inteira de um número (trunca a parte decimal)."
    category = "matemática"
    params = ["value"]
    return_type = int

    def evaluate(self, value: Any) -> int:
        self._require_min_args((value,), 1, self.name)
        return math.trunc(self._to_float(value))


@registry.register
class ModFunction(SentinelaFunction):
    """Retorna o resto da divisão de a por b."""

    name = "mod"
    description = "Retorna o resto da divisão de a por b."
    category = "matemática"
    params = ["a", "b"]
    return_type = float

    def evaluate(self, a: Any, b: Any) -> float:
        self._require_min_args((a, b), 2, self.name)
        divisor = self._to_float(b)
        if divisor == 0:
            raise FunctionError(
                "mod: divisão por zero",
                FunctionErrorType.DIVISION_BY_ZERO,
                self.name,
            )
        return math.fmod(self._to_float(a), divisor)


# ---------------------------------------------------------------------------
# Funções de comparação e sinal
# ---------------------------------------------------------------------------
@registry.register
class SignFunction(SentinelaFunction):
    """Retorna o sinal de um número: -1, 0 ou 1."""

    name = "sign"
    description = "Retorna o sinal de um número: -1, 0 ou 1."
    category = "matemática"
    params = ["value"]
    return_type = int

    def evaluate(self, value: Any) -> int:
        self._require_min_args((value,), 1, self.name)
        v = self._to_float(value)
        if v > 0:
            return 1
        if v < 0:
            return -1
        return 0


# ---------------------------------------------------------------------------
# Constantes e utilitários
# ---------------------------------------------------------------------------
@registry.register
class PiFunction(SentinelaFunction):
    """Retorna a constante matemática π (pi)."""

    name = "pi"
    description = "Retorna a constante matemática π (pi)."
    category = "matemática"
    params = []
    return_type = float

    def evaluate(self, *args: Any) -> float:
        return math.pi


@registry.register
class EFunction(SentinelaFunction):
    """Retorna a constante matemática e (número de Euler)."""

    name = "e"
    description = "Retorna a constante matemática e (número de Euler)."
    category = "matemática"
    params = []
    return_type = float

    def evaluate(self, *args: Any) -> float:
        return math.e


@registry.register
class InfFunction(SentinelaFunction):
    """Retorna o valor infinito positivo."""

    name = "inf"
    description = "Retorna o valor infinito positivo."
    category = "matemática"
    params = []
    return_type = float

    def evaluate(self, *args: Any) -> float:
        return math.inf


@registry.register
class NanFunction(SentinelaFunction):
    """Retorna o valor NaN (Not a Number)."""

    name = "nan"
    description = "Retorna o valor NaN (Not a Number)."
    category = "matemática"
    params = []
    return_type = float

    def evaluate(self, *args: Any) -> float:
        return math.nan


@registry.register
class RandomFunction(SentinelaFunction):
    """Retorna um número aleatório entre 0 e 1 (ou entre min e max)."""

    name = "random"
    description = "Retorna um número aleatório entre 0 e 1 (ou entre min e max)."
    category = "matemática"
    params = ["min", "max"]
    return_type = float

    def evaluate(self, min_val: Any = None, max_val: Any = None) -> float:
        if min_val is None and max_val is None:
            return random.random()
        if min_val is None:
            return random.random() * self._to_float(max_val)
        if max_val is None:
            return random.random() * self._to_float(min_val)
        lo = self._to_float(min_val)
        hi = self._to_float(max_val)
        if lo > hi:
            lo, hi = hi, lo
        return lo + random.random() * (hi - lo)