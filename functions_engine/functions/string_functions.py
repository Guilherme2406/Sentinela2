# functions_engine/functions/string_functions.py
"""Funções de string do Sentinela XDR.

Implementa 15 funções de string estilo Zabbix:
concat, strfind, left, len, lower, mid, regex, replace, right, rtrim,
str, strftime, strstr, trim, upper, bitlength, bytelength.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from functions_engine.core import (
    FunctionError,
    FunctionErrorType,
    SentinelaFunction,
)
from functions_engine.registry import registry


@registry.register
class ConcatFunction(SentinelaFunction):
    """Concatena duas ou mais strings em uma única string (O(n))."""

    name = "concat"
    description = "Concatena duas ou mais strings em uma única string (O(n))."
    category = "string"
    params = ["values..."]
    return_type = str

    def evaluate(self, *args: Any) -> str:
        self._require_min_args(args, 1, self.name)
        return "".join(str(a) for a in args)


@registry.register
class StrFindFunction(SentinelaFunction):
    """Retorna a posição da primeira ocorrência de uma substring."""

    name = "strfind"
    description = "Retorna a posição da primeira ocorrência de uma substring."
    category = "string"
    params = ["value", "substring"]
    return_type = int

    def evaluate(self, value: Any, substring: Any) -> int:
        self._require_min_args((value, substring), 2, self.name)
        idx = str(value).find(str(substring))
        return idx if idx >= 0 else -1


@registry.register
class LeftFunction(SentinelaFunction):
    """Retorna os primeiros N caracteres de uma string."""

    name = "left"
    description = "Retorna os primeiros N caracteres de uma string."
    category = "string"
    params = ["value", "length"]
    return_type = str

    def evaluate(self, value: Any, length: Any) -> str:
        self._require_min_args((value, length), 2, self.name)
        try:
            n = int(length)
        except (TypeError, ValueError):
            raise FunctionError(
                f"left: comprimento inválido: {length!r}",
                FunctionErrorType.PARAMETER,
                self.name,
            )
        if n < 0:
            n = 0
        return str(value)[:n]


@registry.register
class LenFunction(SentinelaFunction):
    """Retorna o comprimento (número de caracteres) de uma string."""

    name = "len"
    description = "Retorna o comprimento (número de caracteres) de uma string."
    category = "string"
    params = ["value"]
    return_type = int

    def evaluate(self, value: Any) -> int:
        self._require_min_args((value,), 1, self.name)
        return len(str(value))


@registry.register
class LowerFunction(SentinelaFunction):
    """Converte uma string para minúsculas."""

    name = "lower"
    description = "Converte uma string para minúsculas."
    category = "string"
    params = ["value"]
    return_type = str

    def evaluate(self, value: Any) -> str:
        self._require_min_args((value,), 1, self.name)
        return str(value).lower()


@registry.register
class MidFunction(SentinelaFunction):
    """Retorna uma substring começando na posição especificada."""

    name = "mid"
    description = "Retorna uma substring começando na posição especificada."
    category = "string"
    params = ["value", "start", "length"]
    return_type = str

    def evaluate(self, value: Any, start: Any, length: Any = None) -> str:
        self._require_min_args((value, start), 2, self.name)
        try:
            s = int(start)
        except (TypeError, ValueError):
            raise FunctionError(
                f"mid: posição inicial inválida: {start!r}",
                FunctionErrorType.PARAMETER,
                self.name,
            )
        text = str(value)
        if length is None:
            return text[s:]
        try:
            n = int(length)
        except (TypeError, ValueError):
            raise FunctionError(
                f"mid: comprimento inválido: {length!r}",
                FunctionErrorType.PARAMETER,
                self.name,
            )
        return text[s:s + n]


@registry.register
class RegexFunction(SentinelaFunction):
    """Retorna a primeira correspondência de uma expressão regular."""

    name = "regex"
    description = "Retorna a primeira correspondência de uma expressão regular."
    category = "string"
    params = ["value", "pattern"]
    return_type = str

    def evaluate(self, value: Any, pattern: Any) -> str:
        self._require_min_args((value, pattern), 2, self.name)
        try:
            match = re.search(str(pattern), str(value))
        except re.error as exc:
            raise FunctionError(
                f"regex: padrão inválido: {exc}",
                FunctionErrorType.PARAMETER,
                self.name,
            )
        if match:
            return match.group(0)
        return ""


@registry.register
class ReplaceFunction(SentinelaFunction):
    """Substitui todas as ocorrências de uma substring por outra."""

    name = "replace"
    description = "Substitui todas as ocorrências de uma substring por outra."
    category = "string"
    params = ["value", "old", "new"]
    return_type = str

    def evaluate(self, value: Any, old: Any, new: Any) -> str:
        self._require_min_args((value, old, new), 3, self.name)
        text = str(value)
        old_str = str(old)
        new_str = str(new)
        if not old_str:
            return text
        return text.replace(old_str, new_str)


@registry.register
class RightFunction(SentinelaFunction):
    """Retorna os últimos N caracteres de uma string."""

    name = "right"
    description = "Retorna os últimos N caracteres de uma string."
    category = "string"
    params = ["value", "length"]
    return_type = str

    def evaluate(self, value: Any, length: Any) -> str:
        self._require_min_args((value, length), 2, self.name)
        try:
            n = int(length)
        except (TypeError, ValueError):
            raise FunctionError(
                f"right: comprimento inválido: {length!r}",
                FunctionErrorType.PARAMETER,
                self.name,
            )
        if n <= 0:
            return ""
        return str(value)[-n:]


@registry.register
class RtrimFunction(SentinelaFunction):
    """Remove espaços em branco do final de uma string."""

    name = "rtrim"
    description = "Remove espaços em branco do final de uma string."
    category = "string"
    params = ["value", "chars"]
    return_type = str

    def evaluate(self, value: Any, chars: Any = None) -> str:
        self._require_min_args((value,), 1, self.name)
        if chars is None:
            return str(value).rstrip()
        return str(value).rstrip(str(chars))


@registry.register
class StrFunction(SentinelaFunction):
    """Converte um valor para string."""

    name = "str"
    description = "Converte um valor para string."
    category = "string"
    params = ["value"]
    return_type = str

    def evaluate(self, value: Any) -> str:
        self._require_min_args((value,), 1, self.name)
        return str(value)


@registry.register
class StrftimeFunction(SentinelaFunction):
    """Formata um timestamp Unix em uma string de data/hora."""

    name = "strftime"
    description = "Formata um timestamp Unix em uma string de data/hora."
    category = "string"
    params = ["timestamp", "format"]
    return_type = str

    def evaluate(self, timestamp: Any = None, format_str: Any = "%Y-%m-%d %H:%M:%S") -> str:
        if timestamp is None:
            ts = self.context.now
        else:
            try:
                ts = float(timestamp)
            except (TypeError, ValueError):
                raise FunctionError(
                    f"strftime: timestamp inválido: {timestamp!r}",
                    FunctionErrorType.PARAMETER,
                    self.name,
                )
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        return dt.strftime(str(format_str))


@registry.register
class StrstrFunction(SentinelaFunction):
    """Retorna a substring a partir da primeira ocorrência de uma substring."""

    name = "strstr"
    description = "Retorna a substring a partir da primeira ocorrência de uma substring."
    category = "string"
    params = ["value", "substring"]
    return_type = str

    def evaluate(self, value: Any, substring: Any) -> str:
        self._require_min_args((value, substring), 2, self.name)
        text = str(value)
        sub = str(substring)
        idx = text.find(sub)
        if idx < 0:
            return ""
        return text[idx:]


@registry.register
class TrimFunction(SentinelaFunction):
    """Remove espaços em branco das extremidades de uma string."""

    name = "trim"
    description = "Remove espaços em branco das extremidades de uma string."
    category = "string"
    params = ["value", "chars"]
    return_type = str

    def evaluate(self, value: Any, chars: Any = None) -> str:
        self._require_min_args((value,), 1, self.name)
        if chars is None:
            return str(value).strip()
        return str(value).strip(str(chars))


@registry.register
class UpperFunction(SentinelaFunction):
    """Converte uma string para maiúsculas."""

    name = "upper"
    description = "Converte uma string para maiúsculas."
    category = "string"
    params = ["value"]
    return_type = str

    def evaluate(self, value: Any) -> str:
        self._require_min_args((value,), 1, self.name)
        return str(value).upper()


@registry.register
class BitLengthFunction(SentinelaFunction):
    """Retorna o comprimento em bits de uma string (UTF-8)."""

    name = "bitlength"
    description = "Retorna o comprimento em bits de uma string (UTF-8)."
    category = "string"
    params = ["value"]
    return_type = int

    def evaluate(self, value: Any) -> int:
        self._require_min_args((value,), 1, self.name)
        return len(str(value).encode("utf-8")) * 8


@registry.register
class ByteLengthFunction(SentinelaFunction):
    """Retorna o comprimento em bytes de uma string (UTF-8)."""

    name = "bytelength"
    description = "Retorna o comprimento em bytes de uma string (UTF-8)."
    category = "string"
    params = ["value"]
    return_type = int

    def evaluate(self, value: Any) -> int:
        self._require_min_args((value,), 1, self.name)
        return len(str(value).encode("utf-8"))
