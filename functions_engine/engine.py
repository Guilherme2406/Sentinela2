# functions_engine/engine.py
"""Motor principal de avaliação de expressões do Sentinela XDR.

O FunctionsEngine é o ponto de entrada para avaliar expressões de monitoramento
no formato estilo Zabbix, por exemplo::

    last("system.cpu[0,util]") > 90
    avg("net.if.in[eth0]", 300) > 1M
    forecast("disk.used[/]", 3600) > 80
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from functions_engine.core import (
    FunctionContext,
    FunctionError,
    FunctionErrorType,
    SecurityItem,
)
from functions_engine.registry import FunctionRegistry, registry as default_registry

# Expressão de função: nome(args...)
_FUNC_CALL_RE = re.compile(r"^([a-zA-Z_][a-zA-Z0-9_]*)\s*\((.*)\)\s*$", re.DOTALL)


@dataclass
class EvalOptions:
    """Opções de avaliação de expressões."""

    #: Tempo máximo de avaliação em segundos (0 = sem limite)
    timeout: float = 0.0

    #: Se True, converte o resultado para booleano (comparação)
    as_bool: bool = False

    #: Se True, propaga exceções (útil para debug)
    raise_errors: bool = False


class FunctionsEngine:
    """Motor de avaliação de expressões de monitoramento.

    Exemplo de uso::

        engine = FunctionsEngine()
        engine.register_default_functions()

        # Avalia uma expressão
        result = engine.evaluate('last("system.cpu[0,util]")')
        print(result)  # 42.5
    """

    def __init__(
        self,
        registry: Optional[FunctionRegistry] = None,
        context: Optional[FunctionContext] = None,
        options: Optional[EvalOptions] = None,
    ):
        self.registry = registry or default_registry
        self.context = context or FunctionContext()
        self.options = options or EvalOptions()

    # ------------------------------------------------------------------
    # Registro de funções
    # ------------------------------------------------------------------
    def register(self, func_cls: type) -> type:
        """Registra uma função no motor (delega ao registry)."""
        return self.registry.register(func_cls)

    def register_default_functions(self) -> None:
        """Registra todas as funções padrão do Sentinela XDR."""
        from functions_engine import functions as _  # noqa: F401  (importa efeitos colaterais)

    # ------------------------------------------------------------------
    # Avaliação de expressões
    # ------------------------------------------------------------------
    def evaluate(
        self,
        expression: str,
        context: Optional[FunctionContext] = None,
        **kwargs: Any,
    ) -> Any:
        """Avalia uma expressão de monitoramento.

        Args:
            expression: Expressão no formato `func(args...)` ou valor literal.
            context: Contexto de execução (usa o do motor se não informado).
            **kwargs: Argumentos adicionais de contexto.

        Returns:
            O resultado da avaliação.
        """
        ctx = context or self.context
        if kwargs:
            ctx = FunctionContext(
                storage=ctx.storage,
                clock=getattr(ctx, "_clock", None),
                timezone_offset=ctx.timezone_offset,
                **{**ctx.extra, **kwargs},
            )

        expression = expression.strip()
        if not expression:
            raise FunctionError(
                "Expressão vazia", FunctionErrorType.PARAMETER, "evaluate"
            )

        # Tenta avaliar como chamada de função
        try:
            return self._evaluate_expression(expression, ctx)
        except FunctionError:
            raise
        except Exception as exc:
            raise FunctionError(
                f"Erro ao avaliar expressão {expression!r}: {exc}",
                FunctionErrorType.INTERNAL,
                "evaluate",
            ) from exc

    def _evaluate_expression(self, expression: str, ctx: FunctionContext) -> Any:
        """Avalia uma expressão, resolvendo chamadas de função aninhadas."""
        # Tenta avaliar como chamada de função
        match = _FUNC_CALL_RE.match(expression)
        if match:
            func_name = match.group(1)
            args_str = match.group(2).strip()

            # Divide os argumentos respeitando parênteses e aspas
            args = self._parse_args(args_str)

            # Avalia cada argumento (pode ser outra chamada de função)
            evaluated_args = [self._evaluate_arg(arg, ctx) for arg in args]

            # Executa a função
            return self._call_function(func_name, evaluated_args, ctx)

        # Tenta avaliar como valor literal
        return self._parse_literal(expression)

    def _evaluate_arg(self, arg: str, ctx: FunctionContext) -> Any:
        """Avalia um argumento, que pode ser uma chamada de função aninhada."""
        arg = arg.strip()

        # Se for uma chamada de função, avalia recursivamente
        match = _FUNC_CALL_RE.match(arg)
        if match:
            return self._evaluate_expression(arg, ctx)

        # Caso contrário, tenta converter para literal
        return self._parse_literal(arg)

    def _parse_args(self, args_str: str) -> List[str]:
        """Divide uma string de argumentos respeitando parênteses, colchetes e aspas."""
        if not args_str.strip():
            return []

        args = []
        current = []
        depth = 0
        bracket_depth = 0
        in_string: Optional[str] = None
        i = 0

        while i < len(args_str):
            ch = args_str[i]

            if in_string:
                current.append(ch)
                if ch == "\\" and i + 1 < len(args_str):
                    current.append(args_str[i + 1])
                    i += 2
                    continue
                if ch == in_string:
                    in_string = None
            else:
                if ch in "\"'":
                    in_string = ch
                    current.append(ch)
                elif ch == "(":
                    depth += 1
                    current.append(ch)
                elif ch == ")":
                    depth -= 1
                    current.append(ch)
                elif ch == "[":
                    bracket_depth += 1
                    current.append(ch)
                elif ch == "]":
                    bracket_depth -= 1
                    current.append(ch)
                elif ch == "," and depth == 0 and bracket_depth == 0:
                    args.append("".join(current).strip())
                    current = []
                else:
                    current.append(ch)
            i += 1

        if current:
            args.append("".join(current).strip())

        return args

    def _parse_literal(self, value: str) -> Any:
        """Converte uma string em um valor literal (int, float, bool, None, string, lista)."""
        value = value.strip()

        if not value:
            return ""

        # Lista entre colchetes: [1, 2, 3]
        if value.startswith("[") and value.endswith("]"):
            inner = value[1:-1].strip()
            if not inner:
                return []
            items = self._parse_args(inner)
            return [self._parse_literal(item) for item in items]

        # String entre aspas
        if (value[0] == '"' and value[-1] == '"') or (value[0] == "'" and value[-1] == "'"):
            return value[1:-1]

        # Booleanos e None
        if value == "true" or value == "True":
            return True
        if value == "false" or value == "False":
            return False
        if value == "null" or value == "None":
            return None

        # Números
        try:
            return int(value)
        except ValueError:
            pass
        try:
            return float(value)
        except ValueError:
            pass

        # Sufixos de tamanho (Zabbix-style): 1K, 2M, 3G, 1Kb, etc.
        size_match = re.match(r"^([\d.]+)\s*([KkMmGgTt]?[Bb]?)$", value)
        if size_match:
            num = float(size_match.group(1))
            suffix = size_match.group(2).lower()
            multipliers = {
                "": 1, "b": 1,
                "k": 1024, "kb": 1024,
                "m": 1024**2, "mb": 1024**2,
                "g": 1024**3, "gb": 1024**3,
                "t": 1024**4, "tb": 1024**4,
            }
            if suffix in multipliers:
                return num * multipliers[suffix]

        # Sufixos de tempo (Zabbix-style): 1s, 5m, 1h, 1d, 1w
        time_match = re.match(r"^([\d.]+)\s*([smhdw])$", value, re.IGNORECASE)
        if time_match:
            num = float(time_match.group(1))
            unit = time_match.group(2).lower()
            multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
            return num * multipliers[unit]

        # Caso contrário, retorna como string
        return value

    def _call_function(
        self, name: str, args: List[Any], ctx: FunctionContext
    ) -> Any:
        """Chama uma função registrada com os argumentos avaliados."""
        if not self.registry.has(name):
            raise FunctionError(
                f"Função não registrada: {name!r}",
                FunctionErrorType.NOT_FOUND,
                name,
            )

        func_cls = self.registry.get(name)
        func = func_cls(context=ctx)
        return func.evaluate(*args)

    # ------------------------------------------------------------------
    # Avaliação de expressões de trigger (comparações e operadores lógicos)
    # ------------------------------------------------------------------
    def evaluate_trigger(self, expression: str, **kwargs: Any) -> bool:
        """Avalia uma expressão de trigger, retornando True/False.

        Suporta operadores lógicos (and, or, not) e relacionais (>, <, >=, <=, =, ==, !=, <>).
        Exemplos:
            last("system.cpu.util") > 90
            last("system.cpu.util") > 85 and last("system.memory.util") > 80
            not (last("system.cpu.util") < 10)
        """
        expression = expression.strip()
        if not expression:
            return False

        # Remove parênteses externos redundantes se envolverem toda a expressão
        while expression.startswith("(") and expression.endswith(")"):
            depth = 0
            encloses_all = True
            for idx, ch in enumerate(expression[:-1]):
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        encloses_all = False
                        break
            if encloses_all:
                expression = expression[1:-1].strip()
            else:
                break

        # 1. Operador lógico 'or' (menor precedência)
        or_idx = self._find_logical_operator(expression, "or")
        if or_idx >= 0:
            left_part = expression[:or_idx].strip()
            right_part = expression[or_idx + 2:].strip()
            return self.evaluate_trigger(left_part, **kwargs) or self.evaluate_trigger(right_part, **kwargs)

        # 2. Operador lógico 'and'
        and_idx = self._find_logical_operator(expression, "and")
        if and_idx >= 0:
            left_part = expression[:and_idx].strip()
            right_part = expression[and_idx + 3:].strip()
            return self.evaluate_trigger(left_part, **kwargs) and self.evaluate_trigger(right_part, **kwargs)

        # 3. Operador lógico unário 'not'
        if expression.lower().startswith("not ") or expression.lower().startswith("not("):
            sub_expr = expression[3:].strip()
            return not self.evaluate_trigger(sub_expr, **kwargs)

        # 4. Procura por operadores de comparação relacionais
        operators = [">=", "<=", "!=", "<>", "==", "=", ">", "<"]
        for op in operators:
            idx = self._find_operator(expression, op)
            if idx >= 0:
                left = expression[:idx].strip()
                right = expression[idx + len(op):].strip()

                left_val = self.evaluate(left, **kwargs)
                right_val = self._parse_literal(right)

                return self._compare(left_val, op, right_val)

        # Sem operador, avalia como expressão simples
        return bool(self.evaluate(expression, **kwargs))

    def _find_logical_operator(self, expression: str, operator: str) -> int:
        """Encontra a posição de um operador lógico ('and', 'or') fora de strings e parênteses."""
        in_string: Optional[str] = None
        depth = 0
        i = 0
        op_len = len(operator)
        expr_len = len(expression)

        while i < expr_len:
            ch = expression[i]

            if in_string:
                if ch == "\\":
                    i += 2
                    continue
                if ch == in_string:
                    in_string = None
            else:
                if ch in "\"'":
                    in_string = ch
                elif ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                elif depth == 0 and i + op_len <= expr_len:
                    if expression[i : i + op_len].lower() == operator.lower():
                        prev_char = expression[i - 1] if i > 0 else " "
                        next_char = expression[i + op_len] if i + op_len < expr_len else " "
                        if (prev_char.isspace() or prev_char in ")") and (next_char.isspace() or next_char in "("):
                            return i
            i += 1
        return -1

    def _find_operator(self, expression: str, operator: str) -> int:
        """Encontra a posição de um operador fora de strings e parênteses."""
        in_string: Optional[str] = None
        depth = 0
        i = 0
        while i < len(expression):
            ch = expression[i]

            if in_string:
                if ch == "\\":
                    i += 2
                    continue
                if ch == in_string:
                    in_string = None
            else:
                if ch in "\"'":
                    in_string = ch
                elif ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                elif depth == 0 and expression.startswith(operator, i):
                    return i
            i += 1
        return -1

    def _compare(self, left: Any, op: str, right: Any) -> bool:
        """Executa uma comparação entre dois valores."""
        try:
            if op in ("=", "=="):
                return left == right
            if op == "!=" or op == "<>":
                return left != right
            if op == ">":
                return left > right
            if op == "<":
                return left < right
            if op == ">=":
                return left >= right
            if op == "<=":
                return left <= right
        except TypeError:
            return False
        return False

    # ------------------------------------------------------------------
    # Ingestão de dados
    # ------------------------------------------------------------------
    def ingest(self, item: SecurityItem) -> None:
        """Ingere um novo ponto de dados no armazenamento do contexto."""
        if self.context.storage is not None:
            self.context.storage.append(item)

    def ingest_many(self, items: List[SecurityItem]) -> None:
        """Ingere múltiplos pontos de dados de uma vez."""
        for item in items:
            self.ingest(item)

    # ------------------------------------------------------------------
    # Utilidades
    # ------------------------------------------------------------------
    def list_functions(self, **filters: Any) -> List[Dict[str, Any]]:
        """Lista funções registradas com filtros opcionais."""
        return self.registry.list(**filters)

    def __repr__(self) -> str:
        return f"<FunctionsEngine functions={len(self.registry)}>"