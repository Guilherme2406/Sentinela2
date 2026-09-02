# functions_engine - Sentinela XDR Functions Engine
"""Motor de avaliação de expressões e funções do Sentinela XDR.

Implementa as 100+ funções de monitoramento estilo Zabbix:
- Histórico, Tendência, Preditiva, Matemática, String, Agregação, Bitwise, Foreach
"""

from functions_engine.core import (
    SecurityItem,
    FunctionContext,
    SentinelaFunction,
    ParamType,
    FunctionResult,
    FunctionError,
    FunctionErrorType,
)
from functions_engine.registry import FunctionRegistry
from functions_engine.engine import FunctionsEngine
from functions_engine.daemon import TriggerRule, TriggerWatchDaemon

__all__ = [
    "SecurityItem",
    "FunctionContext",
    "SentinelaFunction",
    "ParamType",
    "FunctionResult",
    "FunctionError",
    "FunctionErrorType",
    "FunctionRegistry",
    "FunctionsEngine",
    "TriggerRule",
    "TriggerWatchDaemon",
]

__version__ = "1.0.0"