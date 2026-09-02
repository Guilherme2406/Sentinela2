# functions_engine/functions/__init__.py
"""Implementações das funções do Sentinela XDR.

Importar este pacote registra automaticamente todas as funções no registry global.
"""
import importlib

# Importa os submódulos diretamente para registrar todas as funções no registry
_SUBMODULES = [
    "history",
    "math_functions",
    "string_functions",
    "aggregation",
    "time_functions",
    "bitwise",
    "trend",
    "predictive",
    "statistics",
    "foreach",
]

for _mod_name in _SUBMODULES:
    importlib.import_module(f"{__name__}.{_mod_name}")

__all__ = _SUBMODULES