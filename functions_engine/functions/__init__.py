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

_pkg = __name__.rsplit(".__init__", 1)[0] if __name__.endswith(".__init__") else __name__
for _mod_name in _SUBMODULES:
    importlib.import_module(f"{_pkg}.{_mod_name}")

__all__ = _SUBMODULES