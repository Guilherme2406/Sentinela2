# functions_engine/registry.py
"""Registro central de funções do Sentinela XDR.

Permite registrar, consultar e instanciar funções por nome, categoria ou
qualquer outro atributo. Suporta registro automático via decorator.
"""
from __future__ import annotations

import threading
from typing import Any, Callable, Dict, Iterator, List, Optional, Type, TypeVar, Union

from functions_engine.core import FunctionContext, SentinelaFunction

T = TypeVar("T", bound=SentinelaFunction)


class FunctionRegistry:
    """Registro thread-safe de funções do Sentinela XDR.

    Exemplo de uso::

        registry = FunctionRegistry()

        @registry.register
        class MyFunc(SentinelaFunction):
            name = "my_func"
            def evaluate(self, *args, **kwargs):
                return 42

        func = registry.get("my_func")
        result = func.evaluate()
    """

    def __init__(self) -> None:
        self._functions: Dict[str, Type[SentinelaFunction]] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Registro
    # ------------------------------------------------------------------
    def register(
        self,
        func_cls: Optional[Type[T]] = None,
        *,
        name: Optional[str] = None,
        category: Optional[str] = None,
        overwrite: bool = False,
    ) -> Union[Type[T], Callable[[Type[T]], Type[T]]]:
        """Registra uma função no registry.

        Pode ser usado como decorator simples ou com argumentos::

            @registry.register
            class F(SentinelaFunction): ...

            @registry.register(name="custom_name")
            class G(SentinelaFunction): ...
        """
        if func_cls is None:
            def _decorator(cls: Type[T]) -> Type[T]:
                self.register(cls, name=name, category=category, overwrite=overwrite)
                return cls
            return _decorator

        return self._do_register(func_cls, name=name, category=category, overwrite=overwrite)

    def _do_register(
        self,
        func_cls: Type[T],
        *,
        name: Optional[str] = None,
        category: Optional[str] = None,
        overwrite: bool = False,
    ) -> Type[T]:
        if not (isinstance(func_cls, type) and issubclass(func_cls, SentinelaFunction)):
            raise TypeError(
                f"Somente subclasses de SentinelaFunction podem ser registradas. "
                f"Recebido: {func_cls!r}"
            )

        func_name = name or getattr(func_cls, "name", "") or func_cls.__name__.lower()
        if category:
            func_cls.category = category

        with self._lock:
            if func_name in self._functions and not overwrite:
                raise ValueError(
                    f"Função '{func_name}' já registrada. Use overwrite=True para substituir."
                )
            self._functions[func_name] = func_cls
        return func_cls

    # Alias para compatibilidade
    def register_function(self, func_cls: Type[T], **kwargs: Any) -> Type[T]:
        return self._do_register(func_cls, **kwargs)

    # ------------------------------------------------------------------
    # Consulta
    # ------------------------------------------------------------------
    def get(self, name: str) -> Type[SentinelaFunction]:
        """Retorna a classe da função registrada pelo nome."""
        with self._lock:
            try:
                return self._functions[name]
            except KeyError:
                raise KeyError(f"Função não registrada: {name!r}")

    def get_class(self, name: str) -> Type[SentinelaFunction]:
        return self.get(name)

    def create(self, name: str, context: Optional[FunctionContext] = None) -> SentinelaFunction:
        """Instancia uma função registrada pelo nome."""
        cls = self.get(name)
        return cls(context=context)

    def has(self, name: str) -> bool:
        with self._lock:
            return name in self._functions

    def __contains__(self, name: str) -> bool:
        return self.has(name)

    def names(self) -> List[str]:
        with self._lock:
            return sorted(self._functions.keys())

    def categories(self) -> List[str]:
        with self._lock:
            return sorted({f.category for f in self._functions.values()})

    def list(
        self,
        category: Optional[str] = None,
        search: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Lista funções registradas com metadados, com filtros opcionais."""
        result = []
        with self._lock:
            for name, cls in sorted(self._functions.items()):
                if category and cls.category != category:
                    continue
                if search and search.lower() not in name.lower():
                    continue
                result.append(
                    {
                        "name": name,
                        "class": cls.__name__,
                        "category": cls.category,
                        "description": cls.description,
                        "params": list(cls.params),
                        "return_type": getattr(cls.return_type, "__name__", str(cls.return_type)),
                        "version": cls.version,
                    }
                )
        return result

    def __len__(self) -> int:
        with self._lock:
            return len(self._functions)

    def __iter__(self) -> Iterator[str]:
        return iter(self.names())

    def __repr__(self) -> str:
        return f"<FunctionRegistry functions={len(self)}>"


# Instância global compartilhada
registry = FunctionRegistry()