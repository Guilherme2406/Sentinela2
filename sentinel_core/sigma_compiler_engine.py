"""
Sentinela XDR - Compilador Nativo de Regras Sigma (Sigma Rule Native Compiler)
Tradução em tempo real de especificações universais Sigma (YAML/JSON) para pipelines
de avaliação de alto desempenho em Python/Regex sem necessidade de motores externos.
"""

import re
import time
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("SentinelaSigmaCompiler")


class SigmaCompilerEngine:
    """Compilador e avaliador em tempo de execução de regras de detecção Sigma."""

    BUILTIN_RULES = [
        {
            "id": "SIGMA-001",
            "title": "Suspicious PowerShell Download Cradle",
            "status": "stable",
            "level": "critical",
            "tags": ["attack.execution", "attack.t1059.001"],
            "detection": {
                "selection": {
                    "CommandLine|contains": ["downloadstring", "downloadfile", "invoke-webrequest", "iwr"]
                },
                "condition": "selection"
            }
        },
        {
            "id": "SIGMA-002",
            "title": "Reconnaissance via Whoami and Net Group",
            "status": "stable",
            "level": "medium",
            "tags": ["attack.discovery", "attack.t1033"],
            "detection": {
                "selection": {
                    "Image|endswith": ["whoami.exe", "net.exe", "net1.exe"],
                    "CommandLine|contains": ["/domain", "administrators"]
                },
                "condition": "selection"
            }
        },
        {
            "id": "SIGMA-003",
            "title": "Procdump LSASS Memory Dumping",
            "status": "stable",
            "level": "critical",
            "tags": ["attack.credential_access", "attack.t1003.001"],
            "detection": {
                "selection": {
                    "CommandLine|contains": ["procdump", "lsass"]
                },
                "condition": "selection"
            }
        }
    ]

    def __init__(self, logger_instance=None):
        self.logger = logger_instance
        self.compiled_rules: List[Dict[str, Any]] = []
        self.total_evaluations: int = 0
        self.total_matches: int = 0
        self.recent_matches: List[Dict[str, Any]] = []

        # Compilar regras embutidas
        for r in self.BUILTIN_RULES:
            self._compile_and_register(r)

        self._log("INFO", "SIGMA_COMPILER_INIT", "INIT", f"Compilador Sigma ativo com {len(self.compiled_rules)} regras compiladas.")

    def _log(self, level: str, category: str, action: str, msg: str):
        try:
            if self.logger and hasattr(self.logger, "log_event"):
                self.logger.log_event(level, category, action, msg)
            elif self.logger and hasattr(self.logger, level.lower()):
                getattr(self.logger, level.lower())(f"[{category}] {msg}")
        except Exception:
            pass
        logging.info(f"[{category}] {msg}")

    def _compile_and_register(self, rule: Dict[str, Any]):
        """Converte a definição abstrata da regra em avaliadores regex rápidos."""
        detection = rule.get("detection", {})
        selection = detection.get("selection", {})

        compiled_criteria = []
        for field_expr, expected in selection.items():
            parts = field_expr.split("|")
            field_name = parts[0]
            modifier = parts[1] if len(parts) > 1 else "exact"

            if not isinstance(expected, list):
                expected = [expected]

            compiled_criteria.append({
                "field": field_name,
                "modifier": modifier,
                "values": [str(v).lower() for v in expected]
            })

        self.compiled_rules.append({
            "id": rule.get("id"),
            "title": rule.get("title"),
            "level": rule.get("level", "medium"),
            "tags": rule.get("tags", []),
            "criteria": compiled_criteria
        })

    def evaluate_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Avalia um evento contra o conjunto de regras Sigma compiladas."""
        self.total_evaluations += 1
        matched_rules = []

        # Normalizar chaves do evento para minúsculo
        event_lower = {k.lower(): str(v).lower() for k, v in event.items()}

        for rule in self.compiled_rules:
            rule_matched = True
            for crit in rule["criteria"]:
                field_val = event_lower.get(crit["field"].lower(), "")
                mod = crit["modifier"]
                vals = crit["values"]

                match_found = False
                if mod == "contains":
                    match_found = any(v in field_val for v in vals)
                elif mod == "endswith":
                    match_found = any(field_val.endswith(v) for v in vals)
                elif mod == "startswith":
                    match_found = any(field_val.startswith(v) for v in vals)
                else:
                    match_found = any(field_val == v for v in vals)

                if not match_found:
                    rule_matched = False
                    break

            if rule_matched:
                matched_rules.append(rule)

        has_match = len(matched_rules) > 0
        if has_match:
            self.total_matches += 1
            entry = {
                "timestamp": time.time(),
                "event": event,
                "matches": [{"id": r["id"], "title": r["title"], "level": r["level"]} for r in matched_rules]
            }
            self.recent_matches.insert(0, entry)
            if len(self.recent_matches) > 50:
                self.recent_matches.pop()

            self._log(
                "WARNING",
                "SIGMA_MATCH",
                "RULE_TRIGGERED",
                f"Regra Sigma disparada: '{matched_rules[0]['title']}' (Nível: {matched_rules[0]['level'].upper()})"
            )

        return {
            "status": "match_found" if has_match else "clean",
            "has_match": has_match,
            "matched_rules_count": len(matched_rules),
            "matched_rules": matched_rules
        }

    def get_status(self) -> Dict[str, Any]:
        """Retorna o status operacional do compilador Sigma."""
        return {
            "status": "active",
            "compiled_rules_count": len(self.compiled_rules),
            "total_evaluations": self.total_evaluations,
            "total_matches": self.total_matches,
            "rules": [{"id": r["id"], "title": r["title"], "level": r["level"]} for r in self.compiled_rules],
            "recent_matches": self.recent_matches[:10]
        }
