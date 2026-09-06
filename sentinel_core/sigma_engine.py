# sentinel_core/sigma_engine.py
"""
🛡️ SENTINELA SIGMA DETECTION ENGINE (PADRÃO UNIVERSAL DA INDÚSTRIA)
Permite ao Sentinela XDR carregar e avaliar regras no padrão universal Sigma (YAML).
Permite ingestão de milhares de regras públicas da comunidade MITRE ATT&CK sem modificar o código.
"""

import os
import re
import json
import logging
from typing import Dict, Any, List, Optional

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

logger = logging.getLogger("SentinelaXDR.SigmaEngine")


class SigmaRule:
    """Representação de uma regra Sigma compilada para avaliação ultrarrápida."""

    def __init__(self, raw_data: Dict[str, Any], file_path: Optional[str] = None):
        self.raw = raw_data
        self.file_path = file_path
        self.id = str(raw_data.get("id") or raw_data.get("rule_id") or raw_data.get("title", "UNKNOWN_RULE"))
        self.title = str(raw_data.get("title") or "Unnamed Sigma Rule")
        self.description = str(raw_data.get("description") or "")
        self.status = str(raw_data.get("status") or "stable")
        self.level = str(raw_data.get("level") or "high").upper()
        self.tags = list(raw_data.get("tags") or [])
        self.logsource = raw_data.get("logsource") or {}
        self.detection = raw_data.get("detection") or {}
        self.condition = str(self.detection.get("condition") or "selection").strip()

    def evaluate(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Avalia se o evento satisfaz os critérios de detecção da regra Sigma.
        Retorna detalhes do match ou None.
        """
        if not self.detection:
            return None

        # Avalia cada bloco de seleção/filtro na seção detection
        block_results: Dict[str, bool] = {}
        matched_details: Dict[str, Any] = {}

        # Normaliza as chaves do evento para minúsculas para comparação insensível a maiúsculas
        event_norm = {str(k).lower(): v for k, v in event.items()}

        for block_name, block_def in self.detection.items():
            if block_name in ("condition", "timeframe"):
                continue

            matched = self._evaluate_block(block_def, event_norm, matched_details)
            block_results[block_name] = matched

        # Avalia a condição booleana
        if self._evaluate_condition(self.condition, block_results):
            return {
                "rule_id": self.id,
                "title": self.title,
                "level": self.level,
                "description": self.description,
                "tags": self.tags,
                "matched_fields": matched_details,
                "file": os.path.basename(self.file_path) if self.file_path else "built-in"
            }
        return None

    def _evaluate_block(self, block_def: Any, event_norm: Dict[str, Any], matched_details: Dict[str, Any]) -> bool:
        """Avalia um bloco de seleção individual (dicionário ou lista)."""
        if isinstance(block_def, list):
            # Lista de dicionários representa OR entre os itens
            return any(self._evaluate_block(item, event_norm, matched_details) for item in block_def)

        if not isinstance(block_def, dict):
            return False

        # Cada chave-valor no dicionário do bloco deve coincidir (AND lógico dentro da seleção)
        for field_spec, expected_val in block_def.items():
            parts = field_spec.split("|")
            field_name = parts[0].strip().lower()
            modifiers = [m.strip().lower() for m in parts[1:]]

            # Busca o valor no evento
            event_val = event_norm.get(field_name)
            if event_val is None:
                # Tenta mapeamentos comuns (Image -> name, CommandLine -> cmdline)
                alias_map = {
                    "image": "name",
                    "processname": "name",
                    "commandline": "cmdline",
                    "parentimage": "parent_name",
                    "destinationip": "remote_ip",
                    "dest_ip": "remote_ip",
                    "destinationport": "port"
                }
                alias = alias_map.get(field_name)
                if alias:
                    event_val = event_norm.get(alias)

            if event_val is None:
                return False

            if not self._check_match(event_val, expected_val, modifiers):
                return False

            matched_details[field_spec] = {"expected": expected_val, "actual": event_val}

        return True

    def _check_match(self, actual: Any, expected: Any, modifiers: List[str]) -> bool:
        """Verifica se o valor real satisfaz a expectativa aplicando modificadores."""
        actual_str = str(actual).lower()

        # Se expected for uma lista de valores, o padrão Sigma interpreta como OR (basta um coincidir)
        if isinstance(expected, list) and "all" not in modifiers:
            return any(self._check_single_match(actual_str, exp, modifiers) for exp in expected)
        elif isinstance(expected, list) and "all" in modifiers:
            return all(self._check_single_match(actual_str, exp, modifiers) for exp in expected)
        else:
            return self._check_single_match(actual_str, expected, modifiers)

    def _check_single_match(self, actual_str: str, expected_val: Any, modifiers: List[str]) -> bool:
        exp_str = str(expected_val).lower()

        if "re" in modifiers:
            try:
                return bool(re.search(exp_str, actual_str, re.IGNORECASE))
            except Exception:
                return False

        if "contains" in modifiers:
            return exp_str in actual_str
        elif "startswith" in modifiers:
            return actual_str.startswith(exp_str)
        elif "endswith" in modifiers:
            return actual_str.endswith(exp_str)
        else:
            # Sem modificador: se expected for string curta ou substring comum, aceita substring ou match exato
            return exp_str in actual_str or actual_str == exp_str

    def _evaluate_condition(self, condition: str, block_results: Dict[str, bool]) -> bool:
        """Avalia a expressão lógica de condição do Sigma."""
        cond = condition.strip()

        # Caso simples direto (ex: 'selection')
        if cond in block_results:
            return block_results[cond]

        # Quantificadores comuns: 1 of selection*, all of them, any of them
        if cond in ("1 of them", "any of them"):
            return any(block_results.values())
        if cond == "all of them":
            return all(block_results.values()) if block_results else False

        if cond.startswith("1 of ") or cond.startswith("any of "):
            prefix = cond.split(" ")[-1].replace("*", "")
            matching_blocks = [v for k, v in block_results.items() if k.startswith(prefix)]
            return any(matching_blocks) if matching_blocks else False

        if cond.startswith("all of "):
            prefix = cond.split(" ")[-1].replace("*", "")
            matching_blocks = [v for k, v in block_results.items() if k.startswith(prefix)]
            return all(matching_blocks) if matching_blocks else False

        # Avaliação de expressões com AND / OR / NOT
        try:
            expr = cond
            # Substitui nomes de blocos pelos seus valores booleanos
            for name, val in sorted(block_results.items(), key=lambda x: len(x[0]), reverse=True):
                expr = re.sub(r'\b' + re.escape(name) + r'\b', str(val), expr)

            # Normaliza operadores lógicos para sintaxe Python
            expr = re.sub(r'\band\b', 'and', expr, flags=re.IGNORECASE)
            expr = re.sub(r'\bor\b', 'or', expr, flags=re.IGNORECASE)
            expr = re.sub(r'\bnot\b', 'not', expr, flags=re.IGNORECASE)

            # Sanitiza para garantir execução estritamente booleana segura
            allowed_tokens = {"True", "False", "and", "or", "not", "(", ")", " "}
            tokens = set(re.findall(r'[a-zA-Z]+|[()]', expr))
            if tokens.issubset(allowed_tokens):
                return bool(eval(expr, {"__builtins__": {}}, {}))
        except Exception as e:
            logger.debug(f"[SIGMA] Erro ao avaliar condição '{condition}': {e}")

        # Fallback padrão: se qualquer bloco com nome 'selection' deu True
        return any(v for k, v in block_results.items() if "selection" in k)


class SigmaRuleEngine:
    """Motor central de regras Sigma do Sentinela XDR."""

    def __init__(self, rules_dir: Optional[str] = None, logger_instance=None):
        self.rules_dir = rules_dir
        self.logger = logger_instance
        self.rules: List[SigmaRule] = []
        self._load_all_rules()

    def _load_all_rules(self):
        """Carrega regras do diretório configurado ou injeta as regras Sigma padrão."""
        self.rules = []
        loaded_count = 0

        if self.rules_dir and os.path.exists(self.rules_dir):
            for root, _, files in os.walk(self.rules_dir):
                for f in files:
                    if f.endswith((".yml", ".yaml", ".json")):
                        full_path = os.path.join(root, f)
                        try:
                            rule = self._load_file(full_path)
                            if rule:
                                self.rules.append(rule)
                                loaded_count += 1
                        except Exception as e:
                            logger.debug(f"[SIGMA] Erro ao carregar '{f}': {e}")

        # Se nenhuma regra de arquivo for encontrada, registra o arsenal básico nativo
        if not self.rules:
            self._register_default_sigma_rules()

        logger.info(f"⚡ [SIGMA ENGINE] {len(self.rules)} regras Sigma operacionais no motor.")

    def _load_file(self, full_path: str) -> Optional[SigmaRule]:
        with open(full_path, "r", encoding="utf-8") as fp:
            content = fp.read()
            if HAS_YAML and full_path.endswith((".yml", ".yaml")):
                data = yaml.safe_load(content)
            else:
                data = json.loads(content)
            if isinstance(data, dict) and "detection" in data:
                return SigmaRule(data, file_path=full_path)
        return None

    def _register_default_sigma_rules(self):
        """Conjunto nativo de regras de padrão militar/enterprise em conformidade com Sigma."""
        defaults = [
            {
                "id": "SIGMA-T1003-001",
                "title": "Dump de Memória LSASS via MiniDump",
                "level": "critical",
                "description": "Detecta extração cirúrgica de senhas em memória usando comsvcs.dll ou procdump",
                "tags": ["attack.credential_access", "attack.t1003.001"],
                "detection": {
                    "selection_comsvcs": {
                        "CommandLine|contains": ["comsvcs.dll", "minidump"]
                    },
                    "selection_procdump": {
                        "CommandLine|contains": ["procdump", "lsass"]
                    },
                    "condition": "1 of selection*"
                }
            },
            {
                "id": "SIGMA-T1490-001",
                "title": "Destruição de Cópias de Sombra de Volume (Anti-Ransomware)",
                "level": "critical",
                "description": "Detecta comandos usados por ransomwares como LockBit e BlackCat para apagar backups locais",
                "tags": ["attack.impact", "attack.t1490"],
                "detection": {
                    "selection_vss": {
                        "CommandLine|contains": ["vssadmin", "delete", "shadows"]
                    },
                    "selection_wmic": {
                        "CommandLine|contains": ["wmic", "shadowcopy", "delete"]
                    },
                    "selection_wbadmin": {
                        "CommandLine|contains": ["wbadmin", "delete", "catalog"]
                    },
                    "condition": "1 of selection*"
                }
            },
            {
                "id": "SIGMA-T1105-001",
                "title": "Download de Payload via LOLBin Certutil",
                "level": "high",
                "description": "Detecta abuso de utilitário nativo de certificados para baixar executáveis da internet",
                "tags": ["attack.command_and_control", "attack.t1105"],
                "detection": {
                    "selection": {
                        "CommandLine|contains": ["certutil", "-urlcache", "-split"]
                    },
                    "condition": "selection"
                }
            },
            {
                "id": "SIGMA-T1059-001",
                "title": "Execução de PowerShell Oculto e Cifrado em Base64",
                "level": "high",
                "description": "Detecta PowerShell executado em modo invisível com payload ofuscado",
                "tags": ["attack.execution", "attack.t1059.001"],
                "detection": {
                    "selection": {
                        "CommandLine|contains": ["powershell", "-enc"]
                    },
                    "condition": "selection"
                }
            }
        ]
        for d in defaults:
            self.rules.append(SigmaRule(d))

    def evaluate_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Avalia um evento contra todo o arsenal de regras Sigma ativas."""
        matches = []
        for rule in self.rules:
            res = rule.evaluate(event)
            if res:
                matches.append(res)
                if self.logger:
                    self.logger.log_event(
                        res["level"],
                        "SIGMA_MATCH",
                        res["rule_id"],
                        f"Alerta Sigma: '{res['title']}' | Tags: {', '.join(res['tags'])}"
                    )
        return matches

    def get_rules_summary(self) -> List[Dict[str, Any]]:
        """Retorna a lista de regras carregadas para exibição no dashboard e API."""
        return [
            {
                "id": r.id,
                "title": r.title,
                "level": r.level,
                "description": r.description,
                "tags": r.tags,
                "status": r.status,
                "file": os.path.basename(r.file_path) if r.file_path else "built-in"
            }
            for r in self.rules
        ]

    get_rules = get_rules_summary
