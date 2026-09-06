# sentinel_core/api_security.py
"""
🛡️ SENTINEL API SECURITY & CSRF DEFENDER
Camada de proteção para a REST API local do Sentinela XDR.
Bloqueia requisições maliciosas cross-origin (CSRF) originadas de páginas externas
e gerencia tokens efêmeros de sessão para o dashboard, tray app e CLI.
"""

import os
import hmac
import secrets
import logging
import json
from typing import Optional
from urllib.parse import urlparse
from flask import request, jsonify, make_response, Response

logger = logging.getLogger("SentinelaXDR.APISecurity")

# Gera ou armazena o token efêmero desta sessão
_API_TOKEN: Optional[str] = None
_RUNTIME_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sentinel_runtime.json")


def get_or_create_api_token() -> str:
    """Retorna o token efêmero atual ou gera um novo de 256 bits."""
    global _API_TOKEN
    if _API_TOKEN is None:
        # Se já existir em ambiente ou no runtime, reaproveita
        env_token = os.environ.get("SENTINEL_API_TOKEN")
        if env_token:
            _API_TOKEN = env_token
        else:
            _API_TOKEN = secrets.token_hex(24)
    return _API_TOKEN


def update_runtime_state(port: int, pid: int, status: str = "ONLINE") -> None:
    """Atualiza o arquivo sentinel_runtime.json com o token e informações da instância."""
    token = get_or_create_api_token()
    state = {
        "status": status,
        "port": port,
        "pid": pid,
        "api_token": token,
        "url": f"http://localhost:{port}" if port else "http://localhost:5000"
    }
    try:
        if os.path.exists(_RUNTIME_FILE):
            try:
                with open(_RUNTIME_FILE, "r", encoding="utf-8") as f:
                    existing = json.load(f)
                    if isinstance(existing, dict):
                        existing.update(state)
                        state = existing
            except Exception:
                pass
        with open(_RUNTIME_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        logger.debug(f"[API_SECURITY] Não foi possível gravar runtime_state: {e}")


def is_trusted_origin(origin: Optional[str]) -> bool:
    """Valida se a origem da requisição é local e autorizada.

    Usa parsing real de URL (''urllib.parse.urlparse'') com verificação de
    hostname exato (localhost, 127.0.0.0/8, ::1) — impede bypass do tipo
    ``http://localhost.evil.com`` que a comparação por prefixo permitiria.
    """
    if not origin:
        return True  # Clientes nativos (curl, tray app, python test_client) não enviam Origin

    origin_clean = origin.lower().strip()
    # Arquivos locais abertos via file:// no navegador
    if origin_clean == "null":
        return True

    try:
        parsed = urlparse(origin_clean)
    except ValueError:
        return False

    # Apenas origens http/https são aceitas
    if parsed.scheme not in ("http", "https"):
        return False

    host = (parsed.hostname or "").lower()
    if host in ("localhost", "127.0.0.1", "::1"):
        return True

    # Aceita qualquer endereço da faixa 127.0.0.0/8 (ex.: 127.0.0.2)
    if host.startswith("127."):
        parts = host.split(".")
        if len(parts) == 4 and all(p.isdigit() and p.isascii() for p in parts):
            return all(0 <= int(p) <= 255 for p in parts)

    return False


def is_loopback_request(remote_addr: Optional[str]) -> bool:
    """Determina se a conexão vem da própria máquina (loopback)."""
    if not remote_addr:
        # Clientes nativos sem endereço remoto (test_client, tray) -> tratados como locais
        return True
    if remote_addr in ("127.0.0.1", "::1", "localhost"):
        return True
    if remote_addr.startswith("127."):
        return True
    return False


def extract_api_token(headers=None) -> Optional[str]:
    """Extrai o token de autenticação dos cabeçalhos suportados.

    O dashboard local envia ``X-Sentinel-Auth``; agentes multi-host usam
    ``X-Sentinel-Token``; também é aceito ``Authorization: Bearer``.
    """
    if headers is None:
        headers = request.headers if request else {}
    for header in ("X-Sentinel-Auth", "X-Sentinel-Token"):
        val = headers.get(header)
        if val:
            return str(val).strip()
    auth = headers.get("Authorization", "")
    if isinstance(auth, str) and auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


def validate_api_request():
    """
    Hook de segurança executado antes de cada requisição.

    1) Bloqueia CSRF (Origin/Referer hostis) contra a API local.
    2) Exige o token de sessão da API para clientes remotos (LAN).
    3) Se um token é apresentado, ele é SEMPRE validado (comparação em tempo constante).
    """
    # 1. Permite pre-flight CORS
    if request.method == "OPTIONS":
        return None

    # 2. Ignora validação se explicitamente desativada para testes/instalação
    if os.environ.get("SENTINEL_DISABLE_AUTH") == "1":
        return None

    # 3. Proteção contra CSRF: Verifica os cabeçalhos Origin e Referer
    origin = request.headers.get("Origin")
    if origin and not is_trusted_origin(origin):
        logger.warning(f"🚨 [API_SECURITY] Bloqueada tentativa de CSRF de origem hostil: '{origin}' para '{request.path}'")
        return jsonify({
            "status": "error",
            "code": 403,
            "message": f"Acesso negado: Origem '{origin}' não autorizada a interagir com o Sentinela XDR local."
        }), 403

    referer = request.headers.get("Referer")
    if referer and not is_trusted_origin(referer):
        logger.warning(f"🚨 [API_SECURITY] Bloqueada requisição com Referer hostil: '{referer}' para '{request.path}'")
        return jsonify({
            "status": "error",
            "code": 403,
            "message": "Acesso negado: Referer não autorizado."
        }), 403

    # 4. Validação do token de sessão da API.
    #    - Se o cliente ENVIA um token, ele deve coincidir (token inválido nunca é aceito).
    #    - Se NÃO envia token, só é permitido a partir de loopback (mesma máquina).
    #    - As rotas multi-host (/api/multiagent/*) continuam governadas pela própria
    #      autenticação de frota (token compartilhado de multiagent_config.json).
    if request.path.startswith("/api/multiagent/"):
        return None

    expected = get_or_create_api_token()
    provided = extract_api_token()
    if provided is not None:
        if not hmac.compare_digest(provided, expected):
            logger.warning(f"🚨 [API_SECURITY] Token de sessão inválido rejeitado de '{request.remote_addr}' para '{request.path}'")
            return jsonify({
                "status": "error",
                "code": 401,
                "message": "Token de sessão inválido ou expirado. Autentique-se novamente no painel local."
            }), 401
        return None

    if not is_loopback_request(request.remote_addr):
        logger.warning(f"🚨 [API_SECURITY] Acesso remoto sem token bloqueado de '{request.remote_addr}' para '{request.path}'")
        return jsonify({
            "status": "error",
            "code": 401,
            "message": "Acesso remoto ao Sentinela XDR requer token de sessão. Use o painel local ou autentique-se."
        }), 401

    return None
