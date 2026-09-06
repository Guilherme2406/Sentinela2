# api/index.py
"""
Entrypoint Serverless para Vercel — SENTINEL XDR Cloud Console.
Fornece Dashboard Público Global, Sistema de Autenticação Soberana,
Vinculação de Identidade de Computadores (HWID) e Sincronização em Tempo Real.
"""

import os
import sys
import json
import time
import sqlite3
import hashlib
import hmac
import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from functools import wraps

from flask import Flask, jsonify, request, make_response, redirect, send_from_directory
from flask_cors import CORS

# Diretórios base
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))
TEMPLATES_DIR = BASE_DIR / "templates"
ASSETS_DIR = BASE_DIR / "assets"
DB_PATH = Path("/tmp/sentinel_cloud.db") if os.path.exists("/tmp") else (BASE_DIR / "sentinel_cloud.db")

app = Flask(__name__)
CORS(app, supports_credentials=True)

# Secret Key para assinatura de tokens de sessão
SECRET_KEY = os.environ.get("SENTINEL_SECRET_KEY", "sentinel-sovereign-cloud-master-secret-2026")

# Gerenciador Oficial PostgreSQL do Projeto
pg_manager = None
_pg_init_error = None
try:
    from sentinel_core.db_postgres import pg_manager as _pg
    pg_manager = _pg
    import threading
    threading.Thread(target=pg_manager.init_tables, daemon=True).start()
except Exception as _e:
    _pg_init_error = str(_e)
    print(f"[POSTGRES_INIT_WARNING] {_e}", file=sys.stderr)



# ==============================================================================
# BANCO DE DADOS SERVERLESS (SQLite com Auto-Migração)
# ==============================================================================

def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    computer_id TEXT UNIQUE NOT NULL,
                    hostname TEXT,
                    os_name TEXT,
                    sync_token TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                );
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS telemetry (
                    computer_id TEXT PRIMARY KEY,
                    snapshot_json TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    computer_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT NOT NULL,
                    payload_json TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.commit()
    except Exception as e:
        print(f"[DB_INIT_ERROR] {e}", file=sys.stderr)

# Inicializa banco de dados
init_db()

# ==============================================================================
# FUNÇÕES DE SEGURANÇA, TOKENS STATELESS & CLOUD RELAY
# ==============================================================================

def hash_password(password: str) -> str:
    salt = "sentinel_salt_sovereign_xdr"
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()

def generate_user_token(user_id: int, email: str, computer_id: str = "") -> str:
    exp = int(time.time()) + 86400 * 30
    payload = f"usr:{user_id}:{email}:{computer_id}:{exp}"
    sig = hmac.new(SECRET_KEY.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()[:24]
    return f"{payload}:{sig}"

def generate_device_token(user_id: int, email: str, computer_id: str) -> str:
    payload = f"dev:{user_id}:{email}:{computer_id}"
    sig = hmac.new(SECRET_KEY.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()[:24]
    return f"{payload}:{sig}"

def verify_token(token: Optional[str]) -> Optional[Dict[str, Any]]:
    if not token or ":" not in token:
        return None
    try:
        parts = token.split(":")
        # Formato novo: usr:user_id:email:computer_id:exp:sig
        if len(parts) == 6 and parts[0] == "usr":
            _, uid_str, email, comp_id, exp_str, sig = parts
            if time.time() > int(exp_str):
                return None
            payload = f"usr:{uid_str}:{email}:{comp_id}:{exp_str}"
            expected_sig = hmac.new(SECRET_KEY.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()[:24]
            if hmac.compare_digest(sig, expected_sig):
                return {"user_id": int(uid_str), "email": email, "computer_id": comp_id}

        # Formato device: dev:user_id:email:computer_id:sig
        elif len(parts) == 5 and parts[0] == "dev":
            _, uid_str, email, comp_id, sig = parts
            payload = f"dev:{uid_str}:{email}:{comp_id}"
            expected_sig = hmac.new(SECRET_KEY.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()[:24]
            if hmac.compare_digest(sig, expected_sig):
                return {"user_id": int(uid_str), "email": email, "computer_id": comp_id, "is_device": True}

        # Compatibilidade com formato legado: user_id:email:exp:sig
        elif len(parts) == 4:
            uid_str, email, exp_str, sig = parts
            if time.time() > int(exp_str):
                return None
            payload = f"{uid_str}:{email}:{exp_str}"
            expected_sig = hmac.new(SECRET_KEY.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()[:24]
            if hmac.compare_digest(sig, expected_sig):
                return {"user_id": int(uid_str), "email": email, "computer_id": ""}
    except Exception:
        return None
    return None

def get_current_user() -> Optional[Dict[str, Any]]:
    """Extrai usuário atual de Cookie, Header Authorization, X-Sentinel-Cloud-Token ou query param."""
    token = request.cookies.get("sentinel_cloud_token")
    if not token:
        token = request.args.get("token")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]
        elif request.headers.get("X-Sentinel-Cloud-Token"):
            token = request.headers.get("X-Sentinel-Cloud-Token")
    return verify_token(token)

def _get_cloud_relay_topic(user_id: int) -> str:
    seed = f"{user_id}:{SECRET_KEY}".encode("utf-8")
    h = hashlib.sha256(seed).hexdigest()[:20]
    return f"sentinel_xdr_{h}"

def push_telemetry_to_relay(user_id: int, data: Dict[str, Any]):
    """Transmite telemetria para o canal pub/sub de alta disponibilidade."""
    try:
        import urllib.request
        topic = _get_cloud_relay_topic(user_id)
        req = urllib.request.Request(
            f"https://ntfy.sh/{topic}",
            data=json.dumps(data, ensure_ascii=False).encode("utf-8"),
            headers={"Title": "Sentinel Telemetry", "Priority": "low"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            pass
    except Exception:
        pass

def pull_telemetry_from_relay(user_id: int) -> Optional[Dict[str, Any]]:
    """Recupera último snapshot do canal pub/sub em caso de instância serverless recém-iniciada."""
    try:
        import urllib.request
        topic = _get_cloud_relay_topic(user_id)
        req = urllib.request.Request(f"https://ntfy.sh/{topic}/json?poll=1", headers={"User-Agent": "SentinelCloud/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            lines = resp.read().decode("utf-8").strip().splitlines()
            for line in reversed(lines):
                obj = json.loads(line)
                if obj.get("event") == "message" and obj.get("message"):
                    return json.loads(obj["message"])
    except Exception:
        pass
    return None

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            if request.path.startswith("/api/"):
                return jsonify({"status": "error", "message": "Autenticação requerida"}), 401
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated

# ==============================================================================
# ROTAS DE PÁGINAS (FRONTEND)
# ==============================================================================

@app.route("/", methods=["GET"])
def root():
    user = get_current_user()
    if not user:
        return redirect("/login")
    return redirect("/dashboard")

@app.route("/login", methods=["GET"])
def login_page():
    login_html_path = TEMPLATES_DIR / "login.html"
    if login_html_path.exists():
        with open(login_html_path, "r", encoding="utf-8") as f:
            content = f.read()
        resp = make_response(content, 200)
        resp.headers["Content-Type"] = "text/html; charset=utf-8"
        return resp
    return "<h1>Sentinel XDR Login</h1><p>templates/login.html não encontrado.</p>", 404

@app.route("/dashboard", methods=["GET"])
def dashboard_page():
    user = get_current_user()
    if not user:
        return redirect("/login")

    dashboard_path = BASE_DIR / "dashboard.html"
    if not dashboard_path.exists():
        return jsonify({"status": "error", "message": "dashboard.html não encontrado"}), 404

    with open(dashboard_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Injeta contexto da Nuvem e dados do usuário logado
    token = request.cookies.get("sentinel_cloud_token") or ""
    
    # Busca computador ativo vinculado ao usuário
    active_device = None
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM devices WHERE user_id = ? ORDER BY last_seen DESC LIMIT 1", (user["user_id"],))
            row = cur.fetchone()
            if row:
                active_device = dict(row)
    except Exception:
        pass

    cloud_context_script = f"""
    <style>
        .cloud-status-pill {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(0, 240, 255, 0.08);
            border: 1px solid rgba(0, 240, 255, 0.3);
            border-radius: 20px;
            padding: 5px 12px;
            font-size: 0.75rem;
            color: #f8fafc;
            cursor: pointer;
            transition: all 0.2s ease;
            margin-right: 8px;
        }}
        .cloud-status-pill:hover {{
            background: rgba(0, 240, 255, 0.16);
            border-color: #00f0ff;
            box-shadow: 0 0 12px rgba(0, 240, 255, 0.25);
        }}
        .cloud-pulse {{
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: #10b981;
            box-shadow: 0 0 8px #10b981;
            animation: pulseCloud 2s infinite;
        }}
        .cloud-pulse.offline {{
            background: #f59e0b;
            box-shadow: 0 0 8px #f59e0b;
        }}
        @keyframes pulseCloud {{
            0% {{ opacity: 1; transform: scale(1); }}
            50% {{ opacity: 0.4; transform: scale(0.8); }}
            100% {{ opacity: 1; transform: scale(1); }}
        }}
        .btn-cloud-logout {{
            background: rgba(239, 68, 68, 0.12);
            border: 1px solid rgba(239, 68, 68, 0.4);
            color: #fca5a5;
            border-radius: 8px;
            padding: 5px 10px;
            font-size: 0.75rem;
            font-weight: 600;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 5px;
            transition: all 0.2s ease;
            margin-left: 6px;
        }}
        .btn-cloud-logout:hover {{
            background: rgba(239, 68, 68, 0.25);
            border-color: #ef4444;
            color: #fff;
        }}
        /* Modal de Dispositivos */
        .cloud-modal-overlay {{
            display: none;
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(4, 7, 13, 0.85);
            backdrop-filter: blur(8px);
            z-index: 99999;
            align-items: center;
            justify-content: center;
        }}
        .cloud-modal-card {{
            background: #0d1322;
            border: 1px solid #00f0ff;
            border-radius: 14px;
            padding: 24px;
            max-width: 500px;
            width: 90%;
            box-shadow: 0 15px 40px rgba(0,0,0,0.8), 0 0 25px rgba(0, 240, 255, 0.15);
            color: #f8fafc;
        }}
    </style>
    <script>
        window.SENTINEL_IS_CLOUD = true;
        window.SENTINEL_AUTH_TOKEN = "{token}";
        window.SENTINEL_USER_EMAIL = "{user['email']}";
        window.SENTINEL_ACTIVE_DEVICE = {json.dumps(active_device or {})};

        // Garante que o token da nuvem permaneça ativo no localStorage e cookies
        if (window.SENTINEL_AUTH_TOKEN) {{
            try {{
                localStorage.setItem('sentinel_cloud_token', window.SENTINEL_AUTH_TOKEN);
                document.cookie = "sentinel_cloud_token=" + window.SENTINEL_AUTH_TOKEN + "; path=/; max-age=2592000; SameSite=Lax; Secure";
            }} catch(e){{}}
        }}

        function initCloudConsole() {{
            checkDomainWarning();
            setupCloudHeader();
            startCloudSyncPolling();
        }}

        if (document.readyState === 'loading') {{
            document.addEventListener('DOMContentLoaded', initCloudConsole);
        }} else {{
            initCloudConsole();
        }}

        function checkDomainWarning() {{
            if (window.location.hostname.includes('-git-') || window.location.hostname.includes('vercel.app') && !window.location.hostname.startsWith('sentinela2.')) {{
                if (document.getElementById('domainWarningBanner')) return;
                const banner = document.createElement('div');
                banner.id = 'domainWarningBanner';
                banner.style.cssText = 'background: linear-gradient(90deg, #b91c1c, #991b1b); color: #fff; font-size: 0.78rem; padding: 6px 16px; text-align: center; position: sticky; top: 0; z-index: 999999; display: flex; justify-content: center; align-items: center; gap: 12px; font-weight: 600; box-shadow: 0 2px 10px rgba(0,0,0,0.5);';
                banner.innerHTML = `
                    <span><i class="fa-solid fa-triangle-exclamation"></i> Você está em um link de visualização com proteção do Vercel. Para sincronização completa em tempo real, use a URL Oficial:</span>
                    <a href="https://sentinela2.vercel.app/dashboard" style="background: #fff; color: #b91c1c; padding: 2px 10px; border-radius: 6px; text-decoration: none; font-weight: 700;">Acessar sentinela2.vercel.app</a>
                `;
                document.body.prepend(banner);
            }}
        }}

        function setupCloudHeader() {{
            const brandWrap = document.querySelector('.brand-container') || document.querySelector('header');
            const dev = window.SENTINEL_ACTIVE_DEVICE || {{}};
            const hasDev = !!dev.computer_id;
            const devIdShort = hasDev ? dev.computer_id : 'Nenhum Vinculado';

            if (!document.getElementById('cloudStatusPill')) {{
                const pill = document.createElement('div');
                pill.className = 'cloud-status-pill';
                pill.id = 'cloudStatusPill';
                pill.title = 'Gerenciar Computadores Vinculados à Conta Cloud';
                pill.innerHTML = `
                    <span class="cloud-pulse ${{hasDev ? '' : 'offline'}}" id="cloudPulse"></span>
                    <i class="fa-solid fa-cloud" style="color: #00f0ff;"></i>
                    <span id="cloudDeviceLabel"><strong>PC:</strong> ${{devIdShort}}</span>
                `;
                pill.onclick = openCloudDeviceModal;

                const dbPill = document.createElement('div');
                dbPill.className = 'cloud-status-pill';
                dbPill.id = 'cloudDbPill';
                dbPill.title = 'Status do Banco de Dados Oficial PostgreSQL';
                dbPill.innerHTML = `
                    <i class="fa-solid fa-database" style="color: #60a5fa;"></i>
                    <span id="cloudDbLabel"><strong>DB:</strong> Verificando...</span>
                `;
                dbPill.onclick = () => {{
                    fetch('/api/cloud/db/status').then(r => r.json()).then(d => {{
                        if (d.status === 'connected') {{
                            alert('✅ BANCO POSTGRESQL ATIVO!\nHost: ' + d.database.host + '\nBase: ' + d.database.database + '\nDriver: ' + (d.database.drivers?.pg8000 ? 'pg8000' : 'psycopg2') + '\nStatus: Conectado e Operacional!');
                        }} else {{
                            alert('⚠️ BANCO POSTGRESQL AGUARDANDO LIBERAÇÃO:\nHost: ' + (d.database?.host || '167.249.121.40:5432') + '\nBase: ' + (d.database?.database || 'db_guilherme') + '\n\n' + d.instructions);
                        }}
                    }});
                }};

                if (brandWrap) {{
                    brandWrap.appendChild(pill);
                    brandWrap.appendChild(dbPill);
                }}

                // Atualiza status do banco
                fetch('/api/cloud/db/status').then(r => r.json()).then(d => {{
                    const label = document.getElementById('cloudDbLabel');
                    const pillEl = document.getElementById('cloudDbPill');
                    if (label && pillEl) {{
                        if (d.status === 'connected') {{
                            label.innerHTML = '<strong>DB:</strong> Online';
                            pillEl.style.borderColor = 'rgba(16, 185, 129, 0.5)';
                            pillEl.style.background = 'rgba(16, 185, 129, 0.1)';
                        }} else {{
                            label.innerHTML = '<strong>DB:</strong> Porta 5432';
                            pillEl.style.borderColor = 'rgba(245, 158, 11, 0.5)';
                            pillEl.style.background = 'rgba(245, 158, 11, 0.1)';
                        }}
                    }}
                }}).catch(e => {{}});
            }}

            const actionsWrap = document.querySelector('.header-right-actions');
            if (actionsWrap && !document.getElementById('cloudLogoutBtn')) {{
                const logoutBtn = document.createElement('button');
                logoutBtn.id = 'cloudLogoutBtn';
                logoutBtn.className = 'btn-cloud-logout';
                logoutBtn.title = 'Desconectar da Conta Cloud';
                logoutBtn.innerHTML = '<i class="fa-solid fa-power-off"></i> Sair';
                logoutBtn.onclick = () => {{
                    try {{ localStorage.removeItem('sentinel_cloud_token'); }} catch(e){{}}
                    window.location.href = '/api/cloud/auth/logout';
                }};
                actionsWrap.appendChild(logoutBtn);
            }}

            createDeviceModalDom();
        }}


        function createDeviceModalDom() {{
            if (document.getElementById('cloudDeviceModalOverlay')) return;
            const overlay = document.createElement('div');
            overlay.className = 'cloud-modal-overlay';
            overlay.id = 'cloudDeviceModalOverlay';
            overlay.innerHTML = `
                <div class="cloud-modal-card">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; border-bottom: 1px solid #1e293b; padding-bottom: 12px;">
                        <h3 style="font-size: 1rem; color: #00f0ff; display: flex; align-items: center; gap: 8px;">
                            <i class="fa-solid fa-desktop"></i> Central de Computadores Vinculados
                        </h3>
                        <button onclick="closeCloudDeviceModal()" style="background: none; border: none; color: #94a3b8; font-size: 1.2rem; cursor: pointer;">&times;</button>
                    </div>
                    <div style="font-size: 0.82rem; color: #94a3b8; margin-bottom: 14px;">
                        Conta ativa: <strong style="color: #f8fafc;">${{window.SENTINEL_USER_EMAIL}}</strong>
                    </div>
                    <div id="cloudDevicesList" style="margin-bottom: 20px; max-height: 200px; overflow-y: auto;">
                        <div style="text-align: center; padding: 12px; color: #64748b;">Carregando dispositivos...</div>
                    </div>
                    <div style="border-top: 1px solid #1e293b; padding-top: 14px;">
                        <label style="font-size: 0.78rem; color: #00f0ff; font-weight: 600; display: block; margin-bottom: 6px;">
                            + VINCULAR NOVO COMPUTADOR (HARDWARE ID)
                        </label>
                        <div style="display: flex; gap: 8px;">
                            <input type="text" id="newComputerIdInput" placeholder="Ex: SENT-0E5B-414F-C5DF" style="flex: 1; padding: 8px 12px; background: #060910; border: 1px solid #1e293b; border-radius: 8px; color: #fff; font-family: monospace; font-size: 0.82rem; text-transform: uppercase;">
                            <button onclick="submitLinkDevice()" style="background: #00f0ff; color: #000; border: none; border-radius: 8px; padding: 8px 14px; font-weight: 700; font-size: 0.8rem; cursor: pointer;">Vincular</button>
                        </div>
                    </div>
                </div>
            `;
            document.body.appendChild(overlay);
        }}

        function openCloudDeviceModal() {{
            const overlay = document.getElementById('cloudDeviceModalOverlay');
            if (overlay) {{
                overlay.style.display = 'flex';
                loadCloudDevices();
            }}
        }}

        function closeCloudDeviceModal() {{
            const overlay = document.getElementById('cloudDeviceModalOverlay');
            if (overlay) overlay.style.display = 'none';
        }}

        async function loadCloudDevices() {{
            const listEl = document.getElementById('cloudDevicesList');
            if (!listEl) return;
            try {{
                const res = await fetch('/api/cloud/devices');
                const data = await res.json();
                if (data.status === 'success' && data.devices.length > 0) {{
                    listEl.innerHTML = data.devices.map(d => `
                        <div style="background: #060910; border: 1px solid ${{d.online ? '#10b981' : '#1e293b'}}; border-radius: 8px; padding: 10px 12px; margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center;">
                            <div>
                                <div style="font-size: 0.85rem; font-weight: 600; color: #fff; display: flex; align-items: center; gap: 6px;">
                                    <span style="width: 8px; height: 8px; border-radius: 50%; background: ${{d.online ? '#10b981' : '#f59e0b'}};"></span>
                                    ${{d.computer_id}}
                                </div>
                                <div style="font-size: 0.72rem; color: #64748b; margin-top: 2px;">
                                    ${{d.hostname || 'PC-Sovereign'}} &bull; ${{d.os_name || 'Windows'}} &bull; Visto: ${{d.last_seen || 'Recentemente'}}
                                </div>
                            </div>
                            <span style="font-size: 0.7rem; padding: 2px 8px; border-radius: 4px; background: ${{d.online ? 'rgba(16,185,129,0.15)' : 'rgba(245,158,11,0.15)'}}; color: ${{d.online ? '#10b981' : '#f59e0b'}};">
                                ${{d.online ? 'ONLINE' : 'OFFLINE'}}
                            </span>
                        </div>
                    `).join('');
                }} else {{
                    listEl.innerHTML = '<div style="text-align: center; padding: 12px; color: #94a3b8; font-size: 0.8rem;">Nenhum computador vinculado ainda.<br>Cole o ID da sua máquina abaixo.</div>';
                }}
            }} catch (err) {{
                listEl.innerHTML = '<div style="color: #ef4444; font-size: 0.8rem;">Erro ao carregar dispositivos.</div>';
            }}
        }}

        async function submitLinkDevice() {{
            const input = document.getElementById('newComputerIdInput');
            const compId = input.value.trim().toUpperCase();
            if (!compId) return;
            try {{
                const res = await fetch('/api/cloud/devices/link', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ computer_id: compId }})
                }});
                const data = await res.json();
                if (data.status === 'success') {{
                    input.value = '';
                    loadCloudDevices();
                    alert('Computador vinculado com sucesso!');
                    window.location.reload();
                }} else {{
                    alert(data.message || 'Erro ao vincular');
                }}
            }} catch (e) {{
                alert('Erro na requisição: ' + e.message);
            }}
        }}

        function startCloudSyncPolling() {{
            const pullTelemetry = async () => {{
                try {{
                    const res = await fetch('/api/cloud/sync/pull');
                    const json = await res.json();
                    if (json.status === 'success' && json.data) {{
                        const d = json.data;
                        const pulse = document.getElementById('cloudPulse');
                        if (pulse) pulse.classList.remove('offline');

                        const lbl = document.getElementById('cloudDeviceLabel');
                        if (lbl && (json.computer_id || d.computer_id)) {{
                            lbl.innerHTML = '<strong>PC:</strong> ' + (json.computer_id || d.computer_id);
                        }}

                        // Alimenta gráfico Chart.js Telemetria de Host (CPU % & RAM %)
                        if (d.health && typeof pushTelemetryDataPoint === 'function') {{
                            pushTelemetryDataPoint(d.health.cpu_percent || 0, d.health.memory_percent || 0);
                        }}

                        // Alimenta taxa de eventos Throughput
                        if (d.recent_events && typeof pushEventThroughput === 'function') {{
                            pushEventThroughput(d.recent_events.length || 1);
                        }}

                        // Atualiza valores nas métricas se disponíveis
                        const cpuLive = document.getElementById('cpuLiveVal');
                        if (cpuLive && d.health) cpuLive.innerText = (d.health.cpu_percent || 0) + '%';
                        const ramLive = document.getElementById('ramLiveVal');
                        if (ramLive && d.health) ramLive.innerText = (d.health.memory_percent || 0) + '%';
                    }}
                }} catch (e) {{}}
            }};

            pullTelemetry();
            setInterval(pullTelemetry, 3500);
        }}
    </script>
    """

    if "</head>" in content:
        content = content.replace("</head>", f"{cloud_context_script}\n</head>", 1)
    elif "</body>" in content:
        content = content.replace("</body>", f"{cloud_context_script}\n</body>", 1)


    resp = make_response(content, 200)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

@app.route("/assets/<path:filename>", methods=["GET"])
def serve_assets(filename):
    if ASSETS_DIR.exists():
        return send_from_directory(str(ASSETS_DIR), filename)
    return "Asset não encontrado", 404

@app.route("/favicon.ico", methods=["GET"])
def favicon():
    if (ASSETS_DIR / "sentinel_icon.ico").exists():
        return send_from_directory(str(ASSETS_DIR), "sentinel_icon.ico", mimetype="image/vnd.microsoft.icon")
    return "", 204

# ==============================================================================
# ROTAS DA API DE AUTENTICAÇÃO CLOUD
# ==============================================================================

@app.route("/api/cloud/auth/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    computer_id = data.get("computer_id", "").strip().upper()

    if not email or not password:
        return jsonify({"status": "error", "message": "Email e senha são obrigatórios"}), 400

    pwd_hash = hash_password(password)

    try:
        user_id = 1
        # Tenta persistir no PostgreSQL oficial primeiro
        if pg_manager:
            try:
                pg_u = pg_manager.get_user_by_email(email)
                if pg_u:
                    user_id = pg_u["id"]
                else:
                    new_uid = pg_manager.create_user(email, pwd_hash)
                    if new_uid:
                        user_id = new_uid
            except Exception:
                pass

        # Fallback local SQLite
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("SELECT id FROM users WHERE email = ?", (email,))
                existing = cur.fetchone()
                if existing:
                    user_id = existing["id"]
                else:
                    cur.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, pwd_hash))
                    user_id = cur.lastrowid
                    conn.commit()
        except Exception:
            pass

        token = generate_user_token(user_id, email, computer_id)
        sync_token = generate_device_token(user_id, email, computer_id or "SENT-ENDPOINT")
        linked_device = None

        if computer_id:
            if pg_manager:
                try:
                    pg_manager.upsert_device(user_id, computer_id, "PC-Vinculado", "Windows", sync_token)
                except Exception:
                    pass

            try:
                with get_db() as conn:
                    cur = conn.cursor()
                    cur.execute("""
                        INSERT INTO devices (user_id, computer_id, hostname, os_name, sync_token, last_seen)
                        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                        ON CONFLICT(computer_id) DO UPDATE SET user_id=excluded.user_id, sync_token=excluded.sync_token
                    """, (user_id, computer_id, "PC-Vinculado", "Windows", sync_token))
                    conn.commit()
            except Exception:
                pass
            
            linked_device = {
                "computer_id": computer_id,
                "sync_token": sync_token,
                "hostname": "PC-Vinculado"
            }

        resp = make_response(jsonify({
            "status": "success",
            "message": "Conta criada com sucesso!",
            "token": token,
            "user": {"id": user_id, "email": email},
            "active_device": linked_device
        }))
        resp.set_cookie("sentinel_cloud_token", token, max_age=86400 * 30, httponly=False, samesite="Lax", secure=True, path="/")
        return resp
    except Exception as e:
        return jsonify({"status": "error", "message": f"Erro interno ao registrar: {str(e)}"}), 500

@app.route("/api/cloud/auth/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"status": "error", "message": "Email e senha são obrigatórios"}), 400

    pwd_hash = hash_password(password)

    try:
        user_id = 1
        active_comp_id = ""
        devices = []

        # 1. Consulta no PostgreSQL Oficial
        if pg_manager:
            try:
                pg_u = pg_manager.get_user_by_email(email)
                if pg_u:
                    if pg_u["password_hash"] != pwd_hash:
                        return jsonify({"status": "error", "message": "Email ou senha incorretos"}), 401
                    user_id = pg_u["id"]
                    pg_devs = pg_manager.get_devices(user_id)
                    if pg_devs:
                        devices = pg_devs
                        active_comp_id = devices[0]["computer_id"]
            except Exception:
                pass

        # 2. Fallback local SQLite se não encontrado no PG
        if not devices:
            try:
                with get_db() as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT id, email, password_hash FROM users WHERE email = ?", (email,))
                    row = cur.fetchone()
                    if row:
                        if row["password_hash"] != pwd_hash:
                            return jsonify({"status": "error", "message": "Email ou senha incorretos"}), 401
                        user_id = row["id"]
                        cur.execute("SELECT computer_id, hostname, os_name, sync_token, last_seen FROM devices WHERE user_id = ?", (user_id,))
                        devices = [dict(d) for d in cur.fetchall()]
                        if devices:
                            active_comp_id = devices[0]["computer_id"]
            except Exception:
                pass

        token = generate_user_token(user_id, email, active_comp_id)

        resp = make_response(jsonify({
            "status": "success",
            "message": "Autenticado com sucesso",
            "token": token,
            "user": {"id": user_id, "email": email},
            "devices": devices,
            "active_device": devices[0] if devices else None
        }))
        resp.set_cookie("sentinel_cloud_token", token, max_age=86400 * 30, httponly=False, samesite="Lax", secure=True, path="/")
        return resp
    except Exception as e:
        return jsonify({"status": "error", "message": f"Erro interno ao autenticar: {str(e)}"}), 500

@app.route("/api/cloud/auth/logout", methods=["POST", "GET"])
def logout():
    resp = make_response(redirect("/login"))
    resp.delete_cookie("sentinel_cloud_token", path="/")
    return resp

@app.route("/api/cloud/auth/me", methods=["GET"])
@login_required
def me():
    user = get_current_user()
    devices = []
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("SELECT computer_id, hostname, os_name, sync_token, created_at, last_seen FROM devices WHERE user_id = ?", (user["user_id"],))
            devices = [dict(d) for d in cur.fetchall()]
    except Exception:
        pass
        
    if not devices and user.get("computer_id"):
        devices = [{
            "computer_id": user["computer_id"],
            "hostname": "PC-Vinculado",
            "os_name": "Windows",
            "sync_token": generate_device_token(user["user_id"], user["email"], user["computer_id"]),
            "online": True
        }]

    return jsonify({
        "status": "success",
        "user": user,
        "devices": devices
    })

# ==============================================================================
# VINCULAÇÃO DE DISPOSITIVOS & PAREAMENTO
# ==============================================================================

@app.route("/api/cloud/devices/link", methods=["POST"])
@login_required
def link_device():
    user = get_current_user()
    data = request.get_json() or {}
    computer_id = data.get("computer_id", "").strip().upper()
    hostname = data.get("hostname", "Endpoint-Soberano").strip()
    os_name = data.get("os_name", "Windows").strip()

    if not computer_id:
        return jsonify({"status": "error", "message": "ID do Computador é obrigatório"}), 400

    sync_token = generate_device_token(user["user_id"], user["email"], computer_id)

    if pg_manager:
        try:
            pg_manager.upsert_device(user["user_id"], computer_id, hostname, os_name, sync_token)
        except Exception:
            pass

    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO devices (user_id, computer_id, hostname, os_name, sync_token, last_seen)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(computer_id) DO UPDATE SET 
                    user_id=excluded.user_id, 
                    hostname=excluded.hostname, 
                    os_name=excluded.os_name, 
                    sync_token=excluded.sync_token,
                    last_seen=CURRENT_TIMESTAMP
            """, (user["user_id"], computer_id, hostname, os_name, sync_token))
            conn.commit()
    except Exception:
        pass

    return jsonify({
        "status": "success",
        "message": f"Computador {computer_id} vinculado à sua conta!",
        "computer_id": computer_id,
        "sync_token": sync_token
    })

@app.route("/api/cloud/devices", methods=["GET"])
@login_required
def list_devices():
    user = get_current_user()
    rows = []

    if pg_manager:
        try:
            pg_rows = pg_manager.get_devices(user["user_id"])
            if pg_rows:
                rows = pg_rows
        except Exception:
            pass

    if not rows:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("SELECT computer_id, hostname, os_name, sync_token, created_at, last_seen FROM devices WHERE user_id = ?", (user["user_id"],))
                rows = [dict(d) for d in cur.fetchall()]
        except Exception:
            pass
        
    if not rows and user.get("computer_id"):
        rows = [{
            "computer_id": user["computer_id"],
            "hostname": "PC-Vinculado",
            "os_name": "Windows",
            "sync_token": generate_device_token(user["user_id"], user["email"], user["computer_id"]),
            "last_seen": "Agora",
            "online": True
        }]

    now = datetime.datetime.now()
    for d in rows:
        last_seen = d.get("last_seen")
        is_online = False
        if last_seen:
            try:
                dt = datetime.datetime.fromisoformat(last_seen.replace(" ", "T"))
                if (now - dt).total_seconds() < 90:
                    is_online = True
            except Exception:
                is_online = True
        d["online"] = is_online
        
    return jsonify({"status": "success", "devices": rows})

# ==============================================================================
# SINCRONIZAÇÃO DE TELEMETRIA EM TEMPO REAL (AGENT -> VERCEL CLOUD)
# ==============================================================================

@app.route("/api/cloud/sync/push", methods=["POST"])
def sync_push():
    """Recebe pacote de telemetria do aplicativo Sentinela rodando no Windows."""
    sync_token = request.headers.get("X-Sentinel-Sync-Token") or request.headers.get("Authorization", "").replace("Bearer ", "")
    data = request.get_json() or {}
    computer_id = data.get("computer_id", "").strip().upper()

    if not sync_token or not computer_id:
        return jsonify({"status": "error", "message": "Credenciais de sincronização ou ID ausentes"}), 401

    auth_info = verify_token(sync_token)
    if not auth_info:
        # Fallback legado para sqlite
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("SELECT id, user_id FROM devices WHERE computer_id = ? AND sync_token = ?", (computer_id, sync_token))
                dev = cur.fetchone()
                if dev:
                    auth_info = {"user_id": dev["user_id"]}
        except Exception:
            pass

    if not auth_info:
        return jsonify({"status": "error", "message": "Dispositivo não autorizado ou token inválido"}), 403

    user_id = auth_info.get("user_id", 1)

    # 1. Armazena no PostgreSQL Oficial
    if pg_manager:
        try:
            pg_manager.save_telemetry_snapshot(computer_id, data)
        except Exception:
            pass

    # 2. Armazena no banco local sqlite se disponível
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO devices (user_id, computer_id, hostname, os_name, sync_token, last_seen)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(computer_id) DO UPDATE SET last_seen=CURRENT_TIMESTAMP
            """, (user_id, computer_id, data.get("hostname", "Windows-Endpoint"), data.get("os", "Windows"), sync_token))

            snapshot_str = json.dumps(data, ensure_ascii=False)
            cur.execute("""
                INSERT INTO telemetry (computer_id, snapshot_json, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(computer_id) DO UPDATE SET snapshot_json=excluded.snapshot_json, updated_at=CURRENT_TIMESTAMP
            """, (computer_id, snapshot_str))

            events = data.get("recent_events", [])
            for ev in events[:20]:
                cur.execute("""
                    INSERT INTO audit_events (computer_id, event_type, severity, description, payload_json)
                    VALUES (?, ?, ?, ?, ?)
                """, (computer_id, ev.get("type", "SECURITY"), ev.get("severity", "MEDIUM"), ev.get("description", ""), json.dumps(ev)))

            conn.commit()
    except Exception:
        pass

    # 3. Publica no canal cloud relay pub/sub para persistência distribuída entre instâncias
    push_telemetry_to_relay(user_id, data)

    return jsonify({"status": "success", "message": "Telemetria sincronizada com a nuvem Sentinela"})

@app.route("/api/cloud/sync/pull", methods=["GET"])
@login_required
def sync_pull():
    """Retorna a telemetria sincronizada do dispositivo ativo."""
    user = get_current_user()
    computer_id = request.args.get("computer_id") or user.get("computer_id")

    telemetry_data = None
    updated_at = "Recentemente"

    # 1. Tenta recuperar do PostgreSQL Oficial
    if pg_manager and computer_id:
        try:
            pg_res = pg_manager.get_telemetry_snapshot(computer_id)
            if pg_res:
                telemetry_data, updated_at = pg_res
        except Exception:
            pass

    # 2. Tenta recuperar do banco de dados local SQLite
    if not telemetry_data:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                if not computer_id:
                    cur.execute("SELECT computer_id FROM devices WHERE user_id = ? ORDER BY last_seen DESC LIMIT 1", (user["user_id"],))
                    row = cur.fetchone()
                    if row:
                        computer_id = row["computer_id"]

                if computer_id:
                    cur.execute("SELECT snapshot_json, updated_at FROM telemetry WHERE computer_id = ?", (computer_id,))
                    row = cur.fetchone()
                    if row:
                        telemetry_data = json.loads(row["snapshot_json"])
                        updated_at = row["updated_at"]
        except Exception:
            pass

    # 3. Se ainda não possui o snapshot, recupera do pub/sub cloud relay
    if not telemetry_data:
        relay_snapshot = pull_telemetry_from_relay(user["user_id"])
        if relay_snapshot:
            telemetry_data = relay_snapshot
            computer_id = relay_snapshot.get("computer_id", computer_id)
            updated_at = "Agora (Cloud Relay)"


    if not telemetry_data:
        return jsonify({
            "status": "waiting",
            "computer_id": computer_id or "SENT-LOCAL",
            "message": "Aguardando envio de telemetria do computador local...",
            "data": None
        })

    return jsonify({
        "status": "success",
        "computer_id": computer_id,
        "updated_at": updated_at,
        "data": telemetry_data
    })

@app.route("/api/cloud/db/status", methods=["GET"])
def cloud_db_status():
    """Retorna o status da conexão com o banco de dados oficial PostgreSQL."""
    if not pg_manager:
        return jsonify({
            "status": "disabled",
            "message": "Módulo PostgreSQL não carregado",
            "connected": False
        })
    st = pg_manager.get_status()
    return jsonify({
        "status": "connected" if st["connected"] else "unreachable",
        "database": st,
        "instructions": (
            "Se o status for 'unreachable', certifique-se de liberar a porta 5432 no firewall da VPS "
            "('sudo ufw allow 5432/tcp') e configurar listen_addresses = '*' no postgresql.conf."
        ) if not st["connected"] else "Banco de dados conectado e sincronizado com o Sentinela XDR!"
    })


# ==============================================================================
# PROXY & ENDPOINTS COMPATÍVEIS COM O DASHBOARD WEB
# ==============================================================================

def _get_active_telemetry_or_default():
    user = get_current_user()
    if not user:
        return None

    # 1. Tenta recuperar do PostgreSQL oficial
    if pg_manager:
        try:
            devs = pg_manager.get_devices(user["user_id"])
            if devs:
                snap = pg_manager.get_telemetry_snapshot(devs[0]["computer_id"])
                if snap and snap[0]:
                    return snap[0]
        except Exception:
            pass

    # 2. Tenta recuperar do Cloud Relay pub/sub
    try:
        relay_snapshot = pull_telemetry_from_relay(user["user_id"])
        if relay_snapshot:
            return relay_snapshot
    except Exception:
        pass

    # 3. Tenta SQLite local
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("SELECT t.snapshot_json FROM devices d JOIN telemetry t ON d.computer_id = t.computer_id WHERE d.user_id = ? ORDER BY d.last_seen DESC LIMIT 1", (user["user_id"],))
            row = cur.fetchone()
            if row and row["snapshot_json"]:
                return json.loads(row["snapshot_json"])
    except Exception:
        pass

    return None

@app.route("/api/system/resources", methods=["GET"])
def api_system_resources():
    telemetry = _get_active_telemetry_or_default() or {}
    health = telemetry.get("health", {})
    stats = telemetry.get("stats", {})
    return jsonify({
        "status": "success",
        "cpu_percent": health.get("cpu_percent", 0.0),
        "memory_percent": health.get("memory_percent", 0.0),
        "disk_percent": health.get("disk_percent", 0.0),
        "processes_count": stats.get("monitored_processes", 0)
    })

@app.route("/api/status", methods=["GET"])
def api_status():
    telemetry = _get_active_telemetry_or_default() or {}
    return jsonify({
        "status": "ONLINE",
        "cloud_mode": True,
        "mode": "Sovereign Active Defense",
        "active_modules": 53,
        "telemetry": telemetry
    })

@app.route("/api/health", methods=["GET"])
def api_health():
    telemetry = _get_active_telemetry_or_default()
    if telemetry and "health" in telemetry:
        return jsonify(telemetry["health"])
    return jsonify({
        "status": "ONLINE",
        "cloud_mode": True,
        "mode": "Sovereign Cloud Console",
        "cpu_percent": 0.0,
        "memory_percent": 0.0,
        "active_modules": 53,
        "threats_blocked_today": 0
    })

@app.route("/api/stats", methods=["GET"])
def api_stats():
    telemetry = _get_active_telemetry_or_default()
    if telemetry and "stats" in telemetry:
        return jsonify(telemetry["stats"])
    return jsonify({
        "blocked_attacks": 0,
        "threat_score": 0,
        "active_traps": 24,
        "protected_files": 1280,
        "monitored_processes": 115,
        "status": "CONNECTED_CLOUD"
    })

@app.route("/api/events", methods=["GET"])
def api_events():
    user = get_current_user()
    if not user:
        return jsonify([])
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT e.event_type, e.severity, e.description, e.timestamp, e.payload_json
            FROM audit_events e
            JOIN devices d ON e.computer_id = d.computer_id
            WHERE d.user_id = ?
            ORDER BY e.timestamp DESC LIMIT 50
        """, (user["user_id"],))
        rows = [dict(r) for r in cur.fetchall()]
    return jsonify(rows)

@app.route("/api/threats", methods=["GET"])
def api_threats():
    telemetry = _get_active_telemetry_or_default()
    if telemetry and "threats" in telemetry:
        return jsonify(telemetry["threats"])
    return jsonify({"threats": [], "count": 0})

@app.route("/api/processes", methods=["GET"])
def api_processes():
    telemetry = _get_active_telemetry_or_default()
    if telemetry and "processes" in telemetry:
        return jsonify(telemetry["processes"])
    return jsonify([])

# Exportação do objeto Flask app para o Vercel Serverless
# Vercel detecta a variável top-level `app`
__all__ = ["app"]

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
