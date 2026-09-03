# smoke_test_engines.py
"""Smoke test abrangente dos motores do Sentinela XDR via Flask test client.

Valida que todos os endpoints (motores/camadas) respondem sem erros 500.
"""
import sys
import os

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

os.environ.setdefault("PORT", "0")

from sentinel_api import app

# ------------------------------------------------------------------
# Definição dos endpoints GET esperados (sem payload)
# ------------------------------------------------------------------
GET_ENDPOINTS = [
    "/api/health",
    "/api/status",
    "/api/shield/config",
    "/api/threat_map",
    "/api/warroom",
    "/api/logs?limit=10",
    "/api/logs/filters",
    "/api/defense/mode",
    "/api/reports/forensic",
    "/api/stats",
    "/api/system/resources",
    "/api/firewall/list",
    "/api/intrusion/sensors",
    "/api/terms",
    "/api/autostart/status",
    "/api/pqc/status",
    "/api/zerotrust/status",
    "/api/ueba/status",
    "/api/edr/threats",
    "/api/kernel/integrity",
    "/api/mesh/status",
    "/api/cti/status",
    "/api/protection/diagnostics",
    "/api/system/audit",
    "/api/system/architecture",
    "/api/mitre/matrix",
    "/api/rollback/list",
    "/api/honeytokens/status",
    "/api/quarantine/list",
    "/api/ztna/status",
    "/api/functions/status",
    "/api/functions/list",
    "/api/functions/items?limit=50",
    "/api/functions/telemetry/summary",
    "/api/functions/alarms",
    "/api/functions/presets",
    "/api/identity-guard/status",
    "/api/identity-guard/audit-privileges",
    "/api/dlp/status",
    "/api/dlp/events",
    "/api/anti-exploit/status",
    "/api/anti-exploit/events",
    "/api/perimeter-guard/status",
    "/api/perimeter-guard/events",
    "/api/posture-guard/status",
    "/api/posture-guard/events",
    "/api/multiagent/agent_status",
]

# Endpoints com validação obrigatória de parâmetros (4xx esperado sem args)
# e que devem ser testados com parâmetro real.
PARAM_ENDPOINTS = [
    # (url, parametro, valor) — validação de rota e processamento
    ("/api/quarantine/inspect", "file", "artifact_inexistente.bin"),
]

# POST endpoints (com payload seguro de exemplo)
POST_ENDPOINTS = [
    ("/api/firewall/block", {"ip": "192.0.2.250", "reason": "Teste"}),
    ("/api/firewall/unblock", {"ip": "192.0.2.250"}),
    ("/api/pqc/sign", {"message": "teste-forense"}),
    ("/api/memory/scan", {}),
    ("/api/zerotrust/inspect", {}),
    ("/api/ueba/evaluate", {}),
    ("/api/soar/playbook", {"playbook": "block_ip"}),
    ("/api/soar/shadow", {"action": "hold"}),
    ("/api/edr/remediate", {"pid": -1}),
    ("/api/ai/predict", {}),
    ("/api/scan_now", {}),
    ("/api/functions/evaluate", {"expression": 'last("system.cpu.util")'}),
    ("/api/functions/ingest", {"item_id": "smoke.metric", "value": 1}),
    ("/api/functions/clear", {}),
    ("/api/identity-guard/scan", {}),
    ("/api/dlp/inspect-text", {"text": "Este é um teste 123.456.789-09 sem dados reais."}),
    ("/api/dlp/scan-exfiltration", {}),
    ("/api/anti-exploit/simulate-exploit", {"kind": "hollowing"}),
    ("/api/perimeter-guard/audit-arp", {}),
    ("/api/posture-guard/audit-posture", {}),
]


def main():
    client = app.test_client()
    failures = []
    ok = 0

    print("=" * 78)
    print("SMOKE TEST DE MOTORES — SENTINEL XDR")
    print("=" * 78)

    for ep in GET_ENDPOINTS:
        try:
            r = client.get(ep)
            status = r.status_code
            ct = r.content_type or ""
            verdict = "OK" if status < 400 else "FAIL"
            if status >= 400:
                failures.append((ep, status))
            else:
                ok += 1
            print(f"  [GET ] {verdict:4s} {status}  {ep}")
        except Exception as e:
            failures.append((ep, f"EXC {e}"))
            print(f"  [GET ] FAIL  EXC {ep} -> {e}")

    for ep, payload in POST_ENDPOINTS:
        try:
            r = client.post(ep, json=payload)
            status = r.status_code
            verdict = "OK" if status < 400 else "FAIL"
            if status >= 400:
                failures.append((ep, status))
            else:
                ok += 1
            print(f"  [POST] {verdict:4s} {status}  {ep}")
        except Exception as e:
            failures.append((ep, f"EXC {e}"))
            print(f"  [POST] FAIL  EXC {ep} -> {e}")

    for ep, param, value in PARAM_ENDPOINTS:
        try:
            r = client.get(f"{ep}?{param}={value}")
            status = r.status_code
            # 400/404 = validação funcionando com rota ativa; 500 = falha real
            if status == 500:
                failures.append((ep, status))
            else:
                ok += 1
            print(f"  [PARAM] {'OK  ' if status < 500 else 'FAIL'} {status}  {ep}?{param}={value}")
        except Exception as e:
            failures.append((ep, f"EXC {e}"))
            print(f"  [PARAM] FAIL  EXC {ep} -> {e}")

    print("=" * 78)
    total = len(GET_ENDPOINTS) + len(POST_ENDPOINTS) + len(PARAM_ENDPOINTS)
    print(f"TOTAL: {total} | OK: {ok} | FALHAS: {len(failures)}")
    if failures:
        print("FALHAS DETALHADAS:")
        for ep, st in failures:
            print(f"  - {ep} -> {st}")
        sys.exit(1)
    print(">>> TODOS OS MOTORES OPERACIONAIS <<<")
    sys.exit(0)


if __name__ == "__main__":
    main()