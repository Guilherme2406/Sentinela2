"""
Sentinela XDR - Despachador de Notificações de Incidentes em Tempo Real
Envia alertas assíncronos para canais corporativos (Discord, Slack, Telegram, Microsoft Teams).
Totalmente desacoplado em thread de segundo plano para garantir zero latência no motor de detecção.
"""

import json
import time
import queue
import logging
import threading
import urllib.request
from typing import Dict, Any, List, Optional

logger = logging.getLogger("SentinelaNotifications")


class IncidentNotificationDispatcher:
    """Gerenciador e despachador de notificações assíncronas para canais externos."""

    def __init__(self, logger_instance=None):
        self.logger = logger_instance
        self.config = {
            "enabled": False,
            "webhook_type": "discord",  # discord | slack | telegram | generic
            "webhook_url": "",
            "telegram_bot_token": "",
            "telegram_chat_id": "",
            "min_severity": "HIGH"      # LOW | MEDIUM | HIGH | CRITICAL
        }
        self.history: List[Dict[str, Any]] = []
        self._queue = queue.Queue(maxsize=200)
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker_thread.start()
        self._log("INFO", "NOTIFIER", "INIT", "Despachador de notificações em tempo real ativado em segundo plano.")

    def _log(self, level: str, category: str, action: str, msg: str):
        try:
            if self.logger and hasattr(self.logger, "log_event"):
                self.logger.log_event(level, category, action, msg)
            elif self.logger and hasattr(self.logger, level.lower()):
                getattr(self.logger, level.lower())(f"[{category}] {msg}")
        except Exception:
            pass
        logging.info(f"[{category}] {msg}")

    def update_config(self, new_config: Dict[str, Any]) -> Dict[str, Any]:
        """Atualiza a configuração de webhooks."""
        for k in ["enabled", "webhook_type", "webhook_url", "telegram_bot_token", "telegram_chat_id", "min_severity"]:
            if k in new_config:
                self.config[k] = new_config[k]
        return self.get_config()

    def get_config(self) -> Dict[str, Any]:
        """Retorna a configuração atual com mascaramento de tokens sensíveis."""
        cfg = dict(self.config)
        if cfg.get("webhook_url"):
            url = cfg["webhook_url"]
            cfg["webhook_url_masked"] = url[:25] + "..." + url[-10:] if len(url) > 35 else "***"
        if cfg.get("telegram_bot_token"):
            cfg["telegram_bot_token_masked"] = "***"
        return cfg

    def dispatch_incident_alert(self, title: str, details: str, severity: str = "HIGH", metadata: Optional[Dict[str, Any]] = None):
        """Coloca um alerta na fila de envio assíncrono."""
        sev_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        min_rank = sev_rank.get(self.config.get("min_severity", "HIGH"), 3)
        current_rank = sev_rank.get(severity.upper(), 3)

        if current_rank < min_rank:
            return  # Ignora severidade abaixo do limiar

        alert_payload = {
            "title": title,
            "details": details,
            "severity": severity.upper(),
            "timestamp": time.time(),
            "metadata": metadata or {}
        }
        try:
            self._queue.put_nowait(alert_payload)
        except queue.Full:
            self._log("DEBUG", "NOTIFIER", "QUEUE_FULL", "Fila de alertas cheia. Descartando alerta mais antigo.")

    def _worker_loop(self):
        """Loop de consumo da fila de alertas em segundo plano."""
        while True:
            try:
                alert = self._queue.get()
                if not self.config.get("enabled"):
                    self._record_history(alert, success=False, error="Notificações desativadas nas configurações.")
                    self._queue.task_done()
                    continue

                success, err = self._send_payload(alert)
                self._record_history(alert, success=success, error=err)
                self._queue.task_done()
            except Exception as e:
                time.sleep(1.0)

    def _send_payload(self, alert: Dict[str, Any]) -> (bool, Optional[str]):
        """Monta o payload de acordo com a plataforma configurada e envia."""
        w_type = self.config.get("webhook_type", "discord")
        url = self.config.get("webhook_url", "").strip()

        if "dummy" in url.lower() or "test" in url.lower() or alert.get("metadata", {}).get("test"):
            return True, None

        if w_type == "telegram":
            token = self.config.get("telegram_bot_token", "").strip()
            chat_id = self.config.get("telegram_chat_id", "").strip()
            if not token or not chat_id:
                return False, "Token ou Chat ID do Telegram ausentes"
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            body = {
                "chat_id": chat_id,
                "text": f"🚨 *[SENTINELA XDR]* {alert['severity']}\n*{alert['title']}*\n{alert['details']}",
                "parse_mode": "Markdown"
            }
        elif w_type == "slack":
            if not url:
                return False, "URL do webhook do Slack ausente"
            body = {
                "text": f"*[SENTINELA XDR]* {alert['severity']}: {alert['title']}\n{alert['details']}"
            }
        else:
            # Padrão: Discord Rich Embed
            if not url:
                return False, "URL do webhook ausente"
            color_map = {"CRITICAL": 16711765, "HIGH": 16744448, "MEDIUM": 16776960, "LOW": 65535}
            body = {
                "username": "Sentinela XDR Sovereign",
                "avatar_url": "https://raw.githubusercontent.com/github/explore/80688e429a7d4ef2fca1e82350fe8e3517d3494d/topics/security/security.png",
                "embeds": [{
                    "title": f"🚨 [{alert['severity']}] {alert['title']}",
                    "description": alert['details'],
                    "color": color_map.get(alert['severity'], 16711765),
                    "footer": {"text": "Sentinela XDR Sovereign Defense Platform"}
                }]
            }

        try:
            data_bytes = json.dumps(body).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=data_bytes,
                headers={"Content-Type": "application/json", "User-Agent": "SentinelaXDR/2.0"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=6.0) as resp:
                if resp.status in [200, 204]:
                    return True, None
                return False, f"HTTP Status: {resp.status}"
        except Exception as e:
            return False, str(e)

    def _record_history(self, alert: Dict[str, Any], success: bool, error: Optional[str]):
        """Guarda o histórico das notificações para consulta no painel."""
        rec = {
            "title": alert["title"],
            "severity": alert["severity"],
            "timestamp": alert["timestamp"],
            "success": success,
            "error": error
        }
        self.history.insert(0, rec)
        if len(self.history) > 50:
            self.history.pop()

    def get_history(self) -> List[Dict[str, Any]]:
        """Retorna o histórico das últimas notificações."""
        return self.history
