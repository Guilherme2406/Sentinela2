# sentinel_core/threat_intel.py
"""
Cyber Threat Intelligence (CTI) — feeds GLOBAIS REAIS com cache offline.

Substitui a base mockada (5 IPs hardcoded) por sincronização com feeds
públicos reais, com degradação graciosa para cache local:

  * lists.blocklist.de    -> IPs de botnets/scanners/brute force (texto puro)
  * urlhaus.abuse.ch      -> URLs maliciosas recentes (IPs extraídos)

A interface pública é preservada (check_ip_reputation, is_ip_blacklisted,
sync_global_feeds, sync_feeds, start_auto_sync, get_status) para não quebrar
API, instalador, serviço e dashboard. Em modo offline, opera com o cache
local persistido em `sentinel_vault/cti_cache.json` e nunca levanta exceção.
"""
import ipaddress
import json
import logging
import os
import time
import urllib.request
from typing import Dict, Any, Optional

CTI_FEEDS = {
    "blocklist_de_all": "https://lists.blocklist.de/lists/all.txt",
    "urlhaus_recent": "https://urlhaus.abuse.ch/downloads/csv_recent/",
}

USER_AGENT = "Sentinela-XDR/2.0 (Cyber Threat Intelligence collector)"
MAX_FEED_BYTES = 40 * 1024 * 1024  # proteção contra download gigante


def _is_public_ip(text: str) -> Optional[str]:
    """Valida se a string é um IPv4/IPv6 público e utilizável como IOC."""
    text = (text or "").strip()
    if not text:
        return None
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    if addr.is_global and not addr.is_multicast:
        return str(addr)
    return None


class ThreatIntelFeed:
    """
    Módulo de Cyber Threat Intelligence (CTI).
    Verifica reputação global de IPs contra bases conhecidas de botnets e
    ataques, alimentadas por feeds públicos reais + cache local.
    """

    SEED_IPS = {
        "185.220.101.5": {"risk": "HIGH", "category": "Tor Exit Node", "country": "DE", "source": "seed"},
        "45.146.164.110": {"risk": "CRITICAL", "category": "Ransomware C2", "country": "RU", "source": "seed"},
        "193.142.146.35": {"risk": "HIGH", "category": "Brute Force Scanner", "country": "NL", "source": "seed"},
        "45.154.255.120": {"risk": "CRITICAL", "category": "CobaltStrike C2", "country": "RU", "source": "seed"},
        "91.240.118.172": {"risk": "HIGH", "category": "Mirai Botnet", "country": "UA", "source": "seed"},
    }

    def __init__(self, logger=None, firewall_manager=None, cache_dir: Optional[str] = None):
        self.logger = logger
        self.firewall_manager = firewall_manager
        self.known_malicious_ips = dict(self.SEED_IPS)

        if cache_dir is None:
            cache_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "sentinel_vault",
            )
        self.cache_path = os.path.join(cache_dir, "cti_cache.json")
        self.last_sync: Optional[float] = None
        self.feed_stats: Dict[str, Any] = {}
        self._load_cache()

    # ------------------------------------------------------------------ cache
    def _load_cache(self):
        """Carrega a base CTI persistida localmente (funciona 100% offline)."""
        try:
            with open(self.cache_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            ips = data.get("ips", {})
            if isinstance(ips, dict) and ips:
                self.known_malicious_ips = {
                    k: v for k, v in ips.items()
                    if isinstance(v, dict) and isinstance(k, str) and _is_public_ip(k)
                }
                self.last_sync = data.get("last_sync")
                logging.info(
                    f"[CTI] Cache local carregado: {len(self.known_malicious_ips)} IOCs "
                    f"(último sync: {time.ctime(self.last_sync) if self.last_sync else 'nunca'})"
                )
            self.feed_stats = data.get("feed_stats", {}) or {}
        except FileNotFoundError:
            pass  # primeiro uso — sem cache ainda
        except Exception as exc:
            logging.debug(f"[CTI] Falha ao carregar cache local: {exc}")

    def _save_cache(self):
        try:
            parent = os.path.dirname(self.cache_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(self.cache_path, "w", encoding="utf-8") as f:
                json.dump({
                    "ips": self.known_malicious_ips,
                    "last_sync": self.last_sync,
                    "feed_stats": self.feed_stats,
                }, f)
        except Exception as exc:
            logging.debug(f"[CTI] Falha ao persistir cache local: {exc}")

    # ------------------------------------------------------------------- http
    def _http_get(self, url: str, timeout: int = 20) -> str:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(MAX_FEED_BYTES + 1)
            if len(raw) > MAX_FEED_BYTES:
                raise ValueError("resposta do feed excede o limite de segurança")
            return raw.decode("utf-8", errors="replace")

    # ------------------------------------------------------------------ feeds
    def _ingest_feed(self, name: str, text: str) -> str:
        """Ingere IPs de um feed textual. Retorna o nome do feed (para stats)."""
        if name == "blocklist_de_all":
            for line in text.splitlines():
                ip = _is_public_ip(line)
                if ip and ip not in self.known_malicious_ips:
                    self.known_malicious_ips[ip] = {
                        "risk": "HIGH",
                        "category": "Botnet/Scanner/Brute-force",
                        "country": "UNKNOWN",
                        "source": "blocklist.de",
                    }
        elif name == "urlhaus_recent":
            for line in text.splitlines():
                if not line or line.startswith("#"):
                    continue
                parts = [p.strip().strip('"') for p in line.split(",")]
                if len(parts) < 4:
                    continue
                try:
                    host = urllib.request.urlparse(parts[2]).hostname
                except Exception:
                    host = None
                ip = _is_public_ip(host or "")
                if ip and ip not in self.known_malicious_ips:
                    self.known_malicious_ips[ip] = {
                        "risk": "CRITICAL" if parts[3] == "online" else "HIGH",
                        "category": "URLhaus (malware URL host)",
                        "country": "UNKNOWN",
                        "source": "urlhaus.abuse.ch",
                    }
        return name

    def sync_global_feeds(self) -> int:
        """
        Sincroniza os feeds públicos de CTI.

        Nunca levanta: em caso de falha de rede, utiliza o cache local
        persistido e registra o modo degradado.
        """
        fetched = 0
        errors: list = []

        for name, url in CTI_FEEDS.items():
            try:
                text = self._http_get(url)
                added_before = len(self.known_malicious_ips)
                self._ingest_feed(name, text)
                added = len(self.known_malicious_ips) - added_before
                self.feed_stats[name] = {
                    "last_sync": time.time(),
                    "iocs_added": added,
                    "total_source": sum(
                        1 for v in self.known_malicious_ips.values()
                        if v.get("source") == name
                    ),
                }
                fetched += added
                logging.info(f"[CTI] Feed '{name}' sincronizado: +{added} IOCs.")
            except Exception as exc:
                errors.append(f"{name}: {exc}")
                logging.warning(f"[CTI] Feed '{name}' indisponível ({exc}) — usando cache/última base.")

        if fetched > 0:
            self.last_sync = time.time()
            self._save_cache()

        total = len(self.known_malicious_ips)
        if self.logger:
            try:
                level = "INFO" if (fetched > 0 or not errors) else "WARNING"
                self.logger.log_event(
                    level, "CTI_FEED", "SYNC",
                    f"Feed CTI sincronizado. {total} IOCs ativos (+{fetched} novos). "
                    f"Offline: {len(errors)} feed(s) indisponível(is).",
                )
            except Exception:
                pass
        logging.info(f"[+] Feed CTI: {total} IOCs ativos (+{fetched} novos, {len(errors)} erro(s)).")
        return total

    def sync_feeds(self) -> int:
        """Alias usado por instalador/API: sincroniza e retorna o total de IOCs."""
        return self.sync_global_feeds()

    # -------------------------------------------------------------- consulta
    def check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Consulta reputação do IP nas redes globais de inteligência."""
        if not ip or ip.startswith(("127.", "10.", "192.168.", "172.16.", "0.0.0.0", "localhost")):
            return {"ip": ip, "threat_score": 0, "status": "SAFE", "details": "Rede Interna"}

        if ip in self.known_malicious_ips:
            info = self.known_malicious_ips[ip]
            if self.logger:
                try:
                    self.logger.log_event(
                        "CRITICAL", "THREAT_INTEL", ip,
                        f"IP {ip} identificado na base CTI Global! Risco: {info['risk']} ({info['category']})",
                    )
                except Exception:
                    pass
            return {
                "ip": ip,
                "threat_score": 95,
                "status": "MALICIOUS",
                "category": info["category"],
                "country": info.get("country", "UNKNOWN"),
                "source": info.get("source", "unknown"),
            }

        return {"ip": ip, "threat_score": 5, "status": "CLEAN", "details": "Sem histórico de ataques recentes"}

    def is_ip_blacklisted(self, ip: str) -> bool:
        """Verifica se o IP está classificado como malicioso."""
        rep = self.check_ip_reputation(ip)
        return rep.get("status") == "MALICIOUS"

    # -------------------------------------------------------------- operacao
    def start_auto_sync(self, interval_seconds: int = 3600):
        """Loop de sincronização em segundo plano."""
        while True:
            try:
                self.sync_global_feeds()
            except Exception:
                pass
            time.sleep(max(interval_seconds, 60))

    def get_status(self) -> dict:
        return {
            "feeds_count": len(self.known_malicious_ips),
            "threat_database": "CTI_LIVE_FEEDS_AND_LOCAL_CACHE",
            "last_sync": self.last_sync,
            "feed_stats": self.feed_stats,
            "malicious_samples": list(self.known_malicious_ips.keys())[:20],
        }


# Alias de compatibilidade
GlobalThreatIntel = ThreatIntelFeed
ThreatIntelFeeds = ThreatIntelFeed


