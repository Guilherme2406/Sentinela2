# sentinel_core/ip_geolocator.py
import urllib.request
import json
import logging
import ipaddress
from typing import Dict, Any, Optional

class IPGeolocator:
    """
    Módulo de Geolocalização e Mapeamento de IPs de Ameaças.
    Enriquece IPs com País, Cidade, Organização (ISP), Latitude e Longitude.
    """

    def __init__(self):
        self._cache: Dict[str, Dict[str, Any]] = {}
        # IPs privados/locais não precisam de geolocalização externa
        self.private_ip_prefixes = ("127.", "10.", "192.168.", "172.16.", "172.31.", "0.0.0.0")

    def is_valid_ip(self, ip: str) -> bool:
        """Valida se uma string é um endereço IP válido (IPv4 ou IPv6)."""
        if not ip or not isinstance(ip, str):
            return False
        try:
            ipaddress.ip_address(ip.strip())
            return True
        except ValueError:
            return False

    def is_private_ip(self, ip: str) -> bool:
        """Verifica se o IP pertence à rede privada local."""
        if not self.is_valid_ip(ip):
            return True
        try:
            return ipaddress.ip_address(ip.strip()).is_private
        except ValueError:
            return any(ip.startswith(prefix) for prefix in self.private_ip_prefixes)

    def locate_ip(self, ip: str) -> Dict[str, Any]:
        """
        Retorna informações detalhadas de geolocalização para um IP específico.
        Utiliza cache interno para otimizar desempenho.
        """
        if not ip:
            return self._default_local("127.0.0.1")

        ip_clean = ip.strip()

        if not self.is_valid_ip(ip_clean) or self.is_private_ip(ip_clean):
            return self._default_local(ip_clean)

        if ip_clean in self._cache:
            return self._cache[ip_clean]

        try:
            url = f"http://ip-api.com/json/{ip_clean}?fields=status,country,city,isp,lat,lon,query"
            req = urllib.request.Request(url, headers={'User-Agent': 'SentinelXDR-Shield/2.0'})
            
            with urllib.request.urlopen(req, timeout=2) as response:
                data = json.loads(response.read().decode('utf-8'))
                
                if data.get("status") == "success":
                    geo_info = {
                        "ip": ip_clean,
                        "country": data.get("country", "Desconhecido"),
                        "city": data.get("city", "Desconhecido"),
                        "isp": data.get("isp", "Desconhecido"),
                        "lat": data.get("lat", 0.0),
                        "lon": data.get("lon", 0.0),
                        "is_local": False
                    }
                    self._cache[ip_clean] = geo_info
                    return geo_info
        except Exception as e:
            logging.debug(f"[GEOLOCATOR] Consulta externa para '{ip_clean}' indisponível: {e}")

        fallback_info = {
            "ip": ip_clean,
            "country": "Desconhecido",
            "city": "Desconhecido",
            "isp": "Desconhecido",
            "lat": 0.0,
            "lon": 0.0,
            "is_local": False
        }
        self._cache[ip_clean] = fallback_info
        return fallback_info

    def _default_local(self, ip: str) -> Dict[str, Any]:
        return {
            "ip": ip,
            "country": "Localhost / Rede Privada",
            "city": "Interno",
            "isp": "LAN",
            "lat": 0.0,
            "lon": 0.0,
            "is_local": True
        }

