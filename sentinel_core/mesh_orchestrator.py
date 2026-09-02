# sentinel_core/mesh_orchestrator.py
import time
import json
import logging
from typing import List, Dict, Any, Optional

class DefensiveMeshOrchestrator:
    """
    Gerencia a comunicação P2P defensiva entre instâncias do Sentinela.
    Permite que ameaças identificadas em uma máquina sejam compartilhadas para 
    imunizar os outros nós da rede em tempo real.
    """

    def __init__(self, node_id: str = "node_local", logger=None):
        self.node_id = node_id
        self.logger = logger
        self.known_peers: set = set()
        self.shared_threat_intel: Dict[str, Any] = {
            "blocked_ips": set(),
            "malicious_hashes": set()
        }

    def _log(self, level: str, category: str, action: str, msg: str):
        if self.logger:
            self.logger.log_event(level, category, action, msg)
        logging.info(f"[{category}] {msg}")

    def register_peer(self, peer_address: str):
        """Adiciona um novo nó confiável à rede defensiva."""
        self.known_peers.add(peer_address)
        self._log("INFO", "MESH_DEFENSE", "PEER_REGISTERED", f"Novo nó defensivo registrado: {peer_address}")

    def broadcast_threat(self, threat_type: str, indicator: str) -> Dict[str, Any]:
        """Prepara e envia um pacote de imunização de ameaça para a malha."""
        packet = {
            "origin_node": self.node_id,
            "threat_type": threat_type,  # 'IP' ou 'HASH'
            "indicator": indicator,
            "timestamp": time.time()
        }

        if threat_type.upper() == "IP":
            self.shared_threat_intel["blocked_ips"].add(indicator)
        elif threat_type.upper() == "HASH":
            self.shared_threat_intel["malicious_hashes"].add(indicator)

        self._log("WARNING", "MESH_DEFENSE", "INTEL_BROADCAST", 
                  f"Transmitindo inteligência defensiva ({threat_type}: {indicator}) para {len(self.known_peers)} nós.")
        return packet

    def receive_threat_intel(self, packet: Dict[str, Any]):
        """Processa dados de imunização recebidos de outro nó defensivo."""
        origin = packet.get("origin_node")
        ttype = packet.get("threat_type", "").upper()
        indicator = packet.get("indicator")

        if ttype == "IP":
            self.shared_threat_intel["blocked_ips"].add(indicator)
        elif ttype == "HASH":
            self.shared_threat_intel["malicious_hashes"].add(indicator)

        self._log("INFO", "MESH_DEFENSE", "INTEL_RECEIVED", 
                  f"Imunização recebida do nó '{origin}' -> Bloqueado {ttype}: {indicator}")
