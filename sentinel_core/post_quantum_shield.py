# sentinel_core/post_quantum_shield.py
"""
Camada de Criptografia Pós-Quântica (PQC) NIST REAL para o Sentinela XDR.

Baseada nas primitivas padronizadas FIPS 203 (ML-KEM-1024 / Kyber) e
FIPS 204 (ML-DSA-87 / Dilithium), fornecidas pela biblioteca `cryptography`
(backend Rust/OpenSSL). Não se trata mais de simulação por SHA3/HMAC:

  * KEM: encapsulamento/decapsulamento assimétrico real de segredo (32 B),
    com chave pública de 1568 B e ciphertext de 1568 B.
  * Assinatura: ML-DSA-87 real com verificação por chave pública (2592 B)
    e assinaturas de 4627 B — não-repúdio de comandos SOAR sem HMAC.

Preserva a interface original (agent_id, public_key, encapsulate_shared_secret,
sign_command_pqc, verify_command_pqc, encrypt/decrypt_telemetry_pqc, sign_data)
para não quebrar consumidores existentes (API, SOAR, multiagente).
"""
import json
import base64
import hashlib
import logging
import os as _os
import time
from typing import Dict, Any, Tuple

from sentinel_core.pqc_nist import PQCNISTEngine, KEM_PARAM, DSA_PARAM

logger = logging.getLogger("SentinelaXDR.PostQuantum")

SIGNATURE_PREFIX = "PQC_MLDSA87_V1"


class PostQuantumShield:
    """Escudo Pós-Quântico NIST — implementação real com ML-KEM-1024 e ML-DSA-87."""

    def __init__(self, agent_id: str, private_key_seed: bytes = None,
                 signature_seed: bytes = None):
        """
        Inicializa o escudo gerando (ou restaurando, se `*_seed` forem fornecidos)
        os pares de chaves ML-KEM-1024 (KEM) e ML-DSA-87 (assinatura).
        """
        self.agent_id = str(agent_id)
        self.algorithm_kem = KEM_PARAM
        self.algorithm_dsa = DSA_PARAM

        # --- Par de chaves ML-KEM-1024 (KEM) ---
        if private_key_seed:
            self._kem_private_key = PQCNISTEngine.deserialize_private_key(private_key_seed)
        else:
            self._kem_private_key, _ = PQCNISTEngine.generate_kem_keypair()
        self.public_key = PQCNISTEngine.serialize_public_key(
            self._kem_private_key.public_key()
        )

        # --- Par de chaves ML-DSA-87 (assinatura) ---
        if signature_seed:
            self._dsa_private_key = PQCNISTEngine.deserialize_sign_private_key(signature_seed)
        else:
            self._dsa_private_key, _ = PQCNISTEngine.generate_signature_keypair()
        self.signature_public_key = PQCNISTEngine.serialize_sign_public_key(
            self._dsa_private_key.public_key()
        )

        logger.info(
            f"🔮 [PQC SHIELD] Motor Pós-Quântico REAL ativado para o agente: {self.agent_id} "
            f"({self.algorithm_kem} + {self.algorithm_dsa})"
        )

    # ------------------------------------------------------------------
    # Persistência / Reconstruction
    # ------------------------------------------------------------------
    def get_kem_private_seed(self) -> bytes:
        """Seed de 64 bytes para reconstrução da chave privada ML-KEM."""
        return PQCNISTEngine.serialize_private_key(self._kem_private_key)

    def get_dsa_private_seed(self) -> bytes:
        """Seed de 32 bytes para reconstrução da chave privada ML-DSA."""
        return PQCNISTEngine.serialize_sign_private_key(self._dsa_private_key)

    # ------------------------------------------------------------------
    # KEM — compartilhamento de segredo com nó remoto
# ------------------------------------------------------------------
    # Assinatura digital ML-DSA-87 (Dilithium real)
    # ------------------------------------------------------------------
    def sign_command_pqc(self, command_payload: dict) -> str:
        """Assina um comando SOAR com ML-DSA-87 (não-repúdio por chave pública)."""
        raw_data = json.dumps(command_payload, sort_keys=True).encode()
        signature = PQCNISTEngine.sign(self._dsa_private_key, raw_data)
        signature_b64 = base64.b64encode(signature).decode()
        return f"{SIGNATURE_PREFIX}:{signature_b64}"

    def verify_command_pqc(self, command_payload: dict, signature: str,
                           public_key: bytes = None) -> bool:
        """
        Valida a assinatura ML-DSA de um comando. Por padrão usa a nossa própria
        chave pública; para verificar comandos de OUTROS nós, informe a chave
        pública do emissor em `public_key` (bytes RAW de 2592 B).
        """
        if not signature:
            return False
        if not (signature.startswith(f"{SIGNATURE_PREFIX}:") or signature.startswith("PQC_DILITHIUM_V1:")):
            return False
        try:
            signature_raw = base64.b64decode(signature.split(":", 1)[1])
        except Exception:
            return False
        raw_data = json.dumps(command_payload, sort_keys=True).encode()
        public_key_bytes = public_key or self.signature_public_key
        return PQCNISTEngine.verify(public_key_bytes, signature_raw, raw_data)

    def generate_lattice_log_hash(self, prev_hash: str, log_payload: dict) -> str:
        """
        Gera hash em cadeia (SHA3-256) com a chave pública PQC incorporada,
        garantindo imutabilidade da sequência de logs.
        """
        log_bytes = json.dumps(log_payload, sort_keys=True).encode()
        combined = prev_hash.encode() + log_bytes + self.public_key
        return "PQ_HASH_" + hashlib.sha3_256(combined).hexdigest()

    # ------------------------------------------------------------------
    # Telemetria criptografada AES-256-GCM com chave derivada do segredo PQC
    # ------------------------------------------------------------------
    def encrypt_telemetry_pqc(self, payload: Dict[str, Any], shared_secret: bytes) -> Dict[str, Any]:
        """
        Criptografa pacotes de telemetria sensíveis com AES-256-GCM (AEAD),
        chave derivada do segredo compartilhado PQC (PBKDF2-SHA256).

        Falha de cifra é tratada como erro (nunca degrada silenciosamente).
        """
        raw_data = json.dumps(payload, sort_keys=True).encode("utf-8")
        nonce = _os.urandom(12)

        derived_key = hashlib.pbkdf2_hmac("sha256", shared_secret, nonce, 10000, dklen=32)

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(derived_key)
        ciphertext = aesgcm.encrypt(nonce, raw_data, None)

        return {
            "pqc_protected": True,
            "cipher": "AES-256-GCM",
            "nonce_b64": base64.b64encode(nonce).decode(),
            "ciphertext_b64": base64.b64encode(ciphertext).decode(),
            "quantum_hash": hashlib.sha3_384(ciphertext).hexdigest()
        }

    def decrypt_telemetry_pqc(self, encrypted_payload: Dict[str, Any], shared_secret: bytes) -> Dict[str, Any]:
        """Decifra pacotes protegidos por AES-256-GCM derivado de PQC."""
        nonce = base64.b64decode(encrypted_payload["nonce_b64"])
        ciphertext = base64.b64decode(encrypted_payload["ciphertext_b64"])
        derived_key = hashlib.pbkdf2_hmac("sha256", shared_secret, nonce, 10000, dklen=32)

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(derived_key)
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(decrypted_bytes.decode("utf-8"))

    def sign_data(self, data: Any) -> Dict[str, Any]:
        """Assina dados arbitrários usando o esquema PQC ML-DSA-87."""
        payload = {"data": str(data)}
        sig = self.sign_command_pqc(payload)
        return {
            "signature": sig,
            "pqc_algorithm": DSA_PARAM,
            "agent_id": self.agent_id,
            "timestamp": time.time()
        }

    def verify_signature(self, data: Any, signature: str) -> bool:
        """Verifica a assinatura PQC de dados arbitrários."""
        payload = {"data": str(data)}
        return self.verify_command_pqc(payload, signature)

    # Aliases de compatibilidade
    sign_soar_command = sign_command_pqc
    verify_soar_command_signature = verify_command_pqc
    # ------------------------------------------------------------------
    def encapsulate_shared_secret(self, server_public_key: bytes) -> Tuple[bytes, bytes]:
        """
        KEM Encapsulation (ML-KEM-1024 real): gera o segredo compartilhado
        e o ciphertext a ser enviado ao servidor.

        Retorna (shared_secret, ciphertext).
        """
        ciphertext, shared_secret = PQCNISTEngine.encapsulate(server_public_key)
        return shared_secret, ciphertext

    def decapsulate_shared_secret(self, ciphertext: bytes) -> bytes:
        """
        KEM Decapsulation (ML-KEM-1024 real): recupera o segredo a partir do
        ciphertext enviado pelo remetente (associado à nossa chave pública).
        """
        return PQCNISTEngine.decapsulate(self._kem_private_key, ciphertext)