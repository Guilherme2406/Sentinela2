# sentinel_core/pqc_nist.py
"""
Motor de Criptografia Pós-Quântica NIST REAL (FIPS 203 / FIPS 204).

Implementação baseada nas primitivas padronizadas pelo NIST:
  - ML-KEM-1024 (antes CRYSTALS-Kyber) ......... FIPS 203, nível de segurança 5
  - ML-DSA-87   (antes CRYSTALS-Dilithium) ..... FIPS 204, nível de segurança 5

Ao contrário do módulo anterior (que simulava chaves/assinaturas com SHA3/HMAC),
aqui as operações são executadas por primitivas assimétricas reais vetorizadas
na biblioteca `cryptography` (backend Rust/OpenSSL), com serialização RAW
cruzada, encapsulamento/decapsulamento de segredo compartilhado e assinatura
digital com verificação por chave pública.

Modo de uso (KEM entre dois nós):
  alice_priv, alice_pub = PQCNISTEngine.generate_kem_keypair()
  bob_priv,   bob_pub   = PQCNISTEngine.generate_kem_keypair()

  # Alice quer enviar um segredo a Bob (usa a chave pública de Bob):
  ct, ss_alice = PQCNISTEngine.encapsulate(PQCNISTEngine.serialize_public_key(bob_pub))
  ss_bob = PQCNISTEngine.decapsulate(bob_priv, ct)
  # ss_alice == ss_bob ✓

Modo de uso (assinatura digital ML-DSA):
  spriv, spub = PQCNISTEngine.generate_signature_keypair()
  sig = PQCNISTEngine.sign(spriv, dados)
  ok = PQCNISTEngine.verify(PQCNISTEngine.serialize_sign_public_key(spub), sig, dados)
"""

import logging
from typing import Tuple, Type

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mlkem, mldsa
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger("SentinelaXDR.PQCNIST")

# ---------------------------------------------------------------------------
# Parâmetros NIST adotados (grau máximo de segurança)
# ---------------------------------------------------------------------------
KEM_PRIVATE_CLASS: Type = mlkem.MLKEM1024PrivateKey
KEM_PUBLIC_CLASS: Type = mlkem.MLKEM1024PublicKey
KEM_PARAM = "ML-KEM-1024 (FIPS 203, nível 5)"

DSA_PRIVATE_CLASS: Type = mldsa.MLDSA87PrivateKey
DSA_PUBLIC_CLASS: Type = mldsa.MLDSA87PublicKey
DSA_PARAM = "ML-DSA-87 (FIPS 204, nível 5)"


class PQCNISTEngine:
    """Primitivas criptográficas pós-quânticas NIST reais (stateless)."""

    # ------------------------------------------------------------------ KEM
    @staticmethod
    def generate_kem_keypair():
        """Gera um par de chaves ML-KEM-1024 real."""
        private_key = KEM_PRIVATE_CLASS.generate()
        return private_key, private_key.public_key()

    @staticmethod
    def serialize_public_key(public_key) -> bytes:
        """Serializa a chave pública ML-KEM no formato RAW (1568 bytes)."""
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @staticmethod
    def serialize_private_key(private_key) -> bytes:
        """Serializa a chave privada ML-KEM no formato RAW (3168 bytes)."""
        return private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @staticmethod
    def deserialize_public_key(raw: bytes):
        """Reconstrói a chave pública ML-KEM a partir de bytes RAW."""
        return KEM_PUBLIC_CLASS.from_public_bytes(raw)

    @staticmethod
    def deserialize_private_key(raw: bytes):
        """Reconstrói a chave privada ML-KEM a partir do seed RAW (64 bytes)."""
        return KEM_PRIVATE_CLASS.from_seed_bytes(raw)

    @staticmethod
    def encapsulate(peer_public_key_bytes: bytes) -> Tuple[bytes, bytes]:
        """
        Realiza o KEM encapsulation para a chave pública do nó parceiro.

        Retorna (ciphertext, shared_secret). O ciphertext deve ser enviado ao
        detentor da chave privada correspondente; ambos derivam o mesmo segredo.
        """
        peer_pk = KEM_PUBLIC_CLASS.from_public_bytes(peer_public_key_bytes)
        # NOTA: nesta versão do cryptography, encapsulate() retorna
        # (shared_secret, ciphertext). Normalizamos para (ciphertext, shared_secret).
        shared_secret, ciphertext = peer_pk.encapsulate()
        return ciphertext, shared_secret

    @staticmethod
    def decapsulate(private_key, ciphertext: bytes) -> bytes:
        """Recupera o shared_secret a partir do ciphertext recebido."""
        return private_key.decapsulate(ciphertext)

    # --------------------------------------------------------------- ML-DSA
    @staticmethod
    def generate_signature_keypair():
        """Gera um par de chaves ML-DSA-87 real (FIPS 204)."""
        private_key = DSA_PRIVATE_CLASS.generate()
        return private_key, private_key.public_key()

    @staticmethod
    def serialize_sign_public_key(public_key) -> bytes:
        """Serializa a chave pública ML-DSA no formato RAW (2592 bytes)."""
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @staticmethod
    def serialize_sign_private_key(private_key) -> bytes:
        """Serializa a chave privada ML-DSA no formato RAW (4896 bytes)."""
        return private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @staticmethod
    def deserialize_sign_public_key(raw: bytes):
        """Reconstrói a chave pública ML-DSA a partir de bytes RAW (2592 bytes)."""
        return DSA_PUBLIC_CLASS.from_public_bytes(raw)

    @staticmethod
    def deserialize_sign_private_key(raw: bytes):
        """Reconstrói a chave privada ML-DSA a partir do seed RAW (32 bytes)."""
        return DSA_PRIVATE_CLASS.from_seed_bytes(raw)

    @staticmethod
    def sign(private_key, data: bytes) -> bytes:
        """Assina os dados com ML-DSA-87."""
        return private_key.sign(data)

    @staticmethod
    def verify(public_key_bytes: bytes, signature: bytes, data: bytes) -> bool:
        """
        Verifica a assinatura ML-DSA com a chave pública do assinante.

        Retorna True se válida; False para assinatura inválida, mensagem
        adulterada ou formato incorreto (nunca levanta em dados maliciosos).
        """
        try:
            public_key = DSA_PUBLIC_CLASS.from_public_bytes(public_key_bytes)
            public_key.verify(signature, data)
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False
        except Exception as exc:  # pragma: no cover - defesa em profundidade
            logger.debug(f"[PQCNIST] Falha ao verificar assinatura: {exc}")
            return False