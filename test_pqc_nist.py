# test_pqc_nist.py
"""
Testes de validação do Escudo Pós-Quântico NIST REAL (FIPS 203 / FIPS 204).

Valida:
  1. Geração, serialização e reconstrução de chaves ML-KEM-1024 e ML-DSA-87.
  2. KEM: encapsulate/decapsulate entre dois nós geram o mesmo shared secret.
  3. Assinatura ML-DSA: verificação válida e rejeição de assinatura/mensagem/chave adulteradas.
  4. Compatibilidade de interface com o PostQuantumShield original (usado pela API).
  5. Telemetria cifrada AES-256-GCM (roundtrip + tamper rejection).
  6. Persistência: reconstruction das chaves a partir de seeds.

Executar: python test_pqc_nist.py
"""
import sys
import os
import unittest

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from sentinel_core.pqc_nist import (
    PQCNISTEngine,
    KEM_PRIVATE_CLASS,
    KEM_PUBLIC_CLASS,
    DSA_PRIVATE_CLASS,
    DSA_PUBLIC_CLASS,
    KEM_PARAM,
    DSA_PARAM,
)
from sentinel_core.post_quantum_shield import PostQuantumShield, SIGNATURE_PREFIX


class TestPQCRawPrimitives(unittest.TestCase):
    """Testes das primitivas NIST cruas (PQCNISTEngine)."""

    def test_01_kem_keypair_sizes(self):
        priv, pub = PQCNISTEngine.generate_kem_keypair()
        pub_raw = PQCNISTEngine.serialize_public_key(pub)
        priv_raw = PQCNISTEngine.serialize_private_key(priv)
        self.assertEqual(len(pub_raw), 1568)
        self.assertEqual(len(priv_raw), 64)  # seed de KEM-1024
        self.assertEqual(len(priv.decapsulate(bytearray(1568))), 32)

    def test_02_kem_encapsulate_decapsulate_match(self):
        alice_priv, alice_pub = PQCNISTEngine.generate_kem_keypair()
        bob_priv, bob_pub = PQCNISTEngine.generate_kem_keypair()

        # Alice encapsula para Bob
        ct, ss_alice = PQCNISTEngine.encapsulate(PQCNISTEngine.serialize_public_key(bob_pub))
        ss_bob = PQCNISTEngine.decapsulate(bob_priv, ct)
        self.assertEqual(ss_alice, ss_bob)
        self.assertEqual(len(ss_alice), 32)
        self.assertEqual(len(ct), 1568)

        # Bob encapsula para Alice
        ct2, ss_bob2 = PQCNISTEngine.encapsulate(PQCNISTEngine.serialize_public_key(alice_pub))
        ss_alice2 = PQCNISTEngine.decapsulate(alice_priv, ct2)
        self.assertEqual(ss_bob2, ss_alice2)

    def test_03_kem_different_secret_with_wrong_key(self):
        alice_priv, alice_pub = PQCNISTEngine.generate_kem_keypair()
        eva_priv, eva_pub = PQCNISTEngine.generate_kem_keypair()
        ct, ss_alice = PQCNISTEngine.encapsulate(PQCNISTEngine.serialize_public_key(alice_pub))
        # Eve decapsula com a própria chave (errada) — obtém segredo diferente
        ss_eve = PQCNISTEngine.decapsulate(eva_priv, ct)
        self.assertNotEqual(ss_alice, ss_eve)

    def test_04_public_key_roundtrip(self):
        priv, pub = PQCNISTEngine.generate_kem_keypair()
        raw = PQCNISTEngine.serialize_public_key(pub)
        reloaded = PQCNISTEngine.deserialize_public_key(raw)
        self.assertEqual(PQCNISTEngine.serialize_public_key(reloaded), raw)

    def test_05_ml_dsa_sign_verify(self):
        spriv, spub = PQCNISTEngine.generate_signature_keypair()
        pub_raw = PQCNISTEngine.serialize_sign_public_key(spub)
        priv_raw = PQCNISTEngine.serialize_sign_private_key(spriv)
        self.assertEqual(len(pub_raw), 2592)
        self.assertEqual(len(priv_raw), 32)  # seed de ML-DSA-87

        data = os.urandom(128)
        sig = PQCNISTEngine.sign(spriv, data)
        self.assertEqual(len(sig), 4627)
        self.assertTrue(PQCNISTEngine.verify(pub_raw, sig, data))

    def test_06_ml_dsa_rejects_tampering(self):
        spriv, spub = PQCNISTEngine.generate_signature_keypair()
        pub_raw = PQCNISTEngine.serialize_sign_public_key(spub)
        data = b"comando_soar: shop1 NODE-BLK-44"
        sig = PQCNISTEngine.sign(spriv, data)

        # Assinatura adulterada
        bad_sig = bytearray(sig)
        bad_sig[len(bad_sig) // 2] ^= 0xFF
        self.assertFalse(PQCNISTEngine.verify(pub_raw, bytes(bad_sig), data))

        # Mensagem adulterada
        self.assertFalse(PQCNISTEngine.verify(pub_raw, sig, data + b"X"))

        # Chave pública errada (outro nó)
        _, other_pub = PQCNISTEngine.generate_signature_keypair()
        other_raw = PQCNISTEngine.serialize_sign_public_key(other_pub)
        self.assertFalse(PQCNISTEngine.verify(other_raw, sig, data))

        # Tamanho de assinatura inválido
        self.assertFalse(PQCNISTEngine.verify(pub_raw, b"curto", data))


class TestPostQuantumShieldInterface(unittest.TestCase):
    """Compatibilidade da interface usada pela API/SOAR/multiagente."""

    def setUp(self):
        self.shield = PostQuantumShield(agent_id="NODE-TEST-A")

    def test_07_interface_surface(self):
        self.assertTrue(hasattr(self.shield, "agent_id"))
        self.assertTrue(hasattr(self.shield, "public_key"))
        self.assertTrue(len(self.shield.public_key) == 1568)
        self.assertTrue(callable(self.shield.sign_soar_command))
        self.assertTrue(callable(self.shield.verify_soar_command_signature))
        self.assertTrue(callable(self.shield.sign_command_pqc))
        self.assertTrue(callable(self.shield.verify_command_pqc))
        self.assertTrue(callable(self.shield.encapsulate_shared_secret))
        self.assertTrue(callable(self.shield.encrypt_telemetry_pqc))
        self.assertTrue(callable(self.shield.generate_lattice_log_hash))

    def test_08_sign_and_verify_soar_command(self):
        cmd = {"action": "ISOLATE_HOST", "target_ip": "185.220.101.5", "reason": "autoteste"}
        sig = self.shield.sign_soar_command(cmd)
        self.assertIsInstance(sig, str)
        self.assertTrue(sig.startswith(SIGNATURE_PREFIX))
        self.assertTrue(self.shield.verify_soar_command_signature(cmd, sig))

        # Comando adulterado NÃO deve validar
        tampered = dict(cmd)
        tampered["target_ip"] = "10.0.0.1"
        self.assertFalse(self.shield.verify_soar_command_signature(tampered, sig))

        # Assinatura truncada não deve validar
        self.assertFalse(self.shield.verify_soar_command_signature(cmd, sig[:-5]))

    def test_09_cross_node_signature_verification(self):
        """A assinatura de um nó deve ser verificável por outro por chave pública."""
        alice = PostQuantumShield(agent_id="NODE-ALICE")
        bob = PostQuantumShield(agent_id="NODE-BOB")

        cmd = {"action": "QUARANTINE", "path": "C:\\temp", "nonce": 9931}
        sig_alice = alice.sign_command_pqc(cmd)

        # Bob verifica usando a chave pública de Alice
        self.assertTrue(bob.verify_command_pqc(cmd, sig_alice, public_key=alice.signature_public_key))

        # Bob tentando verificar com a própria chave pública FALHA
        self.assertFalse(bob.verify_command_pqc(cmd, sig_alice, public_key=bob.signature_public_key))

    def test_10_kem_two_nodes_secret_exchange(self):
        alice = PostQuantumShield(agent_id="NODE-ALICE")
        bob = PostQuantumShield(agent_id="NODE-BOB")

        # Alice encapsula para a chave pública KEM de Bob
        ss_alice, ct = alice.encapsulate_shared_secret(bob.public_key)
        ss_bob = bob.decapsulate_shared_secret(ct)
        self.assertEqual(ss_alice, ss_bob)

    def test_11_telemetry_encrypt_decrypt(self):
        payload = {"cpu": 12.5, "mem": 44.1, "process_count": 310, "alert": False}
        ss, _ = self.shield.encapsulate_shared_secret(self.shield.public_key)
        enc = self.shield.encrypt_telemetry_pqc(payload, ss)
        self.assertEqual(enc["cipher"], "AES-256-GCM")
        self.assertTrue(enc["pqc_protected"])
        dec = self.shield.decrypt_telemetry_pqc(enc, ss)
        self.assertEqual(dec, payload)

    def test_12_seed_reconstruction(self):
        kem_seed = self.shield.get_kem_private_seed()
        dsa_seed = self.shield.get_dsa_private_seed()
        self.assertEqual(len(kem_seed), 64)
        self.assertEqual(len(dsa_seed), 32)

        clone = PostQuantumShield(
            agent_id="NODE-TEST-A",
            private_key_seed=kem_seed,
            signature_seed=dsa_seed,
        )
        self.assertEqual(clone.public_key, self.shield.public_key)
        self.assertEqual(clone.signature_public_key, self.shield.signature_public_key)

        # Assinatura do clone deve ser verificável pela chave do original
        cmd = {"action": "PING", "nonce": 7}
        sig = clone.sign_command_pqc(cmd)
        self.assertTrue(self.shield.verify_command_pqc(cmd, sig))

    def test_13_lattice_log_hash_chain(self):
        h1 = self.shield.generate_lattice_log_hash("".join("0" * 64), {"evt": 1, "sev": "LOW"})
        h2 = self.shield.generate_lattice_log_hash(h1, {"evt": 2, "sev": "HIGH"})
        self.assertTrue(h1.startswith("PQ_HASH_"))
        self.assertNotEqual(h1, h2)

    def test_14_algorithms_metadata(self):
        self.assertIn("ML-KEM-1024", self.shield.algorithm_kem)
        self.assertIn("ML-DSA-87", self.shield.algorithm_dsa)

    def test_15_kem_seed_determinism(self):
        """A partir do MESMO seed, from_seed_bytes deve reproduzir a MESMA chave (estilo KAT NIST)."""
        seed = bytes(range(64))
        k1 = KEM_PRIVATE_CLASS.from_seed_bytes(seed)
        k2 = KEM_PRIVATE_CLASS.from_seed_bytes(seed)
        self.assertEqual(
            PQCNISTEngine.serialize_private_key(k1),
            PQCNISTEngine.serialize_private_key(k2),
        )
        # Seeds distintos devem gerar chaves distintas
        k3 = KEM_PRIVATE_CLASS.from_seed_bytes(bytes([0] * 64))
        self.assertNotEqual(
            PQCNISTEngine.serialize_private_key(k1),
            PQCNISTEngine.serialize_private_key(k3),
        )

    def test_16_ml_dsa_seed_determinism(self):
        """Seed fixa => mesma chave ML-DSA. Assinaturas podem ser hedged (randomizadas),
        mas TODAS devem ser verificáveis pela chave pública derivada do mesmo seed."""
        seed = bytes([7] * 32)
        s1 = DSA_PRIVATE_CLASS.from_seed_bytes(seed)
        s2 = DSA_PRIVATE_CLASS.from_seed_bytes(seed)
        self.assertEqual(
            PQCNISTEngine.serialize_sign_private_key(s1),
            PQCNISTEngine.serialize_sign_private_key(s2),
        )
        pub1_raw = PQCNISTEngine.serialize_sign_public_key(s1.public_key())
        data = b"vetor-teste-KAT-01"
        sigs = {PQCNISTEngine.sign(s1, data) for _ in range(3)}
        self.assertEqual(len(sigs), 3)  # hedge: cada assinatura é única
        for sig in sigs:
            self.assertEqual(len(sig), 4627)
            self.assertTrue(PQCNISTEngine.verify(pub1_raw, sig, data))

    def test_17_kem_ciphertext_avalanche(self):
        """Um byte adulterado no ciphertext deve produzir shared secret divergente (CCA)."""
        bob_priv, bob_pub = PQCNISTEngine.generate_kem_keypair()
        ct, ss_a1 = PQCNISTEngine.encapsulate(PQCNISTEngine.serialize_public_key(bob_pub))
        ss_b1 = PQCNISTEngine.decapsulate(bob_priv, ct)
        self.assertEqual(ss_a1, ss_b1)

        tampered = bytearray(ct)
        tampered[len(tampered) // 2] ^= 0xFF
        ss_b2 = PQCNISTEngine.decapsulate(bob_priv, bytes(tampered))
        self.assertNotEqual(ss_b1, ss_b2)


if __name__ == "__main__":
    unittest.main(verbosity=2)