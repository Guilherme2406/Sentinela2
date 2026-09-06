# sentinel_core/crypto_vault.py
import os
import logging
from typing import Optional
from cryptography.fernet import Fernet, InvalidToken

class CryptoVault:
    """Cofre de Criptografia Simétrica (AES-256 / Fernet) para proteção de arquivos e segredos."""
    
    def __init__(self, key_path: str = "sentinel.key"):
        self.key_path = os.path.abspath(key_path) if not os.path.isabs(key_path) else key_path
        self.key = self._load_or_generate_key()
        self.cipher = Fernet(self.key)

    def _load_or_generate_key(self) -> bytes:
        if os.path.exists(self.key_path) and os.path.getsize(self.key_path) > 0:
            try:
                with open(self.key_path, "rb") as f:
                    key = f.read().strip()
                # Valida se a chave tem o formato correto do Fernet
                Fernet(key)
                return key
            except Exception:
                logging.warning(f"[VAULT] Chave existente em '{self.key_path}' inválida. Gerando nova chave.")
        
        key = Fernet.generate_key()
        parent_dir = os.path.dirname(self.key_path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)
        with open(self.key_path, "wb") as f:
            f.write(key)
        logging.info(f"[VAULT] Nova chave de criptografia gerada em '{self.key_path}'.")
        return key

    def encrypt_data(self, raw_data: bytes) -> bytes:
        return self.cipher.encrypt(raw_data)

    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        return self.cipher.decrypt(encrypted_data)

    def encrypt(self, data) -> str:
        if isinstance(data, str):
            raw_bytes = data.encode("utf-8")
            enc = self.encrypt_data(raw_bytes)
            return enc.decode("utf-8")
        enc = self.encrypt_data(data)
        try:
            return enc.decode("utf-8")
        except UnicodeDecodeError:
            return enc

    def decrypt(self, data):
        if isinstance(data, str):
            raw_bytes = data.encode("utf-8")
        else:
            raw_bytes = data
        dec = self.decrypt_data(raw_bytes)
        try:
            return dec.decode("utf-8")
        except UnicodeDecodeError:
            return dec

    def encrypt_file(self, file_path: str, output_path: Optional[str] = None) -> bool:
        try:
            if not os.path.exists(file_path):
                logging.error(f"[ERRO VAULT] Arquivo de origem '{file_path}' não encontrado.")
                return False
            with open(file_path, "rb") as f:
                content = f.read()
            encrypted = self.encrypt_data(content)
            out_file = output_path if output_path else file_path + ".enc"
            parent_dir = os.path.dirname(out_file)
            if parent_dir:
                os.makedirs(parent_dir, exist_ok=True)
            with open(out_file, "wb") as f:
                f.write(encrypted)
            logging.info(f"[VAULT] Arquivo '{file_path}' cifrado com sucesso -> '{out_file}'")
            return True
        except Exception as e:
            logging.error(f"[ERRO VAULT] Falha ao cifrar arquivo: {e}")
            return False

    def decrypt_file(self, encrypted_file_path: str, output_path: Optional[str] = None) -> bool:
        try:
            if not os.path.exists(encrypted_file_path):
                logging.error(f"[ERRO VAULT] Arquivo cifrado '{encrypted_file_path}' não encontrado.")
                return False
            with open(encrypted_file_path, "rb") as f:
                content = f.read()
            decrypted = self.decrypt_data(content)
            if output_path is None:
                if encrypted_file_path.endswith(".enc"):
                    out_file = encrypted_file_path[:-4]
                else:
                    out_file = encrypted_file_path + ".dec"
            else:
                out_file = output_path
            parent_dir = os.path.dirname(out_file)
            if parent_dir:
                os.makedirs(parent_dir, exist_ok=True)
            with open(out_file, "wb") as f:
                f.write(decrypted)
            logging.info(f"[VAULT] Arquivo '{encrypted_file_path}' decifrado com sucesso -> '{out_file}'")
            return True
        except Exception as e:
            logging.error(f"[ERRO VAULT] Falha ao decifrar arquivo: {e}")
            return False

SentinelVault = CryptoVault


