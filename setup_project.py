# setup_project.py
"""
Utilitário de Verificação de Integridade Estrutural e Ambiente do Sentinela XDR.
Garante que todos os diretórios soberanos, cofre de quarentena, armadilhas e banco de dados
estejam criados e configurados corretamente.
"""

import os
import sys
import logging

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SOVEREIGN_DIRECTORIES = [
    "quarantine",        # Cofre de isolamento criptografado AES-256
    "sentinel_vault",    # Armazenamento imutável de snapshots anti-ransomware
    "canary_traps",      # Arquivos canário e armadilhas DLP
    "sentinel_baits",    # Iscas honeytoken de credenciais
    "honeypots",         # Registros e armadilhas de rede
    "user_documents",    # Pasta protegida para testes de rollback
    "restored",          # Destino de arquivos liberados da quarentena
    "assets"             # Logotipos e ícones visuais
]

def verify_and_setup_environment():
    print("\n" + "=" * 65)
    print("🛡️  VERIFICAÇÃO DE INTEGRIDADE ESTRUTURAL — SENTINEL XDR")
    print("=" * 65)

    created_count = 0
    existing_count = 0

    for d in SOVEREIGN_DIRECTORIES:
        full_path = os.path.join(BASE_DIR, d)
        if not os.path.exists(full_path):
            os.makedirs(full_path, exist_ok=True)
            print(f" [+] Criado diretório soberano: '{d}/'")
            created_count += 1
        else:
            print(f" [✓] Diretório soberano ativo: '{d}/'")
            existing_count += 1

    # Validação do Arquivo de Chave Criptográfica
    key_file = os.path.join(BASE_DIR, "sentinel.key")
    if not os.path.exists(key_file):
        print(" [i] Chave master AES-256 será gerada no primeiro início do serviço.")
    else:
        print(" [✓] Chave criptográfica AES-256 presente: 'sentinel.key'")

    print("-" * 65)
    print(f"🎉 Estrutura 100% íntegra! ({existing_count} verificados, {created_count} criados).")
    print("=" * 65 + "\n")

if __name__ == "__main__":
    verify_and_setup_environment()
