# vincular_nuvem.py
"""
Assistente Interativo de Vinculação com o Console Cloud Sentinela no Vercel.
"""

import sys
import getpass
from sentinel_core.machine_identity import load_or_create_identity
from sentinel_core.cloud_sync import pair_with_cloud, CloudSyncWorker

def main():
    print("=" * 65)
    print("🛡️  SENTINEL XDR — VINCULAÇÃO DE HARDWARE COM A NUVEM (VERCEL)")
    print("=" * 65)
    
    ident = load_or_create_identity()
    comp_id = ident["computer_id"]
    hostname = ident["hostname"]
    
    print(f"\n[+] COMPUTADOR LOCAL:")
    print(f"    - Hardware ID : {comp_id}")
    print(f"    - Hostname    : {hostname}")
    print(f"    - Sistema     : {ident['os']}")
    
    if ident.get("paired"):
        print(f"\n[*] Este computador JÁ está vinculado a:")
        print(f"    - Conta : {ident.get('user_email')}")
        print(f"    - Cloud : {ident.get('cloud_url')}")
        resp = input("\nDeseja revincular ou alterar as credenciais? (s/N): ").strip().lower()
        if resp != "s":
            print("\nOperação cancelada. O computador permanece vinculado.")
            return

    print("\n[+] Digite os dados da sua conta na Nuvem Vercel:")
    cloud_url = input("URL da Nuvem (ex: https://seu-projeto.vercel.app): ").strip()
    if not cloud_url:
        print("[!] URL da nuvem é obrigatória.")
        return
        
    email = input("Email da sua conta: ").strip()
    if not email:
        print("[!] Email é obrigatório.")
        return
        
    pwd = getpass.getpass("Senha da sua conta: ")
    if not pwd:
        print("[!] Senha é obrigatória.")
        return

    print(f"\n[*] Conectando a {cloud_url} e registrando Hardware ID {comp_id}...")
    success = pair_with_cloud(cloud_url, email, pwd)
    
    if success:
        print("\n" + "=" * 65)
        print("✅ SUCESSO! Computador vinculado com segurança à sua conta.")
        print("🚀 A telemetria e o estado de ciberdefesa agora são sincronizados.")
        print(f"🌐 Acesse seu painel em qualquer lugar: {cloud_url}/dashboard")
        print("=" * 65)
    else:
        print("\n" + "=" * 65)
        print("❌ FALHA AO VINCULAR:")
        print("Verifique se a URL da nuvem está acessível e se seu email e senha estão corretos.")
        print("Se ainda não tiver conta, crie uma acessando a URL da nuvem pelo navegador.")
        print("=" * 65)

if __name__ == "__main__":
    main()
