# bootstrap_env.py
import os
import sys
import subprocess
import importlib.util
import urllib.request
import logging

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REQ_FILE = os.path.join(BASE_DIR, "requirements.txt")

REQUIRED_MODULES = {
    "flask": "Flask",
    "PyQt6": "PyQt6",
    "psutil": "psutil",
    "cryptography": "cryptography",
    "PIL": "pillow",
    "sklearn": "scikit-learn",
    "numpy": "numpy",
    "requests": "requests",
    "win32api": "pywin32"
}

# Dependências OPCIONAIS: ampliam capacidade sem nunca bloquear a instalação.
OPTIONAL_MODULES = {
    "yara": "yara-python",  # Motor YARA oficial — wheels Windows (CPython 3.x)
}

def is_module_installed(module_name: str) -> bool:
    """Verifica se um módulo Python está instalado e disponível para importação."""
    spec = importlib.util.find_spec(module_name)
    return spec is not None

def ensure_pip():
    """Garante que o pip esteja disponível no ambiente Python atual."""
    try:
        import pip
        return True
    except ImportError:
        print("[!] pip não encontrado. Tentando instalar via ensurepip...")
        try:
            subprocess.run([sys.executable, "-m", "ensurepip", "--default-pip"], check=True)
            return True
        except Exception:
            print("[!] ensurepip falhou. Baixando get-pip.py...")
            try:
                get_pip_url = "https://bootstrap.pypa.io/get-pip.py"
                get_pip_path = os.path.join(BASE_DIR, "_get_pip.py")
                urllib.request.urlretrieve(get_pip_url, get_pip_path)
                subprocess.run([sys.executable, get_pip_path], check=True)
                if os.path.exists(get_pip_path):
                    os.remove(get_pip_path)
                return True
            except Exception as e:
                print(f"[ERRO] Falha ao instalar o pip: {e}")
                return False

def install_missing_dependencies():
    """Verifica todos os pacotes e instala automaticamente qualquer um que esteja ausente."""
    print("=" * 65)
    print("📦 VERIFICANDO E EMBUTINDO DEPENDÊNCIAS DO SENTINEL XDR...")
    print("=" * 65)

    missing_packages = []
    for mod, pkg in REQUIRED_MODULES.items():
        if not is_module_installed(mod):
            missing_packages.append(pkg)
            print(f"   [-] Pacote ausente detectado: {pkg} ({mod})")
        else:
            print(f"   [✓] {pkg} já está instalado e pronto.")

    # Dependências opcionais: nunca falham a instalação (melhoram o produto).
    for mod, pkg in OPTIONAL_MODULES.items():
        if not is_module_installed(mod):
            print(f"   [~] {pkg} (opcional) — tentando instalar sem bloquear a instalação...")
            try:
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", pkg],
                    capture_output=True, check=False, timeout=180,
                )
            except Exception as exc:
                print(f"   [!] Falha ao tentar {pkg} (segue sem ele): {exc}")
        else:
            print(f"   [✓] {pkg} (opcional) já está instalado.")

    if not missing_packages:
        print("\n✅ Todas as dependências e recursos necessários já estão presentes!")
        return True

    print(f"\n⚡ Instalando {len(missing_packages)} recurso(s) ausente(s) automaticamente...")
    if not ensure_pip():
        print("❌ Não foi possível preparar o instalador de pacotes pip.")
        return False

    cmd = [sys.executable, "-m", "pip", "install", "--upgrade"] + missing_packages
    try:
        res = subprocess.run(cmd, capture_output=False, text=True)
        if res.returncode == 0:
            print("\n🎉 Todos os recursos e bibliotecas foram instalados com sucesso!")
            return True
        else:
            print(f"\n⚠️  Aviso: O pip retornou código {res.returncode}. Tentando fallback individual...")
            for pkg in missing_packages:
                subprocess.run([sys.executable, "-m", "pip", "install", pkg], check=False)
            return True
    except Exception as e:
        print(f"\n❌ Erro durante a instalação de dependências: {e}")
        return False

if __name__ == "__main__":
    success = install_missing_dependencies()
    sys.exit(0 if success else 1)
