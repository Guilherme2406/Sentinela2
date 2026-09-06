# test_corpus/build_corpus.py
"""
Gerador de corpus de VALIDAÇÃO DE DETECÇÃO — 100% LEGAL para distribuição.

Compõe 3 categorias, todas **seguras** para estarem num repositório público:

  (a) `eicar/`      - Arquivos EICAR (padrão internacional de teste AV) e variantes.
  (b) `synthetic/`  - Amostras SINTÉTICAS de malware (strings de assinatura
                      conhecidas injetadas em arquivos inofensivos). NÃO são
                      executáveis; contêm apenas padrões de texto/bytes usados
                      em regras de detecção (YARA/Sigma).
  (c) `benign/`     - Arquivos benignos (textos, JSON, chaves curtas, logs)
                      rotulados como LIMPOS para medir falsos-positivos.

Gera também `manifest_checksums.json` com SHA-256 + rótulo de verdade de campo
(ground truth) de cada amostra, usado pelo `test_detection_benchmark.py`.

Executar:  python test_corpus/build_corpus.py
"""
import hashlib
import json
import os
import sys

CORPUS_DIR = os.path.dirname(os.path.abspath(__file__))
MANIFEST = os.path.join(CORPUS_DIR, "manifest_checksums.json")

EICAR_CANONICAL = (
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def generate_samples() -> dict:
    """Retorna {caminho_relativo: (bytes, label, descricao)}."""
    samples = {}

    # ------------------------------------------------------------------
    # (a) EICAR e variantes
    # ------------------------------------------------------------------
    samples["eicar/eicar_standard.com"] = (
        EICAR_CANONICAL,
        "MALICIOUS",
        "EICAR canônico (68 bytes) — padrão internacional de teste AV",
    )
    samples["eicar/eicar_with_nl.com"] = (
        EICAR_CANONICAL + b"\n",
        "MALICIOUS",
        "EICAR com quebra de linha (69 bytes) — variante real vista em downloads",
    )
    samples["eicar/eicar_crlf.com"] = (
        EICAR_CANONICAL + b"\r\n",
        "MALICIOUS",
        "EICAR com CRLF — variante comum em arquivos copiados pelo Windows",
    )
    samples["eicar/eicar_with_prefix.bin"] = (
        b"\x00\x01\x02" * 16 + EICAR_CANONICAL + b"\x90" * 32,
        "MALICIOUS",
        "EICAR embutido após junk de bytes — detectável por assinatura, não pelo hash canônico",
    )
    samples["eicar/documento_infectado_eicar.txt"] = (
        (
            b"RELATORIO QUADRIMESTRAL\n"
            b"Nenhuma anomalia foi identificada nos ativos monitorados.\n"
            + EICAR_CANONICAL
            + b"\n"
            b"Fim do relatorio gerado automaticamente.\n"
        ),
        "MALICIOUS",
        "Documento 'legítimo' com string EICAR embutida — simula baixado com malware",
    )
    # ------------------------------------------------------------------
    # (b) Sintéticos (strings de assinatura conhecidas, NÃO executáveis)
    # ------------------------------------------------------------------
    samples["synthetic/mimikatz_sampler.bin"] = (
        b"MZ\x90\x00\x03\x00\x00\x00 sekurlsa::logonpasswords mimikatz legitcheck",
        "MALICIOUS",
        "String de roubo de credenciais (Mimikatz sekurlsa)",
    )
    samples["synthetic/powershell_obfuscated.ps1"] = (
        b"# script management\npowershell -nop -w hidden -enc ZwBhAG4AZQByAGEAdABlAEEAcABpAEsAeQAhAA==\n",
        "MALICIOUS",
        "Linha de comando PowerShell ofuscada base64 (injeção típica)",
    )
    samples["synthetic/cobalt_reflective_dll.bin"] = (
        b"\x4d\x5a" + b"\x00" * 64 + b"ReflectiveLoader PAYLOAD_PREPEND",
        "MALICIOUS",
        "Indicador de beacon refletivo de Cobalt Strike (ReflectiveLoader)",
    )
    samples["synthetic/cryptominer_config.bin"] = (
        b"[pool]\nhost=stratum+tcp://crypto.pool.example:3333\nuser=wallet\n",
        "MALICIOUS",
        "Configuração de minerador de criptomoeda (pool stratum)",
    )
    samples["synthetic/injection_stub.bin"] = (
        b"VirtualAllocEx + WriteProcessMemory + CreateRemoteThread classic chain",
        "MALICIOUS",
        "Cadela clássica de injeção de processo remoto (APIs perigosas)",
    )
    samples["synthetic/ransomware_sim_rng.bin"] = (
        os.urandom(4096),
        "MALICIOUS",
        "Bloco aleatório 4KB — simula conteúdo criptografado/pacote (alta entropia)",
    )

    # ------------------------------------------------------------------
    # (c) Benignos (rótulo LIMPO — devem NÃO ser detectados)
    # ------------------------------------------------------------------
    samples["benign/relatorio_financeiro.txt"] = (
        b"Relatorio financeiro Q3\nReceita: 1.240.000\nDespesas: 870.500\nLucro liquido: 369.500\n",
        "CLEAN",
        "Texto comum de relatório financeiro",
    )
    samples["benign/config_rede.json"] = (
        b'{"dhcp": true, "gateway": "192.168.1.1", "dns": ["8.8.8.8", "1.1.1.1"], "mtu": 1500}',
        "CLEAN",
        "Configuração JSON de rede (conteúdo normal)",
    )
    samples["benign/script_instalacao.py"] = (
        b"import os\nfor root, dirs, files in os.walk('.'):\n    print(root)\n",
        "CLEAN",
        "Script Python de instalação comum — sem strings maliciosas",
    )
    samples["benign/chave_api_curta.bin"] = (
        os.urandom(64),
        "CLEAN",
        "Chave de API (64 bytes aleatórios): abaixo do limite da heurística de entropia",
    )
    samples["benign/notas_reuniao.txt"] = (
        b"ATA DA REUNIAO\nDecidido: migrar servico de backup para storage em nuvem.\nResponsavel: TI.\nPrazo: 45 dias.\n",
        "CLEAN",
        "Ata de reunião corporativa",
    )
    samples["benign/log_repetitivo_server.txt"] = (
        b"2026-09-01 10:00:00 INFO heartbeat ok\n" * 300,
        "CLEAN",
        "Log de servidor com linhas repetidas (baixa entropia)",
    )

    return samples


def main() -> int:
    samples = generate_samples()
    manifest = {"generated_by": "test_corpus/build_corpus.py", "version": 1, "samples": {}}

    for rel_path, (content, label, description) in sorted(samples.items()):
        abs_path = os.path.join(CORPUS_DIR, rel_path)
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        with open(abs_path, "wb") as f:
            f.write(content)
        manifest["samples"][rel_path.replace("\\", "/")] = {
            "label": label,
            "sha256": sha256_hex(content),
            "size_bytes": len(content),
            "description": description,
        }
        print(f"[OK] {rel_path:45s} {label:10s} {len(content):6d} bytes")

    with open(MANIFEST, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
    total = len(samples)
    mal = sum(1 for s in samples.values() if s[1] == "MALICIOUS")
    clean = total - mal
    print(f"\nCorpus gerado: {total} amostras -> {mal} MALICIOSAS | {clean} LIMPAS")
    print(f"Manifesto: {MANIFEST}")
    return 0


if __name__ == "__main__":
    sys.exit(main())