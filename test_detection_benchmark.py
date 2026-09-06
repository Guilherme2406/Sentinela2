# test_detection_benchmark.py
"""
Benchmark de DETECÇÃO DE MALWARE sobre o corpus legal `test_corpus/`.

Mede métricas reais de eficácia do motor `DynamicFileScanner` (regras internas
YARA-like + heurística de entropia + motor opcional yara-python):

  - Taxa de Detecção (DR)  = Recall = TP / (TP + FN)
  - Taxa de Falsos-Positivos (FPR) = FP / (FP + TN)
  - Precisão = TP / (TP + FP)
  - F1-score
  - Acurácia

Gera `RELATORIO_BENCHMARK_CORPUS.json` com o detalhamento amostra-a-amostra.

Executar:  python test_detection_benchmark.py
"""
import json
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CORPUS_DIR = os.path.join(BASE_DIR, "test_corpus")
MANIFEST_PATH = os.path.join(CORPUS_DIR, "manifest_checksums.json")
REPORT_PATH = os.path.join(BASE_DIR, "RELATORIO_BENCHMARK_CORPUS.json")

from sentinel_core.dynamic_yara_scanner import DynamicFileScanner


def load_manifest() -> dict:
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def compute_metrics(results: list) -> dict:
    tp = sum(1 for r in results if r["label"] == "MALICIOUS" and r["predicted"])
    tn = sum(1 for r in results if r["label"] == "CLEAN" and not r["predicted"])
    fp = sum(1 for r in results if r["label"] == "CLEAN" and r["predicted"])
    fn = sum(1 for r in results if r["label"] == "MALICIOUS" and not r["predicted"])

    total = tp + tn + fp + fn
    dr = (tp / (tp + fn)) if (tp + fn) else 0.0        # Recall (sensibilidade)
    fpr = (fp / (fp + tn)) if (fp + tn) else 0.0        # Falsos-positivos
    precision = (tp / (tp + fp)) if (tp + fp) else 0.0
    f1 = (2 * precision * dr / (precision + dr)) if (precision + dr) else 0.0
    accuracy = (tp + tn) / total if total else 0.0

    return {
        "true_positive": tp,
        "true_negative": tn,
        "false_positive": fp,
        "false_negative": fn,
        "detection_rate_dr": round(dr, 4),
        "false_positive_rate_fpr": round(fpr, 4),
        "precision": round(precision, 4),
        "f1_score": round(f1, 4),
        "accuracy": round(accuracy, 4),
    }


def main() -> int:
    if not os.path.exists(MANIFEST_PATH):
        print("[ERRO] Manifesto do corpus não encontrado. Execute antes:\n"
              "    python test_corpus/build_corpus.py")
        return 1

    manifest = load_manifest()
    scanner = DynamicFileScanner(logger_instance=None, soar=None, auto_quarantine=False)

    results = []
    for rel_path, meta in sorted(manifest["samples"].items()):
        abs_path = os.path.join(CORPUS_DIR, rel_path)
        with open(abs_path, "rb") as f:
            content = f.read()

        scan = scanner.scan_bytes(content, file_name=os.path.basename(rel_path))
        predicted = bool(scan.get("is_malicious"))
        label = meta["label"]
        results.append({
            "file": rel_path,
            "label": label,
            "predicted": predicted,
            "sha256": meta["sha256"],
            "threats": [t.get("rule") for t in scan.get("threats", [])],
            "entropy": scan.get("entropy"),
            "correct": (predicted == (label == "MALICIOUS")),
        })

    metrics = compute_metrics(results)
    report = {
        "ferramenta": "Sentinela XDR — DynamicFileScanner",
        "corpus": CORPUS_DIR,
        "metodologia": "Corpus de homologacao legal (EICAR + sinteticos + benignos)",
        "amostras_totais": len(results),
        "metricas": metrics,
        "detalhamento": results,
        "criteria_aceite": {
            "detection_rate_dr_min": 0.92,
            "false_positive_rate_fpr_max": 0.05,
        },
    }

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print("=" * 68)
    print("BENCHMARK DE DETECÇÃO — CORPUS LEGAL SENTINELA XDR")
    print("=" * 68)
    print(f"Amostras totais : {len(results)}")
    print(f"TP = {metrics['true_positive']} | TN = {metrics['true_negative']} "
          f"| FP = {metrics['false_positive']} | FN = {metrics['false_negative']}")
    print(f"DR (Recall)     : {metrics['detection_rate_dr']:.2%}")
    print(f"FPR             : {metrics['false_positive_rate_fpr']:.2%}")
    print(f"Precisão        : {metrics['precision']:.2%}")
    print(f"F1-score        : {metrics['f1_score']:.2%}")
    print(f"Acurácia        : {metrics['accuracy']:.2%}")
    print("-" * 68)
    for r in results:
        if not r["correct"]:
            print(f"  DISCREPÂNCIA: {r['file']} -> esperado={r['label']}, "
                  f"predito={'MALICIOUS' if r['predicted'] else 'CLEAN'}")

    ok_dr = metrics["detection_rate_dr"] >= report["criteria_aceite"]["detection_rate_dr_min"]
    ok_fpr = metrics["false_positive_rate_fpr"] <= report["criteria_aceite"]["false_positive_rate_fpr_max"]
    print("-" * 68)
    print(f"Critério DR>=92% : {'APROVADO' if ok_dr else 'REPROVADO'}"
          f" (obtido {metrics['detection_rate_dr']:.1%})")
    print(f"Critério FP<=5%  : {'APROVADO' if ok_fpr else 'REPROVADO'}"
          f" (obtido {metrics['false_positive_rate_fpr']:.1%})")
    print(f"Relatório JSON: {REPORT_PATH}")
    return 0 if (ok_dr and ok_fpr) else 1


if __name__ == "__main__":
    sys.exit(main())