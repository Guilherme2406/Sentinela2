# _run_all_tests.py (temporary validation runner — safe to delete)
import sys
import unittest

MODULES = [
    "test_pqc_nist",
    "test_cti_feeds",
    "test_sysmon_collector",
    "test_soc_ops",
]

loader = unittest.TestLoader()
suite = unittest.TestSuite()
for mod in MODULES:
    try:
        m = __import__(mod)
        suite.addTests(loader.loadTestsFromModule(m))
    except Exception as exc:
        print(f"[ERRO] falha ao importar {mod}: {exc}")
        sys.exit(2)

result = unittest.TextTestRunner(verbosity=0, stream=sys.stdout).run(suite)
print(f"\nRESULTADO: tests={result.testsRun} failures={len(result.failures)} "
      f"errors={len(result.errors)} skipped={len(result.skipped)}")
sys.exit(0 if result.wasSuccessful() else 1)