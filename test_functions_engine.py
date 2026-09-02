# test_functions_engine.py
"""Suíte de testes do Functions Engine do Sentinela XDR."""
import math
import sys
import os
import time
import unittest

# Garante que o diretório raiz está no path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from functions_engine.core import (
    FunctionContext,
    FunctionError,
    FunctionErrorType,
    RingBufferStorage,
    SecurityItem,
)
from functions_engine.engine import FunctionsEngine
from functions_engine.registry import registry


class TestFunctionsEngineBase(unittest.TestCase):
    """Base para testes do Functions Engine."""

    @classmethod
    def setUpClass(cls):
        cls.engine = FunctionsEngine()
        cls.engine.register_default_functions()

    def setUp(self):
        self.storage = RingBufferStorage(max_size=10000)
        self.context = FunctionContext(storage=self.storage)
        self.engine.context = self.context

    def _ingest(self, item_id: str, values, start_ts: float = 1000.0, step: float = 10.0):
        """Ingere uma série de valores com timestamps crescentes."""
        for i, v in enumerate(values):
            self.storage.append(SecurityItem(
                item_id=item_id,
                value=v,
                timestamp=start_ts + i * step,
            ))


class TestHistoryFunctions(TestFunctionsEngineBase):
    """Testes das funções de histórico."""

    def test_last(self):
        self._ingest("cpu.util", [10, 20, 30, 40, 50])
        result = self.engine.evaluate('last("cpu.util")')
        self.assertEqual(result, 50)

    def test_change(self):
        self._ingest("cpu.util", [10, 20, 30, 40, 50])
        result = self.engine.evaluate('change("cpu.util")')
        self.assertEqual(result, 10)

    def test_count(self):
        self._ingest("cpu.util", [10, 20, 30, 40, 50])
        result = self.engine.evaluate('count("cpu.util")')
        self.assertEqual(result, 5)

    def test_count_with_value(self):
        self._ingest("cpu.util", [10, 20, 30, 20, 50])
        result = self.engine.evaluate('count("cpu.util", 0, 20, "=")')
        self.assertEqual(result, 2)

    def test_first(self):
        self._ingest("cpu.util", [10, 20, 30, 40, 50])
        result = self.engine.evaluate('first("cpu.util")')
        self.assertEqual(result, 10)

    def test_nodata(self):
        result = self.engine.evaluate('nodata("inexistente")')
        self.assertEqual(result, 1)

    def test_nodata_with_data(self):
        self._ingest("cpu.util", [10, 20, 30])
        result = self.engine.evaluate('nodata("cpu.util")')
        self.assertEqual(result, 0)

    def test_percentile(self):
        self._ingest("latency", [10, 20, 30, 40, 50, 60, 70, 80, 90, 100])
        result = self.engine.evaluate('percentile("latency", 0, 95)')
        self.assertAlmostEqual(result, 95.5, places=1)

    def test_rate(self):
        self._ingest("counter", [0, 10, 20, 30, 40], start_ts=1000.0, step=10.0)
        result = self.engine.evaluate('rate("counter")')
        self.assertAlmostEqual(result, 1.0, places=6)

    def test_changecount(self):
        self._ingest("cpu.util", [10, 10, 20, 20, 30])
        result = self.engine.evaluate('changecount("cpu.util")')
        self.assertEqual(result, 2)

    def test_fuzzytime(self):
        now = time.time()
        self.storage.append(SecurityItem(item_id="cpu.util", value=10, timestamp=now - 5))
        result = self.engine.evaluate('fuzzytime("cpu.util", 60)')
        self.assertEqual(result, 1)

    def test_fuzzytime_stale(self):
        now = time.time()
        self.storage.append(SecurityItem(item_id="cpu.util", value=10, timestamp=now - 120))
        result = self.engine.evaluate('fuzzytime("cpu.util", 60)')
        self.assertEqual(result, 0)

    def test_find(self):
        self._ingest("log.msg", ["INFO: started", "ERROR: failed", "WARN: retry"])
        result = self.engine.evaluate('find("log.msg", "ERROR")')
        self.assertEqual(result, "ERROR: failed")

    def test_counteq(self):
        self._ingest("status", [1, 0, 1, 1, 0])
        result = self.engine.evaluate('counteq("status", 1)')
        self.assertEqual(result, 3)

    def test_monoinc(self):
        self._ingest("cpu.util", [10, 20, 30, 40])
        result = self.engine.evaluate('monoinc("cpu.util")')
        self.assertEqual(result, 1)

    def test_monoinc_false(self):
        self._ingest("cpu.util", [10, 30, 20, 40])
        result = self.engine.evaluate('monoinc("cpu.util")')
        self.assertEqual(result, 0)

    def test_monodec(self):
        self._ingest("cpu.util", [40, 30, 20, 10])
        result = self.engine.evaluate('monodec("cpu.util")')
        self.assertEqual(result, 1)

    def test_monodec_false(self):
        self._ingest("cpu.util", [40, 20, 30, 10])
        result = self.engine.evaluate('monodec("cpu.util")')
        self.assertEqual(result, 0)

    def test_logeventid(self):
        self._ingest("windows.log", ["4624: login success", "4625: login failed"])
        result = self.engine.evaluate('logeventid("windows.log", "4625")')
        self.assertEqual(result, "4625:")

    def test_logseverity(self):
        self._ingest("syslog", ["INFO: started", "CRITICAL: disk full"])
        result = self.engine.evaluate('logseverity("syslog", "disk")')
        self.assertEqual(result, "CRITICAL")

    def test_logsource(self):
        self._ingest("syslog", ["sshd: login attempt", "kernel: oom"])
        result = self.engine.evaluate('logsource("syslog", "login")')
        self.assertIsNone(result)


class TestMathFunctions(TestFunctionsEngineBase):
    """Testes das funções matemáticas."""

    def test_abs(self):
        self.assertEqual(self.engine.evaluate('abs(-5)'), 5)
        self.assertEqual(self.engine.evaluate('abs(5)'), 5)

    def test_acos(self):
        self.assertAlmostEqual(self.engine.evaluate('acos(1)'), 0.0, places=6)

    def test_asin(self):
        self.assertAlmostEqual(self.engine.evaluate('asin(0)'), 0.0, places=6)

    def test_atan(self):
        self.assertAlmostEqual(self.engine.evaluate('atan(0)'), 0.0, places=6)

    def test_atan2(self):
        self.assertAlmostEqual(self.engine.evaluate('atan2(0, 1)'), 0.0, places=6)

    def test_cos(self):
        self.assertAlmostEqual(self.engine.evaluate('cos(0)'), 1.0, places=6)

    def test_cosh(self):
        self.assertAlmostEqual(self.engine.evaluate('cosh(0)'), 1.0, places=6)

    def test_sin(self):
        self.assertAlmostEqual(self.engine.evaluate('sin(0)'), 0.0, places=6)

    def test_sinh(self):
        self.assertAlmostEqual(self.engine.evaluate('sinh(0)'), 0.0, places=6)

    def test_tan(self):
        self.assertAlmostEqual(self.engine.evaluate('tan(0)'), 0.0, places=6)

    def test_tanh(self):
        self.assertAlmostEqual(self.engine.evaluate('tanh(0)'), 0.0, places=6)

    def test_exp(self):
        self.assertAlmostEqual(self.engine.evaluate('exp(0)'), 1.0, places=6)

    def test_log(self):
        self.assertAlmostEqual(self.engine.evaluate('log(1)'), 0.0, places=6)

    def test_log10(self):
        self.assertAlmostEqual(self.engine.evaluate('log10(100)'), 2.0, places=6)

    def test_pow(self):
        self.assertEqual(self.engine.evaluate('pow(2, 10)'), 1024.0)

    def test_sqrt(self):
        self.assertEqual(self.engine.evaluate('sqrt(16)'), 4.0)

    def test_ceil(self):
        self.assertEqual(self.engine.evaluate('ceil(3.2)'), 4)

    def test_floor(self):
        self.assertEqual(self.engine.evaluate('floor(3.8)'), 3)

    def test_round(self):
        self.assertEqual(self.engine.evaluate('round(3.14159, 2)'), 3.14)

    def test_trunc(self):
        self.assertEqual(self.engine.evaluate('trunc(3.99)'), 3)

    def test_mod(self):
        self.assertEqual(self.engine.evaluate('mod(10, 3)'), 1.0)

    def test_sign(self):
        self.assertEqual(self.engine.evaluate('sign(-5)'), -1)
        self.assertEqual(self.engine.evaluate('sign(0)'), 0)
        self.assertEqual(self.engine.evaluate('sign(5)'), 1)

    def test_pi(self):
        self.assertAlmostEqual(self.engine.evaluate('pi()'), math.pi, places=6)

    def test_e(self):
        self.assertAlmostEqual(self.engine.evaluate('e()'), math.e, places=6)

    def test_inf(self):
        self.assertEqual(self.engine.evaluate('inf()'), math.inf)

    def test_nan(self):
        self.assertTrue(math.isnan(self.engine.evaluate('nan()')))

    def test_random(self):
        result = self.engine.evaluate('random()')
        self.assertTrue(0 <= result <= 1)

    def test_division_by_zero(self):
        with self.assertRaises(FunctionError) as ctx:
            self.engine.evaluate('mod(10, 0)')
        self.assertEqual(ctx.exception.error_type, FunctionErrorType.DIVISION_BY_ZERO)


class TestStringFunctions(TestFunctionsEngineBase):
    """Testes das funções de string."""

    def test_concat(self):
        self.assertEqual(self.engine.evaluate('concat("Hello", " ", "World")'), "Hello World")

    def test_strfind(self):
        self.assertEqual(self.engine.evaluate('strfind("hello world", "world")'), 6)

    def test_left(self):
        self.assertEqual(self.engine.evaluate('left("hello", 3)'), "hel")

    def test_len(self):
        self.assertEqual(self.engine.evaluate('len("hello")'), 5)

    def test_lower(self):
        self.assertEqual(self.engine.evaluate('lower("HELLO")'), "hello")

    def test_mid(self):
        self.assertEqual(self.engine.evaluate('mid("hello world", 6, 5)'), "world")

    def test_regex(self):
        self.assertEqual(self.engine.evaluate('regex("abc123def", "[0-9]+")'), "123")

    def test_replace(self):
        self.assertEqual(self.engine.evaluate('replace("hello world", "world", "there")'), "hello there")

    def test_right(self):
        self.assertEqual(self.engine.evaluate('right("hello", 3)'), "llo")

    def test_rtrim(self):
        self.assertEqual(self.engine.evaluate('rtrim("hello   ")'), "hello")

    def test_str(self):
        self.assertEqual(self.engine.evaluate('str(42)'), "42")

    def test_strftime(self):
        result = self.engine.evaluate('strftime(0, "%Y")')
        self.assertEqual(result, "1970")

    def test_strstr(self):
        self.assertEqual(self.engine.evaluate('strstr("hello world", "world")'), "world")

    def test_trim(self):
        self.assertEqual(self.engine.evaluate('trim("  hello  ")'), "hello")

    def test_upper(self):
        self.assertEqual(self.engine.evaluate('upper("hello")'), "HELLO")

    def test_bitlength(self):
        self.assertEqual(self.engine.evaluate('bitlength("A")'), 8)

    def test_bytelength(self):
        self.assertEqual(self.engine.evaluate('bytelength("A")'), 1)


class TestAggregationFunctions(TestFunctionsEngineBase):
    """Testes das funções de agregação."""

    def test_avg(self):
        self._ingest("cpu.util", [10, 20, 30, 40])
        result = self.engine.evaluate('avg("cpu.util")')
        self.assertEqual(result, 25.0)

    def test_max(self):
        self._ingest("cpu.util", [10, 20, 30, 40])
        result = self.engine.evaluate('max("cpu.util")')
        self.assertEqual(result, 40.0)

    def test_min(self):
        self._ingest("cpu.util", [10, 20, 30, 40])
        result = self.engine.evaluate('min("cpu.util")')
        self.assertEqual(result, 10.0)

    def test_sum(self):
        self._ingest("cpu.util", [10, 20, 30, 40])
        result = self.engine.evaluate('sum("cpu.util")')
        self.assertEqual(result, 100.0)

    def test_item_count(self):
        self._ingest("cpu.util", [10, 20, 30, 40])
        result = self.engine.evaluate('item_count("cpu.util")')
        self.assertEqual(result, 4)


class TestTimeFunctions(TestFunctionsEngineBase):
    """Testes das funções de tempo."""

    def test_now(self):
        result = self.engine.evaluate('now()')
        self.assertGreater(result, 0)

    def test_date(self):
        result = self.engine.evaluate('date("%Y")')
        self.assertEqual(len(result), 4)

    def test_dayofmonth(self):
        result = self.engine.evaluate('dayofmonth(0)')
        self.assertEqual(result, 1)

    def test_dayofweek(self):
        # 1970-01-01 era quinta-feira (4 na convenção Zabbix)
        result = self.engine.evaluate('dayofweek(0)')
        self.assertEqual(result, 4)

    def test_time(self):
        result = self.engine.evaluate('time("%H")')
        self.assertEqual(len(result), 2)


class TestBitwiseFunctions(TestFunctionsEngineBase):
    """Testes das funções bitwise."""

    def test_bitand(self):
        self.assertEqual(self.engine.evaluate('bitand(12, 10)'), 8)

    def test_bitlshift(self):
        self.assertEqual(self.engine.evaluate('bitlshift(1, 4)'), 16)

    def test_bitnot(self):
        self.assertEqual(self.engine.evaluate('bitnot(0)'), -1)

    def test_bitor(self):
        self.assertEqual(self.engine.evaluate('bitor(12, 10)'), 14)

    def test_bitrshift(self):
        self.assertEqual(self.engine.evaluate('bitrshift(16, 4)'), 1)

    def test_bitxor(self):
        self.assertEqual(self.engine.evaluate('bitxor(12, 10)'), 6)


class TestTrendFunctions(TestFunctionsEngineBase):
    """Testes das funções de tendência."""

    def test_trendavg(self):
        self._ingest("cpu.util", [10, 20, 30, 40])
        result = self.engine.evaluate('trendavg("cpu.util")')
        self.assertEqual(result, 25.0)

    def test_trendcount(self):
        self._ingest("cpu.util", [10, 20, 30, 40])
        result = self.engine.evaluate('trendcount("cpu.util")')
        self.assertEqual(result, 4)

    def test_trendmax(self):
        self._ingest("cpu.util", [10, 20, 30, 40])
        result = self.engine.evaluate('trendmax("cpu.util")')
        self.assertEqual(result, 40.0)

    def test_trendmin(self):
        self._ingest("cpu.util", [10, 20, 30, 40])
        result = self.engine.evaluate('trendmin("cpu.util")')
        self.assertEqual(result, 10.0)

    def test_trendsum(self):
        self._ingest("cpu.util", [10, 20, 30, 40])
        result = self.engine.evaluate('trendsum("cpu.util")')
        self.assertEqual(result, 100.0)

    def test_baselinedev(self):
        self._ingest("cpu.util", [10, 20, 30, 40, 50])
        result = self.engine.evaluate('baselinedev("cpu.util", 0)')
        self.assertIsInstance(result, float)

    def test_baselinewma(self):
        self._ingest("cpu.util", [10, 20, 30])
        result = self.engine.evaluate('baselinewma("cpu.util")')
        # WMA = (10*1 + 20*2 + 30*3) / (1+2+3) = (10+40+90)/6 = 140/6 ≈ 23.33
        self.assertAlmostEqual(result, 140 / 6, places=6)

    def test_trendstl(self):
        self._ingest("cpu.util", [10, 20, 30, 40, 50, 60])
        result = self.engine.evaluate('trendstl("cpu.util")')
        self.assertIn("trend", result)
        self.assertIn("seasonal", result)
        self.assertIn("residual", result)


class TestPredictiveFunctions(TestFunctionsEngineBase):
    """Testes das funções preditivas."""

    def test_forecast(self):
        # Série linear: y = 2x + 1
        self._ingest("disk.used", [1, 3, 5, 7, 9, 11, 13, 15, 17, 19])
        result = self.engine.evaluate('forecast("disk.used", 0, 10)')
        self.assertIn("predicted_value", result)
        self.assertIn("confidence_interval", result)
        self.assertIn("trend_direction", result)
        self.assertEqual(result["trend_direction"], "UP")

    def test_timeleft(self):
        # Série linear: y = 2x + 1, threshold = 21 -> tempo restante = 10
        self._ingest("disk.used", [1, 3, 5, 7, 9, 11, 13, 15, 17, 19])
        result = self.engine.evaluate('timeleft("disk.used", 21, 0)')
        self.assertGreater(result, 0)


class TestStatisticsFunctions(TestFunctionsEngineBase):
    """Testes das funções de estatística."""

    def test_kurtosis(self):
        self._ingest("cpu.util", [1, 2, 3, 4, 5, 6, 7, 8])
        result = self.engine.evaluate('kurtosis("cpu.util")')
        self.assertIsInstance(result, float)

    def test_mad(self):
        self._ingest("cpu.util", [1, 2, 3, 4, 5])
        result = self.engine.evaluate('mad("cpu.util")')
        self.assertEqual(result, 1.0)

    def test_skewness(self):
        self._ingest("cpu.util", [1, 2, 3, 4, 5, 6, 7, 8])
        result = self.engine.evaluate('skewness("cpu.util")')
        self.assertIsInstance(result, float)

    def test_stddevpop(self):
        self._ingest("cpu.util", [2, 4, 4, 4, 5, 5, 7, 9])
        result = self.engine.evaluate('stddevpop("cpu.util")')
        self.assertAlmostEqual(result, 2.0, places=6)

    def test_stddevsamp(self):
        self._ingest("cpu.util", [2, 4, 4, 4, 5, 5, 7, 9])
        result = self.engine.evaluate('stddevsamp("cpu.util")')
        self.assertAlmostEqual(result, 2.138, places=2)

    def test_varpop(self):
        self._ingest("cpu.util", [2, 4, 4, 4, 5, 5, 7, 9])
        result = self.engine.evaluate('varpop("cpu.util")')
        self.assertAlmostEqual(result, 4.0, places=6)

    def test_varsamp(self):
        self._ingest("cpu.util", [2, 4, 4, 4, 5, 5, 7, 9])
        result = self.engine.evaluate('varsamp("cpu.util")')
        self.assertAlmostEqual(result, 4.571, places=2)

    def test_sumofsquares(self):
        self._ingest("cpu.util", [1, 2, 3])
        result = self.engine.evaluate('sumofsquares("cpu.util")')
        self.assertEqual(result, 14.0)

    def test_histogram_quantile(self):
        result = self.engine.evaluate('histogram_quantile([10, 20, 30], [5, 15, 30], 0.5)')
        self.assertAlmostEqual(result, 20.0, places=6)

    def test_bucket_percentile(self):
        self._ingest("cpu.util", [5, 15, 25, 35, 45])
        result = self.engine.evaluate('bucket_percentile("cpu.util", [10, 20, 30, 40])')
        self.assertIn("<10", result)
        self.assertIn(">=40", result)


class TestForeachFunctions(TestFunctionsEngineBase):
    """Testes das funções foreach."""

    def test_avg_foreach(self):
        self._ingest("system.cpu[0,util]", [10])
        self._ingest("system.cpu[1,util]", [20])
        self._ingest("system.cpu[2,util]", [30])
        result = self.engine.evaluate('avg_foreach("system.cpu[*,util]")')
        self.assertEqual(result, 20.0)

    def test_count_foreach(self):
        self._ingest("system.cpu[0,util]", [10])
        self._ingest("system.cpu[1,util]", [20])
        self._ingest("system.cpu[2,util]", [30])
        result = self.engine.evaluate('count_foreach("system.cpu[*,util]")')
        self.assertEqual(result, 3)

    def test_last_foreach(self):
        self._ingest("system.cpu[0,util]", [10])
        self._ingest("system.cpu[1,util]", [20])
        result = self.engine.evaluate('last_foreach("system.cpu[*,util]")')
        self.assertEqual(result["system.cpu[0,util]"], 10)
        self.assertEqual(result["system.cpu[1,util]"], 20)

    def test_sum_foreach(self):
        self._ingest("system.cpu[0,util]", [10])
        self._ingest("system.cpu[1,util]", [20])
        self._ingest("system.cpu[2,util]", [30])
        result = self.engine.evaluate('sum_foreach("system.cpu[*,util]")')
        self.assertEqual(result, 60.0)


class TestTriggerEvaluation(TestFunctionsEngineBase):
    """Testes de avaliação de triggers."""

    def test_trigger_greater_than(self):
        self._ingest("cpu.util", [95])
        result = self.engine.evaluate_trigger('last("cpu.util") > 90')
        self.assertTrue(result)

    def test_trigger_less_than(self):
        self._ingest("cpu.util", [50])
        result = self.engine.evaluate_trigger('last("cpu.util") < 90')
        self.assertTrue(result)

    def test_trigger_equal(self):
        self._ingest("cpu.util", [50])
        result = self.engine.evaluate_trigger('last("cpu.util") = 50')
        self.assertTrue(result)

    def test_trigger_not_equal(self):
        self._ingest("cpu.util", [50])
        result = self.engine.evaluate_trigger('last("cpu.util") != 60')
        self.assertTrue(result)

    def test_trigger_greater_equal(self):
        self._ingest("cpu.util", [90])
        result = self.engine.evaluate_trigger('last("cpu.util") >= 90')
        self.assertTrue(result)

    def test_trigger_less_equal(self):
        self._ingest("cpu.util", [90])
        result = self.engine.evaluate_trigger('last("cpu.util") <= 90')
        self.assertTrue(result)

    def test_trigger_false(self):
        self._ingest("cpu.util", [50])
        result = self.engine.evaluate_trigger('last("cpu.util") > 90')
        self.assertFalse(result)


class TestRegistry(TestFunctionsEngineBase):
    """Testes do registry."""

    def test_registry_has_functions(self):
        self.assertGreater(len(registry), 50)

    def test_registry_categories(self):
        categories = registry.categories()
        self.assertIn("histórico", categories)
        self.assertIn("matemática", categories)
        self.assertIn("string", categories)
        self.assertIn("agregação", categories)
        self.assertIn("tempo", categories)
        self.assertIn("bitwise", categories)
        self.assertIn("tendência", categories)
        self.assertIn("preditiva", categories)
        self.assertIn("estatística", categories)
        self.assertIn("foreach", categories)

    def test_registry_list(self):
        funcs = registry.list()
        self.assertGreater(len(funcs), 50)

    def test_registry_get(self):
        cls = registry.get("last")
        self.assertEqual(cls.name, "last")

    def test_registry_has(self):
        self.assertTrue(registry.has("last"))
        self.assertFalse(registry.has("nao_existe"))


class TestEngineIngest(TestFunctionsEngineBase):
    """Testes de ingestão de dados."""

    def test_ingest(self):
        self.engine.ingest(SecurityItem(item_id="test.item", value=42))
        result = self.engine.evaluate('last("test.item")')
        self.assertEqual(result, 42)

    def test_ingest_many(self):
        items = [
            SecurityItem(item_id="test.item", value=i, timestamp=1000 + i)
            for i in range(10)
        ]
        self.engine.ingest_many(items)
        result = self.engine.evaluate('count("test.item")')
        self.assertEqual(result, 10)


class TestErrorHandling(TestFunctionsEngineBase):
    """Testes de tratamento de erros."""

    def test_unknown_function(self):
        with self.assertRaises(FunctionError) as ctx:
            self.engine.evaluate('funcao_inexistente("x")')
        self.assertEqual(ctx.exception.error_type, FunctionErrorType.NOT_FOUND)

    def test_empty_expression(self):
        with self.assertRaises(FunctionError):
            self.engine.evaluate("")

    def test_no_data(self):
        with self.assertRaises(FunctionError) as ctx:
            self.engine.evaluate('last("inexistente")')
        self.assertEqual(ctx.exception.error_type, FunctionErrorType.NOT_FOUND)

    def test_invalid_domain(self):
        with self.assertRaises(FunctionError) as ctx:
            self.engine.evaluate('sqrt(-1)')
        self.assertEqual(ctx.exception.error_type, FunctionErrorType.INVALID_VALUE)


class TestLogicalOperatorsInTriggers(TestFunctionsEngineBase):
    """Testes de operadores lógicos compostos (and, or, not, parênteses) em triggers."""

    def setUp(self):
        super().setUp()
        self.engine.ingest(SecurityItem("metric.cpu", value=95, timestamp=1000))
        self.engine.ingest(SecurityItem("metric.ram", value=70, timestamp=1000))
        self.engine.ingest(SecurityItem("metric.disk", value=40, timestamp=1000))

    def test_and_operator(self):
        # Ambos verdadeiros
        self.assertTrue(self.engine.evaluate_trigger('last("metric.cpu") > 90 and last("metric.ram") > 60'))
        # Um falso
        self.assertFalse(self.engine.evaluate_trigger('last("metric.cpu") > 90 and last("metric.ram") > 80'))

    def test_or_operator(self):
        # Pelo menos um verdadeiro
        self.assertTrue(self.engine.evaluate_trigger('last("metric.cpu") > 100 or last("metric.ram") > 60'))
        # Ambos falsos
        self.assertFalse(self.engine.evaluate_trigger('last("metric.cpu") > 100 or last("metric.ram") > 90'))

    def test_not_operator(self):
        # Negação de falso resulta em verdadeiro
        self.assertTrue(self.engine.evaluate_trigger('not (last("metric.cpu") < 50)'))
        # Negação de verdadeiro resulta em falso
        self.assertFalse(self.engine.evaluate_trigger('not (last("metric.cpu") > 50)'))

    def test_parentheses_composition(self):
        expr = '(last("metric.cpu") > 90 and last("metric.ram") > 65) or last("metric.disk") > 80'
        self.assertTrue(self.engine.evaluate_trigger(expr))


class TestTriggerWatchDaemon(TestFunctionsEngineBase):
    """Testes do TriggerWatchDaemon e transições de alarme."""

    def setUp(self):
        super().setUp()
        from functions_engine.daemon import TriggerWatchDaemon, TriggerRule
        self.daemon = TriggerWatchDaemon(engine=self.engine, eval_interval=0.1)

    def test_presets_loaded(self):
        rules = self.daemon.list_rules()
        self.assertGreaterEqual(len(rules), 3)

    def test_register_and_remove_rule(self):
        rule = self.daemon.register_rule(
            name="Test CPU Rule",
            expression='last("test.cpu") > 80',
            severity="HIGH"
        )
        self.assertIsNotNone(rule)
        self.assertIn(rule.id, [r["id"] for r in self.daemon.list_rules()])

        # Remoção
        removed = self.daemon.remove_rule(rule.id)
        self.assertTrue(removed)
        self.assertNotIn(rule.id, [r["id"] for r in self.daemon.list_rules()])

    def test_run_cycle_transition_to_problem_and_resolve(self):
        self.daemon._rules.clear()
        self.daemon.register_rule(
            name="CPU High",
            expression='last("system.cpu.test") > 80',
            severity="HIGH",
            required_consecutive=1,
            rule_id="cpu_high_rule"
        )

        # 1. Sem dados ou abaixo do limiar -> OK
        self.engine.ingest(SecurityItem("system.cpu.test", value=50, timestamp=1000))
        res1 = self.daemon.run_cycle()
        self.assertEqual(res1["active_problems"], 0)
        self.assertEqual(self.daemon._rules["cpu_high_rule"].status, "OK")

        # 2. Acima do limiar -> PROBLEM
        self.engine.ingest(SecurityItem("system.cpu.test", value=95, timestamp=1010))
        res2 = self.daemon.run_cycle()
        self.assertEqual(res2["active_problems"], 1)
        self.assertEqual(self.daemon._rules["cpu_high_rule"].status, "PROBLEM")
        self.assertGreaterEqual(len(self.daemon.get_alarm_history()), 1)

        # 3. Retorna abaixo do limiar -> Normaliza para OK
        self.engine.ingest(SecurityItem("system.cpu.test", value=40, timestamp=1020))
        res3 = self.daemon.run_cycle()
        self.assertEqual(res3["active_problems"], 0)
        self.assertEqual(self.daemon._rules["cpu_high_rule"].status, "OK")


class TestTelemetryCollector(TestFunctionsEngineBase):
    """Testes do coletor central de telemetria."""

    def test_telemetry_collection_and_feed(self):
        from sentinel_core.telemetry_collector import SentinelTelemetryCollector
        collector = SentinelTelemetryCollector(storage=self.storage)
        items = collector.collect_all()

        # Deve conter métricas de sistema e camadas
        item_ids = [it.item_id for it in items]
        self.assertIn("sentinel.active_layers.count", item_ids)
        self.assertIn("sentinel.ztna.risk_score", item_ids)
        self.assertIn("sentinel.posture.hardening_score", item_ids)

        # Alimenta o storage
        fed = collector.feed_storage(self.storage)
        self.assertGreater(fed, 0)
        self.assertEqual(self.engine.evaluate('last("sentinel.active_layers.count")'), 20)


if __name__ == "__main__":
    unittest.main(verbosity=2)