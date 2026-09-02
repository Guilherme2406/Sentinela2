# sentinel_core/ai_anomaly_detector.py
import os
import time
import pickle
import logging
import psutil
import numpy as np
from typing import List, Dict, Any, Optional
from sklearn.ensemble import IsolationForest
from sentinel_core.logger import SecurityEventLogger

logger = logging.getLogger("SentinelaXDR.AIAnomalyDetector")

class AIAnomalyDetector:
    """
    Motor de Inteligência Artificial de 7 Dimensões para detecção de anomalias comportamentais
    em tempo real utilizando o algoritmo Isolation Forest (Detecção Zero-Day).
    Possui persistência de modelo em disco e detecção de I/O de Ransomware.
    """

    SAFE_PROCESS_NAMES = {
        "system idle process", "system", "registry", "smss.exe", 
        "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", 
        "svchost.exe", "fontdrvhost.exe", "dwm.exe"
    }

    def __init__(self, logger: Optional[SecurityEventLogger] = None, logger_instance: Optional[SecurityEventLogger] = None, contamination: float = 0.04, model_dir: Optional[str] = None):
        self.logger = logger or logger_instance
        self.contamination = contamination
        self.model = IsolationForest(contamination=self.contamination, random_state=42, n_estimators=120)
        self.is_trained = False
        self.model_dir = model_dir or os.path.join(os.path.dirname(os.path.dirname(__file__)), "sentinel_vault")
        self.model_file = os.path.join(self.model_dir, "ai_isolation_forest.pkl")
        self._load_persisted_model()

    def _load_persisted_model(self):
        """Carrega modelo pré-treinado do cofre persistente se existir."""
        try:
            if os.path.exists(self.model_file):
                with open(self.model_file, "rb") as f:
                    self.model = pickle.load(f)
                    self.is_trained = True
                logger.info("🧠 [AI_ENGINE] Modelo Isolation Forest persistente carregado com sucesso do cofre.")
        except Exception as e:
            logger.warning(f"Não foi possível carregar modelo persistente de IA: {e}")

    def _save_model(self):
        """Salva os pesos do modelo no cofre para inicialização instantânea."""
        try:
            os.makedirs(self.model_dir, exist_ok=True)
            with open(self.model_file, "wb") as f:
                pickle.dump(self.model, f)
            logger.info("💾 [AI_ENGINE] Pesos da baseline salvos com sucesso em sentinel_vault.")
        except Exception as e:
            logger.debug(f"Erro ao salvar modelo de IA: {e}")

    def collect_process_metrics(self) -> List[Dict[str, Any]]:
        """
        Coleta vetor expandido de 7 métricas comportamentais dos processos ativos:
        [CPU, RAM, Threads, Handles, Read_KB/s, Write_KB/s, Sockets_Count]
        """
        metrics = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'num_threads', 'num_handles']):
            try:
                info = proc.info
                pid = info.get('pid')
                if not pid or pid == 0:
                    continue

                name = info.get('name') or "Desconhecido"
                if name.lower() in self.SAFE_PROCESS_NAMES:
                    continue

                cpu = float(info.get('cpu_percent') or 0.0)
                mem = float(info.get('memory_percent') or 0.0)
                threads = float(info.get('num_threads') or 1.0)
                handles = float(info.get('num_handles') or 0.0)

                # Métricas de I/O de disco (bytes lidos e gravados)
                io_read_kb = 0.0
                io_write_kb = 0.0
                try:
                    io_counters = proc.io_counters()
                    io_read_kb = float(io_counters.read_bytes / 1024.0)
                    io_write_kb = float(io_counters.write_bytes / 1024.0)
                except Exception:
                    pass

                # Métricas de conexões de rede ativas
                sockets_count = 0.0
                try:
                    sockets_count = float(len(proc.net_connections()))
                except Exception:
                    pass

                # Vetor de 7 features normalizado
                features = [
                    max(0.0, min(cpu, 100.0)),
                    max(0.0, min(mem, 100.0)),
                    max(1.0, threads),
                    max(0.0, min(handles, 10000.0)),
                    max(0.0, min(io_read_kb, 500000.0)),
                    max(0.0, min(io_write_kb, 500000.0)),
                    max(0.0, min(sockets_count, 500.0))
                ]

                metrics.append({
                    'pid': pid,
                    'name': name,
                    'features': features
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return metrics

    def train_baseline(self, samples_count: int = 3):
        """Treina a baseline multidimensional de IA e persiste os pesos."""
        logging.info("[AI_ENGINE] Coletando telemetria em 7 dimensões para treinamento...")
        all_features = []
        
        for _ in range(samples_count):
            processes = self.collect_process_metrics()
            for proc in processes:
                all_features.append(proc['features'])
            if samples_count > 1:
                time.sleep(0.2)

        if len(all_features) >= 10:
            X = np.array(all_features, dtype=np.float64)
            self.model.fit(X)
            self.is_trained = True
            self._save_model()
            logging.info(f"[AI_ENGINE] Modelo de IA treinado com sucesso com {len(all_features)} amostras (7 Dimensões).")
        else:
            logging.warning("[AI_ENGINE] Dados insuficientes para treinar o modelo de IA. Treinamento adiado.")

    def detect_anomalies(self) -> List[Dict[str, Any]]:
        """Executa inferência de anomalia Zero-Day em todos os processos ativos."""
        if not self.is_trained:
            self.train_baseline(samples_count=2)
            if not self.is_trained:
                return []

        current_processes = self.collect_process_metrics()
        if not current_processes:
            return []

        X_test = np.array([p['features'] for p in current_processes], dtype=np.float64)
        predictions = self.model.predict(X_test)  # -1 = Anomalia, 1 = Normal
        scores = self.model.decision_function(X_test)

        anomalies = []
        for idx, pred in enumerate(predictions):
            if pred == -1:  # Processo com comportamento anômalo
                proc_info = current_processes[idx]
                anomaly_score = float(scores[idx])
                
                f = proc_info['features']
                desc = (f"ANOMALIA DE IA (7D) DETECTADA! Processo '{proc_info['name']}' (PID: {proc_info['pid']}) "
                        f"[CPU:{f[0]}%, RAM:{f[1]:.1f}%, Threads:{int(f[2])}, Handles:{int(f[3])}, I/O Write:{f[5]:.0f}KB, Sockets:{int(f[6])}] "
                        f"(Score: {anomaly_score:.3f})")
                
                if self.logger:
                    self.logger.log_event("HIGH", "AI_ANOMALY", f"PID:{proc_info['pid']} ({proc_info['name']})", desc)
                logging.warning(f"🤖 [AI ALERT] {desc}")
                
                anomalies.append({
                    "pid": proc_info['pid'],
                    "name": proc_info['name'],
                    "anomaly_score": anomaly_score,
                    "metrics": proc_info['features'],
                    "description": desc
                })
        
        return anomalies

    scan_anomalies = detect_anomalies
    scan = detect_anomalies

AnomalyDetector = AIAnomalyDetector
