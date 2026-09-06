# sentinel_core/ai_anomaly_detector.py
import os
import time
import pickle
import logging
import psutil
import numpy as np
from typing import List, Dict, Any, Optional
from sklearn.ensemble import IsolationForest
from sentinel_core.logger import SecurityEventLogger # Supondo que você tenha um módulo logger em sentinel_core/logger.py

# Configura o logger para este módulo
logger = logging.getLogger("SentinelaXDR.AIAnomalyDetector")
logger.setLevel(logging.INFO) # Nível padrão de log

class AIAnomalyDetectorPro:
    """
    Motor de Inteligência Artificial para detecção de anomalias comportamentais em tempo real
    utilizando o algoritmo Isolation Forest (Detecção Zero-Day).
    Possui persistência de modelo em disco, detecção de I/O de Ransomware e features avançadas.
    """

    # Processos do sistema que devem ser ignorados na análise
    SAFE_PROCESS_NAMES = {
        "system idle process", "system", "registry", "smss.exe", 
        "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", 
        "svchost.exe", "fontdrvhost.exe", "dwm.exe", "explorer.exe" # Adicionei explorer.exe
    }

    # Limites para normalização e detecção (ajustáveis)
    METRIC_LIMITS = {
        'cpu': 100.0, 'mem': 100.0, 'threads': 200.0, 'handles': 10000.0,
        'io_read_kb': 1000000.0, 'io_write_kb': 1000000.0, 'sockets_count': 1000.0
    }

    def __init__(self, 
                 logger: Optional[SecurityEventLogger] = None,
                 logger_instance: Optional[SecurityEventLogger] = None, 
                 contamination: float = 0.01, # Valor inicial mais conservador para evitar falsos positivos
                 n_estimators: int = 200,     # Aumentei para mais robustez
                 max_features: float = 0.8,   # Percentual de features a serem usadas em cada árvore
                 model_dir: Optional[str] = None,
                 auto_train_threshold: int = 50,
                 **kwargs):
        
        self.logger = logger or logger_instance
        self.logger_instance = self.logger
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.max_features = max_features
        self.model = IsolationForest(
            contamination=self.contamination, 
            random_state=42, 
            n_estimators=self.n_estimators,
            max_features=self.max_features,
            n_jobs=-1 # Usa todos os núcleos da CPU para treino/inferência
        )
        self.is_trained = False
        self.model_dir = model_dir or os.path.join(os.path.dirname(os.path.dirname(__file__)), "sentinel_vault")
        self.model_file = os.path.join(self.model_dir, "ai_isolation_forest.pkl")
        self.auto_train_threshold = auto_train_threshold
        self.collected_features_for_retrain: List[np.ndarray] = [] # Buffer para coletar features para retreinamento


        self._load_persisted_model()

    def _load_persisted_model(self):
        """Carrega modelo pré-treinado do cofre persistente se existir."""
        try:
            if not os.path.exists(self.model_dir):
                os.makedirs(self.model_dir) # Cria o diretório se não existir

            if os.path.exists(self.model_file):
                with open(self.model_file, "rb") as f:
                    self.model = pickle.load(f)
                    self.is_trained = True
                logger.info("🧠 [AI_ENGINE] Modelo Isolation Forest persistente carregado com sucesso do cofre.")
            else:
                logger.info("🧠 [AI_ENGINE] Nenhum modelo persistente encontrado. Iniciando com modelo vazio.")
        except Exception as e:
            logger.error(f"❌ [AI_ENGINE] Erro crítico ao carregar modelo persistente de IA: {e}")
            # Em caso de erro, garante que o modelo seja inicializado, mesmo que vazio
            self.model = IsolationForest(
                contamination=self.contamination, 
                random_state=42, 
                n_estimators=self.n_estimators,
                max_features=self.max_features,
                n_jobs=-1
            )


    def _save_model(self):
        """Salva os pesos do modelo no cofre para inicialização instantânea."""
        try:
            os.makedirs(self.model_dir, exist_ok=True)
            with open(self.model_file, "wb") as f:
                pickle.dump(self.model, f)
            logger.info("💾 [AI_ENGINE] Pesos da baseline salvos com sucesso em sentinel_vault.")
        except Exception as e:
            logger.error(f"❌ [AI_ENGINE] Erro ao salvar modelo de IA: {e}")

    def collect_process_metrics(self) -> List[Dict[str, Any]]:
        """
        Coleta vetor expandido de 7 métricas comportamentais dos processos ativos,
        aplicando normalização e tratamento de exceções.
        [CPU, RAM, Threads, Handles, Read_KB/s, Write_KB/s, Sockets_Count]
        """
        metrics = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'num_threads', 'num_handles']):
            try:
                info = proc.info
                pid = info.get('pid')
                if not pid or pid == 0:
                    continue

                name = info.get('name', 'Desconhecido').lower()
                if name in self.SAFE_PROCESS_NAMES:
                    continue

                cpu = info.get('cpu_percent', 0.0)
                mem = info.get('memory_percent', 0.0)
                threads = info.get('num_threads', 1.0)
                handles = info.get('num_handles', 0.0)

                io_read_kb = 0.0
                io_write_kb = 0.0
                try:
                    io_counters = proc.io_counters()
                    io_read_kb = io_counters.read_bytes / 1024.0
                    io_write_kb = io_counters.write_bytes / 1024.0
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass # Ignora se não conseguir acesso

                sockets_count = 0.0
                try:
                    sockets_count = float(len(proc.net_connections()))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass # Ignora se não conseguir acesso

                # Normalização e clipagem (garante que os valores estejam dentro de limites razoáveis)
                features = [
                    min(max(cpu / self.METRIC_LIMITS['cpu'], 0.0), 1.0), # CPU (0-100%)
                    min(max(mem / self.METRIC_LIMITS['mem'], 0.0), 1.0), # RAM (0-100%)
                    min(max(threads / self.METRIC_LIMITS['threads'], 0.0), 1.0), # Threads
                    min(max(handles / self.METRIC_LIMITS['handles'], 0.0), 1.0), # Handles
                    min(max(io_read_kb / self.METRIC_LIMITS['io_read_kb'], 0.0), 1.0), # I/O Read KB
                    min(max(io_write_kb / self.METRIC_LIMITS['io_write_kb'], 0.0), 1.0), # I/O Write KB
                    min(max(sockets_count / self.METRIC_LIMITS['sockets_count'], 0.0), 1.0) # Sockets
                ]

                metrics.append({
                    'pid': pid,
                    'name': proc.info.get('name', 'Desconhecido'), # Mantém o nome original com capitalização
                    'features': np.array(features, dtype=np.float64) # Armazena como numpy array
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                logger.debug(f"⚠️ [AI_ENGINE] Erro ao coletar métricas para processo PID {proc.info.get('pid')}: {e}")
        return metrics

    def _train_model(self, data: List[np.ndarray], min_samples: Optional[int] = None):
        """Função interna para treinar ou retreinar o modelo."""
        threshold = min_samples if min_samples is not None else min(self.auto_train_threshold, 10)
        if not data or len(data) < threshold:
            logger.warning(f"⚠️ [AI_ENGINE] Dados insuficientes para treinar o modelo de IA ({len(data)} amostras). Mínimo: {threshold}.")
            self.is_trained = False
            return

        X = np.array(data, dtype=np.float64)
        try:
            self.model.fit(X)
            self.is_trained = True
            self._save_model()
            logger.info(f"✅ [AI_ENGINE] Modelo de IA treinado/retreinado com sucesso com {len(data)} amostras (7 Dimensões).")
        except Exception as e:
            logger.error(f"❌ [AI_ENGINE] Erro durante o treinamento do modelo de IA: {e}")
            self.is_trained = False

    def train_baseline(self, samples_count: int = 3, delay_between_samples: float = 0.1):
        """
        Treina a baseline multidimensional de IA coletando amostras em intervalos,
        e persiste os pesos. Mais robusto para primeira inicialização.
        """
        logger.info("[AI_ENGINE] Iniciando coleta de telemetria para treinamento da baseline...")
        all_features = []
        
        for i in range(samples_count):
            processes = self.collect_process_metrics()
            for proc in processes:
                all_features.append(proc['features'])
            logger.debug(f"Coletado {len(all_features)} amostras. Amostra {i+1}/{samples_count}.")
            if i < samples_count - 1 and delay_between_samples > 0:
                time.sleep(delay_between_samples)

        self._train_model(all_features, min_samples=min(len(all_features), 10) if len(all_features) >= 5 else 10)
        # Limpa o buffer após o treinamento da baseline inicial
        self.collected_features_for_retrain.clear()


    def detect_anomalies(self) -> List[Dict[str, Any]]:
        """
        Executa inferência de anomalia Zero-Day em todos os processos ativos.
        Inclui lógica de auto-treinamento incremental se o modelo não estiver treinado
        ou se novas amostras suficientes forem coletadas.
        """
        current_processes = self.collect_process_metrics()
        if not current_processes:
            logger.debug("Nenhum processo válido encontrado para análise.")
            return []

        X_test = np.array([p['features'] for p in current_processes], dtype=np.float64)
        
        # Coleta features para potencial retreinamento futuro
        self.collected_features_for_retrain.extend(list(X_test))
        if len(self.collected_features_for_retrain) >= self.auto_train_threshold and self.is_trained:
            logger.info(f"🔄 [AI_ENGINE] Coletadas {len(self.collected_features_for_retrain)} novas amostras. Iniciando retreinamento incremental.")
            self._train_model(self.collected_features_for_retrain)
            self.collected_features_for_retrain.clear() # Limpa o buffer após retreinamento

        if not self.is_trained:
            logger.warning("⚠️ [AI_ENGINE] Modelo de IA não treinado. Tentando auto-treinamento com dados atuais.")
            self._train_model(self.collected_features_for_retrain, min_samples=5) # Tenta treinar com o buffer atual
            if not self.is_trained:
                logger.error("❌ [AI_ENGINE] Falha no auto-treinamento. Detecção de anomalias indisponível.")
                return []

        predictions = self.model.predict(X_test)  # -1 = Anomalia, 1 = Normal
        scores = self.model.decision_function(X_test)

        anomalies = []
        for idx, pred in enumerate(predictions):
            if pred == -1:  # Processo com comportamento anômalo
                proc_info = current_processes[idx]
                anomaly_score = float(scores[idx])
                
                # Desnormaliza as features para a descrição
                f_norm = proc_info['features']
                f_denorm = [
                    f_norm[0] * self.METRIC_LIMITS['cpu'],
                    f_norm[1] * self.METRIC_LIMITS['mem'],
                    f_norm[2] * self.METRIC_LIMITS['threads'],
                    f_norm[3] * self.METRIC_LIMITS['handles'],
                    f_norm[4] * self.METRIC_LIMITS['io_read_kb'],
                    f_norm[5] * self.METRIC_LIMITS['io_write_kb'],
                    f_norm[6] * self.METRIC_LIMITS['sockets_count']
                ]

                desc = (f"ANOMALIA DE IA (7D) DETECTADA! Processo '{proc_info['name']}' (PID: {proc_info['pid']}) "
                        f"[CPU:{f_denorm[0]:.1f}%, RAM:{f_denorm[1]:.1f}%, Threads:{int(f_denorm[2])}, Handles:{int(f_denorm[3])}, "
                        f"I/O Read:{f_denorm[4]:.0f}KB, I/O Write:{f_denorm[5]:.0f}KB, Sockets:{int(f_denorm[6])}] "
                        f"(Score: {anomaly_score:.3f} - quanto menor, mais anômalo)")
                
                if self.logger:
                    self.logger.log_event("HIGH", "AI_ANOMALY", f"PID:{proc_info['pid']} ({proc_info['name']})", desc)
                logger.warning(f"🤖 [AI ALERTA DE ANOMALIA] {desc}")
                
                anomalies.append({
                    "pid": proc_info['pid'],
                    "name": proc_info['name'],
                    "anomaly_score": anomaly_score,
                    "metrics": f_denorm,
                    "metrics_normalized": proc_info['features'].tolist(), # Salva normalizado
                    "metrics_denormalized": f_denorm, # E desnormalizado para visualização
                    "description": desc
                })
        
        return anomalies

    # Aliases para compatibilidade
    scan_anomalies = detect_anomalies
    scan = detect_anomalies

AIAnomalyDetector = AIAnomalyDetectorPro
AnomalyDetector = AIAnomalyDetectorPro
__all__ = ["AIAnomalyDetectorPro", "AIAnomalyDetector", "AnomalyDetector"]


# Exemplo de uso
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Supondo que você tenha um SecurityEventLogger configurado
    class MockSecurityEventLogger:
        def log_event(self, severity, event_type, source, message):
            print(f"[MOCK_LOGGER] [{severity}] [{event_type}] [{source}] {message}")

    mock_logger = MockSecurityEventLogger()

    print("\n--- Inicializando AI Anomaly Detector ---")
    detector = AIAnomalyDetectorPro(logger_instance=mock_logger, contamination=0.008) # Contamination mais baixa
    
    # Força o treinamento inicial se não houver modelo persistente
    if not detector.is_trained:
        print("\n--- Treinando baseline inicial (isso pode levar alguns segundos)... ---")
        detector.train_baseline(samples_count=20, delay_between_samples=0.3) # Mais amostras para a baseline

    print("\n--- Iniciando detecção de anomalias (monitoramento contínuo)... ---")
    for i in range(5):
        print(f"\n--- Ciclo de detecção {i+1} ---")
        anomalies_detected = detector.detect_anomalies()
        if anomalies_detected:
            print(f"❗ Total de anomalias detectadas neste ciclo: {len(anomalies_detected)}")
            for anomaly in anomalies_detected:
                print(f"    - {anomaly['description']}")
        else:
            print("Nenhuma anomalia detectada neste ciclo.")
        time.sleep(5) # Simula intervalo de monitoramento

    print("\n--- Finalizado. ---")

