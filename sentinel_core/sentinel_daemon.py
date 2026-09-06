# sentinel_core/sentinel_daemon.py
import asyncio
import signal
import sys
import logging
from pathlib import Path

# NOTE: A configuração de logging (basicConfig) foi movida para o bloco
# '__main__' abaixo. Antes, apenas importar este módulo reconfigurava o
# logger raiz do processo, sequestrando o console dos pontos de entrada
# (main.py/sentinela_service.py) e misturando os logs da suíte de testes.
logger = logging.getLogger("SentinelDaemon")

class SentinelDaemon:
    """
    Orquestrador Maestro do Sentinel V4.
    Mantém os serviços de Deception, Mesh P2P e Defesa em execução assíncrona paralela.
    """
    def __init__(self, logger_instance=None):
        self.is_running = False
        self.tasks = []
        self.logger = logger_instance
        
        # Diretório base dos canários ancorado à raiz absoluta do projeto
        self.project_root = Path(__file__).resolve().parent.parent
        self.canary_dir = self.project_root / "canary_traps"
        self.canary_dir.mkdir(exist_ok=True)

        # Motores reais integrados
        from sentinel_core.deception_grid import CanaryFileTracker
        from sentinel_core.mesh_orchestrator import DefensiveMeshOrchestrator
        from sentinel_core.threat_detector import ThreatDetector
        self.canary_tracker = CanaryFileTracker(watch_dirs=[str(self.canary_dir)], logger=self.logger)
        self.mesh_orchestrator = DefensiveMeshOrchestrator(node_id="SentinelDaemonNode", logger=self.logger)
        self.threat_detector = ThreatDetector(logger=self.logger)

    async def _start_deception_grid(self):
        """Inicializa e monitora a Deception Grid (Canários e Honeypots)."""
        logger.info("🪤 [Deception Grid] Inicializando armadilhas e arquivos canário...")
        self.canary_tracker.deploy_canaries()
        
        while self.is_running:
            # Inspeção real de integridade dos arquivos canário
            try:
                tampered = self.canary_tracker.check_canaries()
                if tampered:
                    logger.warning(f"🚨 [Deception Grid] Canários violados detectados: {tampered}")
            except Exception as e:
                logger.debug(f"[Deception Grid] Erro na inspeção: {e}")
            await asyncio.sleep(5)

    async def _start_mesh_orchestrator(self):
        """Inicializa o nó P2P da Mesh Network."""
        logger.info("🌐 [Mesh Network] Subindo nó P2P privado e escutando conexões...")
        
        while self.is_running:
            try:
                known = len(self.mesh_orchestrator.known_peers)
                blocked = len(self.mesh_orchestrator.shared_threat_intel.get("blocked_ips", []))
                logger.debug(f"🌐 [Mesh Network] Sincronização ativa (Nós: {known}, IOCs compartilhados: {blocked}).")
            except Exception as e:
                logger.debug(f"[Mesh Network] Erro de sincronização: {e}")
            await asyncio.sleep(15)

    async def _start_defensive_analyst(self):
        """Inicializa o motor de análise de ameaças e mitigação de incidentes."""
        logger.info("🛡️ [Defensive Analyst] Motor de inferência e análise em tempo real ativo.")
        
        while self.is_running:
            try:
                import psutil
                # Varredura não-bloqueante para integridade de processos de sistema
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        pname = (proc.info.get('name') or '').lower()
                        if pname in ("mimikatz.exe", "procdump.exe"):
                            logger.critical(f"🛑 [Defensive Analyst] Processo hostil interceptado pelo daemon: {pname} (PID: {proc.info.get('pid')})")
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            except Exception as e:
                logger.debug(f"[Defensive Analyst] Erro na verificação: {e}")
            await asyncio.sleep(10)


    async def start(self):
        """Dispara todos os motores defensivos em paralelo."""
        self.is_running = True
        logger.info("🚀 ==========================================")
        logger.info("🚀 SENTINEL CORE V4 DAEMON INICIADO")
        logger.info("🚀 ==========================================")

        # Criando tarefas assíncronas para cada motor
        self.tasks = [
            asyncio.create_task(self._start_deception_grid(), name="DeceptionGrid"),
            asyncio.create_task(self._start_mesh_orchestrator(), name="MeshOrchestrator"),
            asyncio.create_task(self._start_defensive_analyst(), name="DefensiveAnalyst"),
        ]

        try:
            await asyncio.gather(*self.tasks)
        except asyncio.CancelledError:
            logger.info("🛑 Recebido sinal de cancelamento nas tarefas do Daemon.")

    async def stop(self):
        """Encerra o Daemon e limpa os recursos com segurança."""
        if not self.is_running:
            return

        logger.info("🛑 Desativando o Sentinel Daemon...")
        self.is_running = False

        # Cancela todas as tarefas ativas
        for task in self.tasks:
            if not task.done():
                task.cancel()

        await asyncio.gather(*self.tasks, return_exceptions=True)
        logger.info("✅ Todos os motores foram desligados com segurança. Sistema limpo.")

def handle_shutdown_signals(daemon, loop):
    """Captura SIGINT (Ctrl+C) e SIGTERM para shutdown gracioso."""
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, lambda: asyncio.create_task(daemon.stop()))
        except NotImplementedError:
            # Tratamento para sistemas Windows onde add_signal_handler tem limitações
            pass

async def main():
    daemon = SentinelDaemon()
    loop = asyncio.get_running_loop()
    handle_shutdown_signals(daemon, loop)

    try:
        await daemon.start()
    except Exception as e:
        logger.critical(f"💥 Falha fatal no Daemon: {e}", exc_info=True)
    finally:
        await daemon.stop()

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] (%(name)s) %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler("sentinel_daemon.log", encoding="utf-8")
        ]
    )
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Sentinel Daemon finalizado pelo usuário.")
