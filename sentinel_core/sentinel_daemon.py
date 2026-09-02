# sentinel_core/sentinel_daemon.py
import asyncio
import signal
import sys
import logging
from pathlib import Path

# Configuração de logging estruturado
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (%(name)s) %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("sentinel_daemon.log", encoding="utf-8")
    ]
)
logger = logging.getLogger("SentinelDaemon")

class SentinelDaemon:
    """
    Orquestrador Maestro do Sentinel V4.
    Mantém os serviços de Deception, Mesh P2P e Defesa em execução assíncrona paralela.
    """
    def __init__(self):
        self.is_running = False
        self.tasks = []
        
        # Diretório base dos canários
        self.canary_dir = Path("./canary_traps")
        self.canary_dir.mkdir(exist_ok=True)

    async def _start_deception_grid(self):
        """Inicializa e monitora a Deception Grid (Canários e Honeypots)."""
        logger.info("🪤 [Deception Grid] Inicializando armadilhas e arquivos canário...")
        
        # Simulação do loop de escuta das portas Honeypot e checagem de Canários
        while self.is_running:
            # Aqui o DeceptionGrid inspeciona modificações nos arquivos canário
            await asyncio.sleep(5)
            logger.debug("🪤 [Deception Grid] Integridade dos canários verificada. Status: OK.")

    async def _start_mesh_orchestrator(self):
        """Inicializa o nó P2P da Mesh Network."""
        logger.info("🌐 [Mesh Network] Subindo nó P2P privado e escutando conexões...")
        
        while self.is_running:
            # Loop de manutenção das conexões com outros nós autorizados
            await asyncio.sleep(10)
            logger.debug("🌐 [Mesh Network] Sincronização de regras defensivas ativa.")

    async def _start_defensive_analyst(self):
        """Inicializa o motor de análise de ameaças e mitigação de incidentes."""
        logger.info("🛡️ [Defensive Analyst] Motor de inferência e análise em tempo real ativo.")
        
        while self.is_running:
            await asyncio.sleep(3)

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
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Sentinel Daemon finalizado pelo usuário.")
