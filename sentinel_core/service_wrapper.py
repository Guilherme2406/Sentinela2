# sentinel_core/service_wrapper.py
import sys
import time
import logging
import win32serviceutil
import win32service
import win32event
import servicemanager

logger = logging.getLogger("SentinelaXDR.ServiceWrapper")

class SentinelaXDRWinService(win32serviceutil.ServiceFramework):
    _svc_name_ = "SentinelaXDRAgent"
    _svc_display_name_ = "Sentinela XDR Endpoint Protection Agent"
    _svc_description_ = "Agente de resposta e detecção proativa de ameaças em tempo real."

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.is_running = True

    def SvcStop(self):
        """Notifica o Windows que o serviço está parando."""
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)
        self.is_running = False
        logger.info("🛑 Serviço Sentinela XDR recebendo sinal de parada...")

    def SvcDoRun(self):
        """Ponto de entrada do serviço quando iniciado pelo System Service Control Manager."""
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.EVENT_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        logger.info("🚀 Serviço Sentinela XDR iniciado com sucesso no Windows Service Control Manager.")
        self.main()

    def main(self):
        # Inicializa o motor de defesa completo (API, motores soberanos, honeypot,
        # NIDS, tarpit, watchdog de threads) dentro do contexto do Serviço Windows.
        try:
            from sentinela_service import SentinelBackgroundDaemon
            self.daemon = SentinelBackgroundDaemon()
            self.daemon.start_service(blocking=False)
            logger.info("🚀 [SERVICE] Loop de defesa contínua iniciado sob o controle do Windows SCM.")
        except Exception as e:
            logger.exception(f"[SERVICE] Falha ao iniciar o motor de defesa: {e}")
            # Não derruba o serviço silenciosamente; aguarda o SCM encerrar.
            self.daemon = None

        # Loop de vida do serviço: aguarda sinal de parada do Service Control Manager.
        while self.is_running:
            rc = win32event.WaitForSingleObject(self.stop_event, 5000)
            if rc == win32event.WAIT_OBJECT_0:
                break

        # Encerramento ordeiro dos motores (honeypot, nids, tarpit e runtime).
        if getattr(self, "daemon", None) is not None:
            try:
                self.daemon.stop_service()
            except Exception as e:
                logger.debug(f"[SERVICE] Aviso no encerramento do daemon: {e}")
        logger.info("🛑 [SERVICE] Serviço Sentinela XDR encerrado de forma ordeira.")

if __name__ == '__main__':
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(SentinelaXDRWinService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(SentinelaXDRWinService)
