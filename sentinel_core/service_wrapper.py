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
        # Aqui o loop do agente executa em segundo plano
        while self.is_running:
            # Aguarda 5 segundos ou sinal de parada
            rc = win32event.WaitForSingleObject(self.stop_event, 5000)
            if rc == win32event.WAIT_OBJECT_0:
                break
            
            # Loop de monitoramento continuo
            # Ex: ETW, Check de Honeytokens, PQC Heartbeat
            pass

if __name__ == '__main__':
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(SentinelaXDRWinService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(SentinelaXDRWinService)
