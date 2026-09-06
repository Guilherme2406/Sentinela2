# sentinel_core/sysmon_collector.py
"""
🛡️ SENTINELA SYSMON DEEP KERNEL TELEMETRY COLLECTOR
Coleta telemetria forense profunda a partir do canal Microsoft-Windows-Sysmon/Operational.
Ingere Event IDs críticos:
  - Event ID 1: Criação de Processos com hash e linha de comando completa
  - Event ID 8: CreateRemoteThread (Injeção de DLL / Shellcode)
  - Event ID 10: ProcessAccess (Acesso cirúrgico à memória do LSASS)
  - Event ID 11: FileCreate (Tripwire para criação em massa de ransomwares)
Opera em modo tolerante a falhas (fallback gracioso se o Sysmon não estiver instalado).
"""

import os
import sys
import time
import json
import logging
import threading
from typing import Dict, Any, List, Optional, Callable

try:
    import win32evtlog
    import xml.etree.ElementTree as ET
    HAS_WIN32EVTLOG = True
except ImportError:
    win32evtlog = None
    ET = None
    HAS_WIN32EVTLOG = False

logger = logging.getLogger("SentinelaXDR.SysmonCollector")

# Event IDs de interesse analítico do Sentinel
INTERESTING_EVENT_IDS = {
    1: "ProcessCreate",
    3: "NetworkConnect",
    5: "ProcessTerminate",
    6: "DriverLoad",
    7: "ImageLoad",
    8: "CreateRemoteThread",
    9: "RawAccessRead",
    10: "ProcessAccess",
    11: "FileCreate",
    13: "RegistryValueSet",
    17: "PipeCreated",
    18: "PipeConnected",
    22: "DnsQuery",
    23: "FileDelete",
    25: "ProcessTampering",
    26: "FileDeleteDetected",
}

# TLDs historicamente associados a infraestrutura maliciosa (domínios DGA/phishing)
SUSPICIOUS_TLDS = {"top", "xyz", "zip", "click", "link", "gq", "tk", "ml", "cf", "ga", "work"}


class SysmonCollector:
    """Coletor e correlacionador de eventos do Microsoft Sysmon."""

    SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

    def __init__(self, logger_instance=None, sigma_engine=None):
        self.logger = logger_instance
        self.sigma_engine = sigma_engine
        self.is_windows = sys.platform == "win32"
        self.sysmon_available = False
        self.events_collected_count = 0
        self.recent_events: List[Dict[str, Any]] = []
        self.listening_event_ids = set(INTERESTING_EVENT_IDS)

        # Deduplicação por número de registro (EventRecordID) do Event Log
        self._seen_record_ids = set()
        self._lock = threading.RLock()
        self.event_id_counts = {eid: 0 for eid in INTERESTING_EVENT_IDS}

        # Polling em segundo plano (bookmark/cursor em memória)
        self._poll_thread: Optional[threading.Thread] = None
        self._poll_stop = threading.Event()
        self._last_poll: Optional[float] = None

        self._check_sysmon_availability()

    def _check_sysmon_availability(self):
        """Verifica se o canal do Sysmon existe no Event Log do Windows."""
        if not self.is_windows or not HAS_WIN32EVTLOG:
            self.sysmon_available = False
            return

        try:
            # Tenta abrir o canal do Sysmon para leitura
            handle = win32evtlog.EvtQuery(
                self.SYSMON_CHANNEL,
                win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
            )
            self.sysmon_available = True
            logger.info("🛡️ [SYSMON COLLECTOR] Canal Microsoft-Windows-Sysmon detectado e pronto para ingestão.")
        except Exception:
            self.sysmon_available = False
            logger.debug("[SYSMON COLLECTOR] Sysmon não instalado no host. Operando em modo de telemetria WMI/Heurística nativa.")

    def _log(self, level: str, category: str, action: str, msg: str):
        try:
            if self.logger:
                self.logger.log_event(level, category, action, msg)
        except Exception:
            pass
        logging.info(f"[{category}] {msg}")

    def process_raw_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Processa e normaliza um evento do Sysmon, avaliando contra o motor Sigma."""
        event_id = int(event_data.get("EventID") or event_data.get("event_id") or 1)
        record_id = event_data.get("RecordID") or event_data.get("record_id")

        # Deduplicação por número de registro (quando presente no XML bruto)
        if record_id is not None:
            with self._lock:
                if record_id in self._seen_record_ids:
                    return {"source": "SYSMON", "event_id": event_id, "record_id": record_id, "duplicate": True}
                self._seen_record_ids.add(record_id)
                if len(self._seen_record_ids) > 20000:  # memória limitada
                    self._seen_record_ids = set(list(self._seen_record_ids)[-10000:])

        normalized = {
            "source": "SYSMON",
            "event_id": event_id,
            "record_id": record_id,
            "timestamp": event_data.get("UtcTime") or event_data.get("TimeCreated") or time.strftime("%Y-%m-%d %H:%M:%S"),
            "image": event_data.get("Image") or event_data.get("image", ""),
            "commandline": event_data.get("CommandLine") or event_data.get("commandline", ""),
            "parent_image": event_data.get("ParentImage") or event_data.get("parent_image", ""),
            "user": event_data.get("User") or event_data.get("user", ""),
            "target_image": event_data.get("TargetImage") or "",
            "source_image": event_data.get("SourceImage") or "",
            "target_filename": event_data.get("TargetFilename") or "",
            "hashes": event_data.get("Hashes", ""),
            "target_object": event_data.get("TargetObject") or event_data.get("target_object", ""),
            "query_name": event_data.get("QueryName") or event_data.get("query_name", ""),
        }

        self.events_collected_count += 1
        with self._lock:
            self.event_id_counts[event_id] = self.event_id_counts.get(event_id, 0) + 1
        self.recent_events.append(normalized)
        if len(self.recent_events) > 100:
            self.recent_events.pop(0)

        # 1. Correlação com Event IDs Críticos do Sysmon
        target_img = normalized["target_image"].lower()
        target_obj = normalized["target_object"].lower()
        qname = normalized["query_name"]

        if event_id == 8:  # CreateRemoteThread
            self._log(
                "CRITICAL", "SYSMON_INJECTION", "CREATE_REMOTE_THREAD",
                f"Injeção de Thread Remota interceptada: '{normalized['source_image']}' -> '{normalized['target_image']}'"
            )
        elif event_id == 10 and "lsass.exe" in target_img:
            self._log(
                "CRITICAL", "SYSMON_LSASS", "PROCESS_ACCESS_LSASS",
                f"Tentativa de acesso à memória do LSASS detectada via Sysmon ID 10 por '{normalized['source_image']}'"
            )
        elif event_id == 13 and any(k in target_obj for k in ("\\run\\", "\\runonce\\", "currentversion\\run", "\\startup\\")):
            self._log(
                "MEDIUM", "SYSMON_PERSISTENCE", "REGISTRY_AUTORUN",
                f"Chave de persistência/autorun alterada: '{target_obj}'"
            )
        elif event_id == 22:
            tld = qname.rsplit(".", 1)[-1].lower() if "." in qname else ""
            if tld in SUSPICIOUS_TLDS:
                self._log(
                    "MEDIUM", "SYSMON_DNS_SUSPICIOUS", "DNS_SUSPICIOUS_TLD",
                    f"Resolução DNS para TLD suspeito ('{tld}'): {qname}"
                )
        elif event_id == 1 and normalized["image"]:
            self._log(
                "INFO", "SYSMON_PROCESS", "PROCESS_CREATE",
                f"Novo processo criado: '{normalized['image']}' cmdline: {normalized['commandline'][:250]}"
            )

        # 2. Avaliação no Motor Sigma
        if self.sigma_engine:
            try:
                matches = self.sigma_engine.evaluate_event(normalized)
                if matches:
                    normalized["sigma_matches"] = matches
            except Exception as e:
                logger.debug(f"[SYSMON] Erro ao correlacionar com Sigma: {e}")

        return normalized

    def read_latest_events(self, max_events: int = 15) -> List[Dict[str, Any]]:
        """Lê eventos recentes do canal Sysmon do Windows, eliminando duplicatas."""
        collected = []
        if not self.sysmon_available or not HAS_WIN32EVTLOG or win32evtlog is None:
            return collected

        try:
            query = win32evtlog.EvtQuery(
                self.SYSMON_CHANNEL,
                win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
            )
            events = win32evtlog.EvtNext(query, max_events)
            for ev in events:
                xml_content = win32evtlog.EvtRender(ev, win32evtlog.EvtRenderEventXml)
                parsed = self._parse_sysmon_xml(xml_content)
                if not parsed:
                    continue
                rid = parsed.get("RecordID")
                with self._lock:
                    if rid is not None and rid in self._seen_record_ids:
                        continue
                    if rid is not None:
                        self._seen_record_ids.add(rid)
                processed = self.process_raw_event(parsed)
                if not processed.get("duplicate"):
                    collected.append(processed)
        except Exception as e:
            logger.debug(f"[SYSMON] Erro na leitura de eventos: {e}")

        return collected

    def poll_events(self, max_events: int = 20) -> List[Dict[str, Any]]:
        """
        Polling incremental do canal Sysmon: retorna APENAS eventos novos
        (cursor/dedup por EventRecordID). Chamável em background.
        """
        collected = []
        if not self.sysmon_available or not HAS_WIN32EVTLOG or win32evtlog is None:
            return collected
        try:
            query = win32evtlog.EvtQuery(
                self.SYSMON_CHANNEL,
                win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
            )
            events = win32evtlog.EvtNext(query, max_events)
            for ev in events:
                xml_content = win32evtlog.EvtRender(ev, win32evtlog.EvtRenderEventXml)
                parsed = self._parse_sysmon_xml(xml_content)
                if not parsed:
                    continue
                rid = parsed.get("RecordID")
                with self._lock:
                    if rid is not None and rid in self._seen_record_ids:
                        continue  # evento já ingerido — sem duplicata
                    if rid is not None:
                        self._seen_record_ids.add(rid)
                processed = self.process_raw_event(parsed)
                if not processed.get("duplicate"):
                    collected.append(processed)
            self._last_poll = time.time()
        except Exception as e:
            logger.debug(f"[SYSMON] Erro no poll de eventos: {e}")
        return collected

    def start_polling(self, interval_seconds: int = 30,
                      callback: Optional[Callable[[List[Dict[str, Any]]], None]] = None,
                      max_events: int = 20) -> bool:
        """Inicia thread de polling em segundo plano com watchdog simples."""
        if self._poll_thread and self._poll_thread.is_alive():
            return False
        self._poll_stop.clear()

        def _loop():
            while not self._poll_stop.is_set():
                try:
                    events = self.poll_events(max_events=max_events)
                    if events and callback:
                        callback(events)
                except Exception as exc:
                    logger.debug(f"[SYSMON] Falha no ciclo de polling: {exc}")
                self._poll_stop.wait(max(interval_seconds, 5))

        self._poll_thread = threading.Thread(target=_loop, name="SysmonCollectorPolling", daemon=True)
        self._poll_thread.start()
        logging.info("[SYSMON] Polling em segundo plano iniciado.")
        return True

    def stop_polling(self):
        """Encerra a thread de polling em segundo plano."""
        self._poll_stop.set()
        if self._poll_thread:
            self._poll_thread.join(timeout=5)
            self._poll_thread = None

    def is_polling(self) -> bool:
        return bool(self._poll_thread and self._poll_thread.is_alive())

    def _parse_sysmon_xml(self, xml_text: str) -> Optional[Dict[str, Any]]:
        """Converte XML bruto do Event Log do Sysmon em dicionário estruturado."""
        try:
            root = ET.fromstring(xml_text)
            ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
            system = root.find("ns:System", ns)
            event_id = system.find("ns:EventID", ns).text if system is not None else "1"

            event_data_dict = {"EventID": event_id}

            # Campo de deduplicação (EventRecordID) e linha temporal real
            if system is not None:
                rid = system.find("ns:EventRecordID", ns)
                if rid is not None and rid.text:
                    event_data_dict["RecordID"] = rid.text
                tc = system.find("ns:TimeCreated", ns)
                if tc is not None:
                    event_data_dict["TimeCreated"] = tc.attrib.get("SystemTime") or ""

            event_data = root.find("ns:EventData", ns)
            if event_data is not None:
                for data_tag in event_data.findall("ns:Data", ns):
                    name = data_tag.attrib.get("Name")
                    if name:
                        event_data_dict[name] = data_tag.text or ""
            return event_data_dict
        except Exception:
            return None

    def get_status(self) -> Dict[str, Any]:
        """Retorna o status do coletor de telemetria profunda."""
        return {
            "engine": "Sentinel Sysmon Deep Kernel Telemetry Collector",
            "channel": self.SYSMON_CHANNEL,
            "sysmon_available": self.sysmon_available,
            "polling_active": self.is_polling(),
            "events_collected": self.events_collected_count,
            "listening_event_ids": sorted(self.listening_event_ids),
            "event_id_counts": {str(k): v for k, v in self.event_id_counts.items() if v},
            "last_poll": self._last_poll,
            "recent_events": self.recent_events[-10:] if self.recent_events else []
        }
