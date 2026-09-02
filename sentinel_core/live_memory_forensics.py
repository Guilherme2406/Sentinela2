# sentinel_core/live_memory_forensics.py
import os
import sys
import math
import logging
import re
from typing import Dict, Any, List, Optional

logger = logging.getLogger("SentinelaXDR.MemoryForensics")

class LiveMemoryForensics:
    """
    Motor Avançado de Forense e Volatilidade de Memória RAM (Modo Hardened).
    Inspeciona o espaço virtual de processos em busca de Reflective DLL Injections,
    Cobalt Strike Beacons, Meterpreter, Donut Shellcodes e blocos de alta entropia (Sleep Masks).
    """

    # Assinaturas Forenses de Injeção em Memória
    FORENSIC_PATTERNS = [
        {"name": "NOP_SLED_GENERIC", "pattern": rb"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"},
        {"name": "COBALT_STRIKE_REFLECTIVE_LOADER", "pattern": rb"\xfc\xe8\x82\x00\x00\x00"},
        {"name": "METERPRETER_PAYLOAD_PROLOGUE", "pattern": rb"\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5"},
        {"name": "DONUT_SHELLCODE_ENTRY", "pattern": rb"\xe8\x00\x00\x00\x00\x5d\x83\xed"},
        {"name": "INFINITE_LOOP_STUB", "pattern": rb"\xeb\xfe"},
        {"name": "EXECVE_SHELLCODE_FRAG", "pattern": rb"\x31\xc0\x50\x68\x2f\x2f\x73\x68"}
    ]

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calcula a Entropia de Shannon de um bloco de memória."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 3)

    @classmethod
    def scan_process_memory_dump(cls, pid: int, memory_bytes: bytes) -> Dict[str, Any]:
        """
        Analisa um buffer de memória RAM extraído do processo.
        """
        logger.info(f"🔬 [RAM Forensics] Inspecionando memória do PID {pid} ({len(memory_bytes)} bytes)...")
        
        detected_artifacts = []
        has_unreflected_pe = False
        
        # 1. Busca por múltiplos cabeçalhos MZ (Reflective DLL Injection)
        mz_matches = [m.start() for m in re.finditer(rb"MZ", memory_bytes)]
        if len(mz_matches) > 1:
            has_unreflected_pe = True
            detected_artifacts.append("REFLECTIVE_DLL_INJECTION_DETECTED")

        # 2. Busca por assinaturas de Exploits / C2 Beacons
        for item in cls.FORENSIC_PATTERNS:
            if item["pattern"] in memory_bytes:
                detected_artifacts.append(f"SIGNATURE_MATCH_{item['name']}")

        # 3. Análise de Entropia de Memória (Sleep Mask / In-Memory Encrypted C2)
        entropy = cls.calculate_entropy(memory_bytes)
        if entropy > 7.4 and len(memory_bytes) > 1024:
            detected_artifacts.append(f"HIGH_MEMORY_ENTROPY_DETECTED_{entropy}")

        is_compromised = len(detected_artifacts) > 0 or has_unreflected_pe
        confidence = 98 if has_unreflected_pe else 90 if len(detected_artifacts) > 1 else 75 if is_compromised else 0
        
        return {
            "pid": pid,
            "is_memory_compromised": is_compromised,
            "detected_artifacts": detected_artifacts,
            "unreflected_pe_found": has_unreflected_pe,
            "memory_entropy": entropy,
            "confidence_score": confidence
        }
