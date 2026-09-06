/*
 * Sentinela XDR — Regras YARA oficiais (motor yara-python).
 *
 * Ruleset soberano mínimo consumido por dynamic_yara_scanner.py quando o
 * pacote opcional `yara-python` está instalado. Cada regra espelha também a
 * regra interna equivalente (MALICIOUS_STRINGS), garantindo paridade de
 * detecção mesmo sem o motor oficial.
 */
rule EICAR_AV_Test_File
{
    meta:
        description = "String padrao internacional de teste de antivirus (EICAR)"
        author = "Sentinela XDR"
        severity = "HIGH"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
    strings:
        $s1 = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" nocase
    condition:
        any of them
}

rule Mimikatz_Credential_Dump
{
    meta:
        description = "Roubo de credenciais via Mimikatz (sekurlsa::logonpasswords)"
        author = "Sentinela XDR"
        severity = "CRITICAL"
    strings:
        $s1 = "sekurlsa::logonpasswords"
        $s2 = "mimikatz"
    condition:
        any of them
}

rule Obfuscated_PowerShell_OneLiner
{
    meta:
        description = "Execucao de PowerShell ofuscada em linha unica (enc/nop/w hidden)"
        author = "Sentinela XDR"
        severity = "CRITICAL"
    strings:
        $cmd = "powershell" nocase
        $nop = "-nop" nocase
        $win = "-w hidden" nocase
        $enc = "-enc" nocase
    condition:
        $cmd and $enc and ($nop or $win)
}

rule CobaltStrike_ReflectiveLoader
{
    meta:
        description = "Indicador de beacon refletivo de Cobalt Strike"
        author = "Sentinela XDR"
        severity = "CRITICAL"
    strings:
        $s1 = "ReflectiveLoader"
        $s2 = "beacon.dll" nocase
    condition:
        any of them
}

rule CryptoMiner_Stratum_Pool
{
    meta:
        description = "Configuracao de minerador de criptomoeda (pool stratum+tcp)"
        author = "Sentinela XDR"
        severity = "HIGH"
    strings:
        $s1 = "stratum+tcp://"
    condition:
        any of them
}

rule Remote_Process_Injection
{
    meta:
        description = "Cadela classica de injecao remota de processo (VirtualAllocEx/WriteProcessMemory/CreateRemoteThread)"
        author = "Sentinela XDR"
        severity = "CRITICAL"
    strings:
        $alloc = "VirtualAllocEx" nocase
        $write = "WriteProcessMemory" nocase
        $thread = "CreateRemoteThread" nocase
    condition:
        1 of them or ($alloc and ($write or $thread))
}