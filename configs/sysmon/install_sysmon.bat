@echo off
REM ============================================================
REM  Sentinela XDR - Instalador silencioso do Sysmon (ENDURECIDO)
REM  Instala o driver Sysmon da Sysinternals (Microsoft) com a
REM  configuracao endurecida sysmon-config-hardened.xml.
REM
REM  Requisitos:
REM    - Executar como ADMINISTRADOR
REM    - Internet (para baixar o Sysmon, se nao estiver local)
REM  Validacao:
REM    - wevtutil gl Microsoft-Windows-Sysmon/Operational
REM ============================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo.
echo  ============================================
echo   [SENTINELA XDR] Instalador do Sysmon
echo  ============================================
echo.

REM --- 1. Verifica privilegios de administrador ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo  [!] ERRO: execute este script COMO ADMINISTRADOR.
    echo      Clique com o botao direito -^> "Executar como administrador"
    pause
    exit /b 1
)

REM --- 2. Se Sysmon ja instalado, encerra ---
sc query Sysmon >nul 2>&1
if %errorlevel% equ 0 (
    echo  [i] Sysmon ja esta instalado neste host.
    echo      Para reconfigurar:  sysmon64 -c sysmon-config-hardened.xml
    wevtutil gl Microsoft-Windows-Sysmon/Operational
    pause
    exit /b 0
)

REM --- 3. Localiza ou baixa o sysmon64.exe ---
set "SYSMON_EXE="
if exist "%~dp0sysmon64.exe" set "SYSMON_EXE=%~dp0sysmon64.exe"
if not defined SYSMON_EXE (
    where sysmon64.exe >nul 2>&1 && set "SYSMON_EXE=sysmon64.exe"
)
if not defined SYSMON_EXE (
    echo  [~] sysmon64.exe nao encontrado. Baixando da Microsoft (Sysinternals)...
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
        "Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile '%~dp0_Sysmon.zip'"
    if errorlevel 1 (
        echo  [!] Falha no download. Baixe manualmente em https://learn.microsoft.com/sysinternals/downloads/sysmon
        echo      e coloque o sysmon64.exe ao lado deste script.
        pause
        exit /b 1
    )
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
        "Expand-Archive -Path '%~dp0_Sysmon.zip' -DestinationPath '%~dp0' -Force"
    if exist "%~dp0_Sysmon.zip" del "%~dp0_Sysmon.zip"
    set "SYSMON_EXE=%~dp0sysmon64.exe"
)

if not exist "%SYSMON_EXE%" (
    echo  [!] sysmon64.exe nao disponivel apos download.
    pause
    exit /b 1
)

REM --- 4. Aceita EULA e instala com a config endurecida ---
echo  [*] Instalando Sysmon com configuracao endurecida (hashing SHA-256, cmdline completa)...
"%SYSMON_EXE%" -accepteula -i "%~dp0sysmon-config-hardened.xml"
if errorlevel 1 (
    echo  [!] Falha ao instalar o driver Sysmon. Verifique assinatura/test mode.
    pause
    exit /b 1
)

REM --- 5. Validacao do canal de eventos ---
echo.
echo  [*] Validando canal de eventos Sysmon...
wevtutil gl Microsoft-Windows-Sysmon/Operational
echo.
echo  ============================================
echo   [OK] Sysmon instalado e coletando telemetria.
echo        O Sentinela XDR ingere automaticamente os eventos
echo        (IDs 1, 8, 10, 11, 13, 22, ...) no proximo ciclo.
echo  ============================================
pause
exit /b 0