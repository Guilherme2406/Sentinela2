@echo off
chcp 65001 >nul
title Instalador SENTINEL XDR Sovereign
cd /d "%~dp0"

:: 0. Verifica se o PyQt6 (requisito da interface gráfica) está presente.
::    Se não estiver, o instalador abre em modo console (que instala as
::    dependências automaticamente antes de iniciar o serviço).
where python >nul 2>nul
if %errorlevel% equ 0 (
    python -c "import importlib.util,sys; sys.exit(0 if importlib.util.find_spec('PyQt6') else 1)" >nul 2>nul
    if not errorlevel 1 goto gui
    echo [i] PyQt6 nao encontrado. Abrindo o instalador em modo console...
    echo     (Ele instalara todas as dependencias automaticamente.)
    echo.
    python installer.py
    exit /b 0
)

:gui
:: 1. Tenta localizar pythonw ou python no PATH
where pythonw >nul 2>nul
if %errorlevel% equ 0 (
    start "" pythonw gui_installer.pyw
    exit /b 0
)

where python >nul 2>nul
if %errorlevel% equ 0 (
    start "" python gui_installer.pyw
    exit /b 0
)

where py >nul 2>nul
if %errorlevel% equ 0 (
    start "" py -m gui_installer.pyw
    exit /b 0
)

:: 2. Busca em diretórios reais conhecidos (pythoncore e Programs)
if exist "%LOCALAPPDATA%\Python\pythoncore-3.14-64\pythonw.exe" (
    start "" "%LOCALAPPDATA%\Python\pythoncore-3.14-64\pythonw.exe" gui_installer.pyw
    exit /b 0
)
if exist "%LOCALAPPDATA%\Python\pythoncore-3.13-64\pythonw.exe" (
    start "" "%LOCALAPPDATA%\Python\pythoncore-3.13-64\pythonw.exe" gui_installer.pyw
    exit /b 0
)
if exist "%LOCALAPPDATA%\Python\pythoncore-3.12-64\pythonw.exe" (
    start "" "%LOCALAPPDATA%\Python\pythoncore-3.12-64\pythonw.exe" gui_installer.pyw
    exit /b 0
)
if exist "%LOCALAPPDATA%\Programs\Python\Python314\pythonw.exe" (
    start "" "%LOCALAPPDATA%\Programs\Python\Python314\pythonw.exe" gui_installer.pyw
    exit /b 0
)
if exist "%LOCALAPPDATA%\Programs\Python\Python313\pythonw.exe" (
    start "" "%LOCALAPPDATA%\Programs\Python\Python313\pythonw.exe" gui_installer.pyw
    exit /b 0
)
if exist "%LOCALAPPDATA%\Programs\Python\Python312\pythonw.exe" (
    start "" "%LOCALAPPDATA%\Programs\Python\Python312\pythonw.exe" gui_installer.pyw
    exit /b 0
)
if exist "%LOCALAPPDATA%\Python\pythoncore-3.14-64\python.exe" (
    start "" "%LOCALAPPDATA%\Python\pythoncore-3.14-64\python.exe" gui_installer.pyw
    exit /b 0
)

:: Fallback se não encontrar
echo [ERRO] Python não foi localizado para abrir a interface gráfica.
echo Baixe gratuitamente em: https://www.python.org/downloads/
pause
exit /b 1
