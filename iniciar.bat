@echo off
title Sentinela Security Engine - SIEM / XDR / SOAR
chcp 65001 >nul
cls
echo ===================================================================
echo   🛡️  INICIANDO SENTINELA SECURITY ENGINE (XDR / SIEM / SOAR)  🛡️
echo ===================================================================
echo.
echo [+] Verificando ambiente Python...
python --version
if errorlevel 1 (
    echo [ERRO] Python nao foi encontrado no PATH. Por favor instale o Python.
    pause
    exit /b 1
)

echo [+] Iniciando o Sentinela Engine e Dashboard Web...
python main.py
pause
