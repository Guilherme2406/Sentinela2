@echo off
chcp 65001 >nul
title Desinstalador SENTINEL XDR Sovereign
cls
echo ==========================================================
echo   Iniciando o Assistente de Desinstalacao do SENTINEL XDR...
echo ==========================================================
echo.
cd /d "%~dp0"
python uninstaller.py
pause
