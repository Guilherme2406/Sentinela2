@echo off
chcp 65001 >nul
title Instalador SENTINEL XDR (Modo Administrador)
cd /d "%~dp0"

:: Auto-elevação de privilégios para Administrador
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -Command "Start-Process cmd -ArgumentList '/c cd /d ""%~dp0"" && instalar.bat' -Verb RunAs"
    exit /b
)

call instalar.bat
