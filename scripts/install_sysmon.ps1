<#
.SYNOPSIS
    Sentinela XDR - Instalador e Atualizador Silencioso e Endurecido do Microsoft Sysmon.
.DESCRIPTION
    Verifica privilégios de Administrador, localiza ou baixa a versão oficial do Sysmon da
    Sysinternals (Microsoft), aplica a configuração endurecida 'sysmon-config-hardened.xml'
    e valida o canal Microsoft-Windows-Sysmon/Operational.
    Gera manifesto de auditoria em sentinel_vault/sysmon_install_state.json.
.PARAMETER ForceUpdate
    Força a reaplicação da configuração mesmo se o Sysmon já estiver instalado.
.PARAMETER ConfigPath
    Caminho customizado para o arquivo de configuração XML do Sysmon.
#>

[CmdletBinding()]
param(
    [switch]$ForceUpdate,
    [string]$ConfigPath = ""
)

$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " 🛡️  SENTINELA XDR - INSTALADOR CORPORATIVO DO SYSMON" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Checa privilégios de Administrador
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "[!] ERRO CRÍTICO: Este script deve ser executado como ADMINISTRADOR / ELEVADO."
    exit 1
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Resolve-Path (Join-Path $ScriptDir "..")
$VaultDir = Join-Path $ProjectRoot "sentinel_vault"
if (-not (Test-Path $VaultDir)) {
    New-Item -ItemType Directory -Path $VaultDir -Force | Out-Null
}
$StateFile = Join-Path $VaultDir "sysmon_install_state.json"

if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    $ConfigPath = Join-Path $ProjectRoot "configs\sysmon\sysmon-config-hardened.xml"
}

if (-not (Test-Path $ConfigPath)) {
    Write-Error "[!] Arquivo de configuração endurecido não encontrado em: $ConfigPath"
    exit 1
}

Write-Host "[*] Utilizando configuração: $ConfigPath" -ForegroundColor Gray

# 2. Localiza ou faz download do Sysmon
$SysmonExe = ""
$Candidates = @(
    (Join-Path $ProjectRoot "configs\sysmon\sysmon64.exe"),
    (Join-Path $ScriptDir "sysmon64.exe"),
    (Join-Path $env:SystemRoot "sysmon64.exe")
)

foreach ($c in $Candidates) {
    if (Test-Path $c) {
        $SysmonExe = $c
        break
    }
}

if (-not $SysmonExe) {
    $SysmonCmd = Get-Command sysmon64.exe -ErrorAction SilentlyContinue
    if ($SysmonCmd) {
        $SysmonExe = $SysmonCmd.Source
    }
}

if (-not $SysmonExe) {
    Write-Host "[~] sysmon64.exe não encontrado localmente. Baixando da Microsoft Sysinternals..." -ForegroundColor Yellow
    $ZipPath = Join-Path $ScriptDir "_Sysmon.zip"
    $DownloadUrl = "https://download.sysinternals.com/files/Sysmon.zip"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $ZipPath -UseBasicParsing
        Expand-Archive -Path $ZipPath -DestinationPath $ScriptDir -Force
        Remove-Item $ZipPath -Force -ErrorAction SilentlyContinue
        $SysmonExe = Join-Path $ScriptDir "sysmon64.exe"
    } catch {
        Write-Error "[!] Falha ao baixar Sysmon automaticamente: $_. Baixe de https://learn.microsoft.com/sysinternals/downloads/sysmon"
        exit 1
    }
}

if (-not (Test-Path $SysmonExe)) {
    Write-Error "[!] Binário sysmon64.exe não disponível."
    exit 1
}

# 3. Verifica se o serviço já está instalado
$SysmonService = Get-Service -Name "Sysmon", "Sysmon64" -ErrorAction SilentlyContinue | Select-Object -First 1
$ActionTaken = ""

if ($SysmonService -and (-not $ForceUpdate)) {
    Write-Host "[i] Sysmon já está instalado e ativo (Serviço: $($SysmonService.Name)). Atualizando configuração..." -ForegroundColor Green
    & $SysmonExe -c $ConfigPath
    $ActionTaken = "UPDATED_CONFIG"
} else {
    Write-Host "[*] Instalando driver Sysmon com aceitação automática de EULA e configuração endurecida..." -ForegroundColor Yellow
    & $SysmonExe -accepteula -i $ConfigPath
    $ActionTaken = "FRESH_INSTALL"
}

# 4. Validação via wevtutil
$ChannelValid = $false
try {
    $evtOutput = & wevtutil gl Microsoft-Windows-Sysmon/Operational 2>&1
    if ($LASTEXITCODE -eq 0 -or ($evtOutput -match "enabled:\s*true")) {
        $ChannelValid = $true
        Write-Host "[✅] Canal Microsoft-Windows-Sysmon/Operational validado e ativo!" -ForegroundColor Green
    }
} catch {
    Write-Warning "[!] Falha ao verificar canal via wevtutil: $_"
}

# 5. Salva estado estruturado para o Sentinela XDR
$State = @{
    "installed" = $true
    "service_name" = if ($SysmonService) { $SysmonService.Name } else { "Sysmon64" }
    "action_taken" = $ActionTaken
    "channel_active" = $ChannelValid
    "config_path" = $ConfigPath
    "installed_at" = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    "sysmon_binary" = $SysmonExe
}

$State | ConvertTo-Json -Depth 4 | Set-Content -Path $StateFile -Encoding UTF8
Write-Host "[✅] Manifesto de telemetria salvo com sucesso em: $StateFile" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
