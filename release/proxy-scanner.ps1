<#
.SYNOPSIS
  Запуск Proxy Scanner на Windows со всеми подготовительными шагами.

.DESCRIPTION
  * запрашивает права администратора (UAC) — они нужны режиму masscan;
  * снимает с файлов «метку интернета» (Zone.Identifier), из-за которой
    SmartScreen блокирует или предупреждает при запуске скачанных exe;
  * проверяет Npcap и, если его нет, запускает установщик npcap-*.exe,
    лежащий рядом со скриптом (в закрытом контуре положите его заранее);
  * запускает proxy-scanner.exe с переданными аргументами.

  Удобнее запускать через proxy-scanner.cmd (двойной щелчок): он обходит
  политику выполнения скриптов PowerShell.

.PARAMETER User
  Не запрашивать права администратора (доступен только режим TCP-connect).

.PARAMETER NoInstall
  Не запускать установщик Npcap.

.PARAMETER CheckOnly
  Только выполнить проверки и вывести результат, программу не запускать.

.EXAMPLE
  .\proxy-scanner.ps1
  .\proxy-scanner.ps1 -User
  .\proxy-scanner.ps1 --renderer glow
#>
[CmdletBinding()]
param(
    [switch]$User,
    [switch]$NoInstall,
    [switch]$CheckOnly,
    [switch]$Elevated,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$AppArgs
)

$ErrorActionPreference = 'Stop'
$Dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$App = Join-Path $Dir 'proxy-scanner.exe'
$Masscan = Join-Path $Dir 'masscan64.exe'
if ($null -eq $AppArgs) { $AppArgs = @() }

function Say([string]$m)  { Write-Host "[proxy-scanner] $m" -ForegroundColor Cyan }
function Warn([string]$m) { Write-Host "[proxy-scanner] $m" -ForegroundColor Yellow }
function Fail([string]$m) {
    Write-Host "[proxy-scanner] $m" -ForegroundColor Red
    if (-not $CheckOnly) { Read-Host 'Нажмите Enter, чтобы закрыть окно' | Out-Null }
    exit 1
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-Npcap {
    $root = $env:SystemRoot
    foreach ($p in @('System32\Npcap\wpcap.dll', 'System32\wpcap.dll', 'SysWOW64\Npcap\wpcap.dll')) {
        if (Test-Path (Join-Path $root $p)) { return $true }
    }
    return $false
}

# Кавычки для аргументов командной строки Windows.
function Quote([string]$a) {
    if ($a -eq '') { return '""' }
    if ($a -notmatch '[\s"]') { return $a }
    '"' + ($a -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"'
}

if (-not (Test-Path $App)) { Fail "Не найден $App. Положите скрипт рядом с программой." }

# 1. Права администратора (кроме режима -User и проверки).
if (-not $User -and -not $CheckOnly -and -not (Test-Admin)) {
    if ($Elevated) { Fail 'Не удалось получить права администратора.' }
    Say 'Запрашиваю права администратора (нужны для режима masscan)...'
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Quote $MyInvocation.MyCommand.Path), '-Elevated')
    if ($NoInstall) { $argList += '-NoInstall' }
    $argList += ($AppArgs | ForEach-Object { Quote $_ })
    try {
        Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList ($argList -join ' ') | Out-Null
    } catch {
        Warn 'Повышение прав отклонено. Запускаю без прав администратора: доступен только TCP-connect.'
        $User = $true
    }
    if (-not $User) { exit 0 }
}

if (Test-Admin) { Say 'Права: администратор' } else { Warn 'Права: обычный пользователь — режим masscan недоступен' }

# 2. Снять «метку интернета» с файлов (SmartScreen / «файл заблокирован»).
$files = @($App, $Masscan, (Join-Path $Dir 'proxy-scanner.ps1')) + @(Get-ChildItem -Path $Dir -Filter 'npcap-*.exe' -ErrorAction SilentlyContinue | ForEach-Object FullName)
foreach ($f in $files) {
    if (Test-Path $f) {
        $zone = Get-Item -Path $f -Stream 'Zone.Identifier' -ErrorAction SilentlyContinue
        if ($zone) {
            if ($CheckOnly) { Warn "Файл помечен как скачанный из интернета: $(Split-Path -Leaf $f)" }
            else { Unblock-File -Path $f; Say "Снята метка интернета: $(Split-Path -Leaf $f)" }
        }
    }
}

# 3. masscan рядом с программой.
if (Test-Path $Masscan) { Say 'masscan64.exe найден' } else { Warn 'masscan64.exe не найден рядом с программой — режим masscan будет недоступен' }

# 4. Npcap.
if (Test-Npcap) {
    Say 'Npcap установлен'
} else {
    $installer = Get-ChildItem -Path $Dir -Filter 'npcap-*.exe' -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
    if ($installer -and -not $NoInstall -and -not $CheckOnly -and (Test-Admin)) {
        Say "Npcap не установлен — запускаю установщик $($installer.Name)"
        Say 'В установщике оставьте настройки по умолчанию; режим совместимости с WinPcap не нужен.'
        Start-Process -FilePath $installer.FullName -Wait
        if (Test-Npcap) { Say 'Npcap установлен' } else { Warn 'Npcap так и не установлен — режим masscan работать не будет' }
    } else {
        Warn 'Npcap не установлен: режим masscan работать не будет, TCP-connect работает.'
        if (-not $installer) {
            Warn 'Скачайте установщик с https://npcap.com/#download и положите npcap-*.exe рядом со скриптом —'
            Warn 'при следующем запуске скрипт установит его сам.'
        }
    }
}

if ($CheckOnly) {
    Say "Аргументы программы: [$($AppArgs -join '] [')]"
    Say 'Проверка завершена, программа не запускалась (-CheckOnly).'
    exit 0
}

# 5. Запуск программы.
Say "Запуск: $App $($AppArgs -join ' ')"
$startArgs = @{ FilePath = $App; WorkingDirectory = $Dir }
if ($AppArgs.Count -gt 0) { $startArgs.ArgumentList = (($AppArgs | ForEach-Object { Quote $_ }) -join ' ') }
try {
    Start-Process @startArgs | Out-Null
} catch {
    Fail "Не удалось запустить программу: $($_.Exception.Message)"
}
