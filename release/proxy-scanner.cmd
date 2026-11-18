@echo off
rem Proxy Scanner launcher: runs proxy-scanner.ps1 bypassing the PowerShell execution policy.
rem Usage: proxy-scanner.cmd [-User] [-NoInstall] [-CheckOnly] [program arguments]
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0proxy-scanner.ps1" %*
if errorlevel 1 pause
