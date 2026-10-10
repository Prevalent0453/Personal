@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0fix-network.ps1" %*
