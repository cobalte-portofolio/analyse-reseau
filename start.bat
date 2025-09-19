@echo off
:: Vérifie si admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Relance en mode administrateur...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: Commandes une fois admin
pip install scapy
python tcp-detect.py
pause
