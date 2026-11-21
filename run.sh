#!/usr/bin/env bash
# SMART SECURITY MONITOR - Lancement Linux/macOS
echo "======================================================================="
echo "  SMART SECURITY MONITOR - SYSTEME DE SURVEILLANCE ET D'ALARME (TP4)"
echo "======================================================================="

mkdir -p storage/recordings storage/screenshots storage/logs

# Démarrage simulateur mock en tâche de fond
python3 tests/mock_ipwebcam.py --port 8081 &
SIM_PID=$!
echo "[*] Simulateur démarré (PID: $SIM_PID)"

trap "kill $SIM_PID; exit" INT TERM EXIT

sleep 2
echo "[*] Démarrage du Monitoring Host sur http://127.0.0.1:5000"
python3 app.py
