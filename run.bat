@echo off
chcp 65001 >nul
echo =======================================================================
echo   SMART SECURITY MONITOR - SYSTEME DE SURVEILLANCE ET D'ALARME (TP4)
echo =======================================================================
echo.

:: Verifier Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERREUR] Python n'est pas installe ou n'est pas present dans le PATH.
    pause
    exit /b 1
)

:: Creer les dossiers de stockage si necessaires
if not exist "storage\recordings" mkdir storage\recordings
if not exist "storage\screenshots" mkdir storage\screenshots
if not exist "storage\logs" mkdir storage\logs
if not exist "storage\backups" mkdir storage\backups

echo [1/3] Demarrage du Simulateur Mock IP Webcam sur http://127.0.0.1:8081 ...
start "Mock IP Webcam Simulator" /min python tests\mock_ipwebcam.py --port 8081

echo [2/3] Pause de 2 secondes pour initialisation...
timeout /t 2 /nobreak >nul

echo [3/3] Demarrage du Monitoring Host Flask sur http://127.0.0.1:5000 ...
echo.
echo Ouvrez votre navigateur sur : http://127.0.0.1:5000
echo Appuyez sur Ctrl+C pour arreter le serveur.
echo.

python app.py

pause
