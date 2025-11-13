@echo off
REM Démarre le serveur de stockage (socket) avec Python portable/venv/micromamba
cd /d "%~dp0"

REM Priorité: Python portable uniquement (simplifié)

if exist "python_portable\python.exe" (
  echo [INFO] Utilisation de Python portable (embeddable).
  python_portable\python.exe -m pip install -r requirements.txt
  python_portable\python.exe dossier_server\server.py
  exit /b %ERRORLEVEL%
)

echo [ERREUR] Python portable introuvable. Exécutez setup_portable_python.bat.
exit /b 1