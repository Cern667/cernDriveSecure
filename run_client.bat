@echo off
REM Démarre le client Flask avec Python portable/venv/micromamba
cd /d "%~dp0"

REM Priorité: Python portable, puis venv/système, puis micromamba

if exist "python_portable\python.exe" (
  echo [INFO] Utilisation de Python portable (embeddable).
  python_portable\python.exe -m pip install -r requirements.txt
  echo [INFO] Démarrage du client Flask sur http://localhost:5000 ...
  python_portable\python.exe dossier_client\app.py
  exit /b %ERRORLEVEL%
)

if exist "python_portable\python.exe" (
  echo [INFO] Utilisation de Python portable (embeddable).
  python_portable\python.exe -m pip install -r requirements.txt
  echo [INFO] Démarrage du client Flask sur http://localhost:5000 ...
  python_portable\python.exe dossier_client\app.py
  exit /b %ERRORLEVEL%
)

set RUNPY=
if exist ".venv\Scripts\python.exe" set RUNPY=.venv\Scripts\python.exe
if not defined RUNPY (
  where python >nul 2>nul && set RUNPY=python
)
if not defined RUNPY (
  where py >nul 2>nul && set RUNPY=py
)
if not defined RUNPY (
  echo [ERREUR] Aucun Python trouvé. Exécutez d'abord setup_venv.bat.
  exit /b 1
)

echo [INFO] Installation des dépendances (si besoin)...
"%RUNPY%" -m pip install -r requirements.txt

echo [INFO] Démarrage du client Flask sur http://localhost:5000 ...
"%RUNPY%" dossier_client\app.py

REM Dernier recours: micromamba portable
if exist "portable_env\micromamba.exe" (
  echo [INFO] Tentative avec l'environnement portable micromamba.
  portable_env\micromamba.exe run -r portable_env -n nas python -m pip install -r requirements.txt || goto :next
  echo [INFO] Démarrage du client Flask sur http://localhost:5000 ...
  portable_env\micromamba.exe run -r portable_env -n nas python dossier_client\app.py
  exit /b %ERRORLEVEL%
)

:next