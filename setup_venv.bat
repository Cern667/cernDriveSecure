@echo off
REM Crée un environnement virtuel Python et installe les dépendances
cd /d "%~dp0"

setlocal
set PYEXE=

where py >nul 2>nul && set PYEXE=py
if not defined PYEXE (
  where python >nul 2>nul && set PYEXE=python
)

if not defined PYEXE (
  echo [ERREUR] Python n'est pas installé ou introuvable dans PATH.
  echo Installez Python 3 puis relancez ce script.
  echo Exemples:
  echo   winget install -e --id Python.Python.3.12
  echo   OU téléchargez depuis https://www.python.org/downloads/
  exit /b 1
)

echo [INFO] Création de l'environnement virtuel .venv ...
%PYEXE% -m venv .venv
if %ERRORLEVEL% NEQ 0 (
  echo [ERREUR] Échec de création de l'environnement virtuel.
  exit /b 1
)

echo [INFO] Activation et installation des dépendances ...
call ".venv\Scripts\activate"
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
if %ERRORLEVEL% NEQ 0 (
  echo [ERREUR] Échec d'installation des dépendances.
  exit /b 1
)

echo [SUCCES] Environnement prêt.
echo Pour l'activer: .venv\Scripts\activate
echo Ensuite: run_server.bat (serveur) ou run_client.bat (client)

endlocal