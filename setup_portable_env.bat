@echo off
REM Prépare un environnement Python portable avec micromamba et installe requirements
cd /d "%~dp0"

set ROOT=portable_env
if not exist "%ROOT%" mkdir "%ROOT%"

REM Déterminer l'architecture Windows (win-64 ou win-32)
set ARCH=win-64
if /I "%PROCESSOR_ARCHITECTURE%"=="x86" set ARCH=win-32
if /I "%PROCESSOR_ARCHITEW6432%"=="x86" set ARCH=win-32

echo [INFO] Téléchargement de micromamba (%ARCH%)...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'https://micro.mamba.pm/api/micromamba/%ARCH%/latest' -OutFile '%ROOT%\micromamba.exe'"
if %ERRORLEVEL% NEQ 0 (
  echo [ERREUR] Échec du téléchargement de micromamba.
  echo Essayez de lancer PowerShell en tant qu'administrateur ou vérifiez la connexion Internet.
  exit /b 1
)

echo [INFO] Création de l'environnement 'nas'...
"%ROOT%\micromamba.exe" create -y -r "%ROOT%" -n nas python=3.12 pip
if %ERRORLEVEL% NEQ 0 (
  echo [ERREUR] Échec de création de l'environnement.
  echo Si le binaire n'est pas compatible, relancez ce script après avoir basculé d'architecture.
  exit /b 1
)

echo [INFO] Installation des dépendances depuis requirements.txt ...
"%ROOT%\micromamba.exe" run -r "%ROOT%" -n nas python -m pip install -r requirements.txt
if %ERRORLEVEL% NEQ 0 (
  echo [ERREUR] Échec d'installation des dépendances.
  exit /b 1
)

echo [SUCCES] Environnement portable prêt.
echo Utilisez run_server.bat ou run_client.bat pour démarrer.