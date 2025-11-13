@echo off
REM Prépare un Python portable (embeddable zip) et installe requirements
cd /d "%~dp0"

set PDIR=python_portable
if not exist "%PDIR%" mkdir "%PDIR%"

REM Déterminer l'architecture et la version à télécharger
set ARCH=amd64
if /I "%PROCESSOR_ARCHITECTURE%"=="x86" set ARCH=win32
if /I "%PROCESSOR_ARCHITEW6432%"=="x86" set ARCH=win32
set PYVER=3.11.9

echo [INFO] Téléchargement de Python portable %PYVER% (%ARCH%)...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/%PYVER%/python-%PYVER%-embed-%ARCH%.zip' -OutFile '%PDIR%\python-embed.zip'"
if %ERRORLEVEL% NEQ 0 (
  echo [ERREUR] Échec du téléchargement du zip embeddable.
  exit /b 1
)

echo [INFO] Extraction...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Expand-Archive -Path '%PDIR%\python-embed.zip' -DestinationPath '%PDIR%' -Force"
if %ERRORLEVEL% NEQ 0 (
  echo [ERREUR] Échec d'extraction.
  exit /b 1
)

echo [INFO] Activation de 'import site' pour les packages...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$p=Get-ChildItem -Path '%PDIR%' -Filter 'python*._pth' | Select-Object -First 1; if (!$p) { Write-Error 'PTH file not found'; exit 1 }; (Get-Content $p.FullName) -replace '^#import site','import site' | Set-Content $p.FullName"

echo [INFO] Installation de pip (get-pip.py)...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'https://bootstrap.pypa.io/get-pip.py' -OutFile '%PDIR%\get-pip.py'"
"%PDIR%\python.exe" "%PDIR%\get-pip.py"
if %ERRORLEVEL% NEQ 0 (
  echo [ERREUR] Échec d'installation de pip.
  exit /b 1
)

echo [INFO] Vérification de pip...
"%PDIR%\python.exe" -m pip --version || (
  echo [ERREUR] pip introuvable via -m; vérifiez le fichier ._pth.
  exit /b 1
)

echo [INFO] Installation des dépendances depuis requirements.txt ...
"%PDIR%\python.exe" -m pip install -r requirements.txt
if %ERRORLEVEL% NEQ 0 (
  echo [ERREUR] Échec d'installation des dépendances.
  exit /b 1
)

echo [SUCCES] Python portable prêt.
echo Utilisez run_server.bat ou run_client.bat (ils détecteront python_portable).