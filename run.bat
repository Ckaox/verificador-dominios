@echo off
setlocal enableextensions

REM ===========================================================
REM Reachflow - Verificador de Dominios (launcher local)
REM Doble-click para arrancar. Crea venv la primera vez.
REM ===========================================================

cd /d "%~dp0"

echo.
echo === Reachflow - Verificador de Dominios ===
echo.

REM -- 1. Detectar Python --
set "PY_CMD="
where python >nul 2>nul && set "PY_CMD=python"
if not defined PY_CMD where py >nul 2>nul && set "PY_CMD=py -3"

if not defined PY_CMD (
  echo ERROR: Python no encontrado en PATH.
  echo.
  echo   Instala Python 3.10 o superior desde https://www.python.org/downloads/
  echo   Durante la instalacion marca la casilla "Add Python to PATH".
  echo.
  pause
  exit /b 1
)

REM -- 2. Crear venv si no existe --
if not exist ".venv\Scripts\python.exe" (
  echo [1/3] Creando entorno virtual .venv ...
  %PY_CMD% -m venv .venv
  if errorlevel 1 (
    echo ERROR: no se pudo crear el entorno virtual.
    pause
    exit /b 1
  )
)

REM -- 3. Activar venv --
call ".venv\Scripts\activate.bat"
if errorlevel 1 (
  echo ERROR: no se pudo activar .venv.
  pause
  exit /b 1
)

REM -- 4. Instalar/actualizar dependencias --
echo [2/3] Instalando dependencias ...
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt
if errorlevel 1 (
  echo ERROR: fallo el pip install. Reviza tu conexion a internet.
  pause
  exit /b 1
)

REM -- 5. Arrancar app --
echo [3/3] Iniciando servidor ...
echo.
python run_local.py
if errorlevel 1 (
  echo.
  echo El servidor termino con error. Mira el mensaje arriba.
  pause
)
endlocal
