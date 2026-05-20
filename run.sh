#!/usr/bin/env bash
# Reachflow - Verificador de Dominios (launcher local para macOS/Linux)
set -e

cd "$(dirname "$0")"

echo ""
echo "=== Reachflow - Verificador de Dominios ==="
echo ""

# 1. Detectar Python
if command -v python3 >/dev/null 2>&1; then
  PY=python3
elif command -v python >/dev/null 2>&1; then
  PY=python
else
  echo "ERROR: Python no encontrado."
  echo "  Instala Python 3.10+ desde https://www.python.org/downloads/"
  exit 1
fi

# 2. Crear venv
if [ ! -f ".venv/bin/python" ]; then
  echo "[1/3] Creando entorno virtual .venv ..."
  $PY -m venv .venv
fi

# 3. Activar venv
# shellcheck disable=SC1091
source .venv/bin/activate

# 4. Instalar deps
echo "[2/3] Instalando dependencias ..."
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt

# 5. Arrancar
echo "[3/3] Iniciando servidor ..."
echo ""
python run_local.py
