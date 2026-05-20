"""
Launcher local — corre el servidor en 127.0.0.1:8000 y abre el navegador.

Uso:
    python run_local.py
    python run_local.py --port 9000 --no-browser
"""
import argparse
import logging
import socket
import threading
import time
import webbrowser

import uvicorn


class _QuietPollingFilter(logging.Filter):
    """Oculta del access log los endpoints de polling que no aportan info."""
    NOISY = ('GET /api/jobs HTTP', 'GET /api/jobs/')

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        # uvicorn.access loguea: '127.0.0.1:port - "GET /api/jobs HTTP/1.1" 200 OK'
        if 'GET /api/jobs HTTP' in msg:
            return False
        if '/events HTTP' in msg:
            return False
        return True


def open_browser_when_ready(url: str, host: str, port: int, timeout: float = 30.0):
    """Espera a que el puerto acepte conexiones, después abre el navegador."""
    def _wait_and_open():
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with socket.create_connection((host, port), timeout=0.5):
                    break
            except OSError:
                time.sleep(0.3)
        # Pequeño margen para que el handshake HTTP esté listo
        time.sleep(0.4)
        try:
            webbrowser.open(url)
        except Exception:
            pass
    threading.Thread(target=_wait_and_open, daemon=True).start()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--no-browser", action="store_true",
                        help="No abrir el navegador automáticamente")
    args = parser.parse_args()

    url = f"http://{args.host}:{args.port}/ui/"
    print()
    print("  ╔══════════════════════════════════════════════════╗")
    print("  ║  Reachflow — Verificador de Dominios (local)     ║")
    print("  ╠══════════════════════════════════════════════════╣")
    print(f"  ║  UI:      {url:<39}║")
    print(f"  ║  API:     http://{args.host}:{args.port}/docs"
          + " " * (50 - len(f"  API:     http://{args.host}:{args.port}/docs"))
          + "║")
    print("  ║  Stop:    Ctrl+C                                 ║")
    print("  ╚══════════════════════════════════════════════════╝")
    print()

    if not args.no_browser:
        # Conexión a localhost siempre como 127.0.0.1, evita ambigüedad ipv4/ipv6
        open_browser_when_ready(url, "127.0.0.1", args.port)

    # Filtrar el polling del sidebar y el stream SSE del access log
    logging.getLogger("uvicorn.access").addFilter(_QuietPollingFilter())

    uvicorn.run("app.main:app", host=args.host, port=args.port, reload=False, log_level="info")


if __name__ == "__main__":
    main()
