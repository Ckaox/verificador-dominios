"""API para verificación de registros DNS de dominios y descubrimiento de dominios corporativos"""
from fastapi import FastAPI, HTTPException, status, Query, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from datetime import datetime
from pathlib import Path
import csv as csvlib
import io
import json
import re
import os
import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, Dict

from .models import (
    DNSInfo, EmailSecuritySummary, MXRecord, SPFRecord, DMARCRecord, DKIMRecord,
    BulkCheckRequest,
)
from .utils import DNSChecker, DomainDiscovery, Job


# ---------------------------------------------------------------------------
# Aplicación FastAPI
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Verificador DNS & Descubridor de Dominios",
    description=(
        "API para verificar registros DNS (MX, SPF, DMARC, DKIM) y descubrir "
        "dominios secundarios de una empresa mediante Certificate Transparency (crt.sh) "
        "y generación de variantes de marca/TLD. Útil para cold email prospecting."
    ),
    version="3.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def validate_domain(domain: str) -> str:
    """Valida y limpia el formato del dominio."""
    domain = domain.lower()
    domain = re.sub(r'^https?://', '', domain)
    domain = re.sub(r'^www\.', '', domain)
    domain = domain.split('/')[0]

    domain_pattern = r'^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$'
    if not re.match(domain_pattern, domain):
        raise ValueError(f"Formato de dominio inválido: {domain}")

    return domain


def calculate_email_security_summary(dns_info: DNSInfo) -> EmailSecuritySummary:
    """Calcula un resumen de seguridad de correo electrónico."""
    spf_ok = dns_info.spf.has_spf and dns_info.spf.valid
    dmarc_ok = dns_info.dmarc.has_dmarc and dns_info.dmarc.valid
    dkim_ok = dns_info.dkim.has_dkim and dns_info.dkim.valid

    configured_count = sum([spf_ok, dmarc_ok, dkim_ok])

    if configured_count == 3:
        score = "Excellent"
    elif configured_count == 2:
        score = "Good"
    elif configured_count == 1:
        score = "Fair"
    else:
        score = "Poor"

    recommendations = []

    if not spf_ok:
        recommendations.append(
            "Configurar SPF: Añade un registro TXT con 'v=spf1' para especificar "
            "qué servidores pueden enviar correos en nombre de tu dominio"
        )

    if not dmarc_ok:
        recommendations.append(
            "Configurar DMARC: Añade un registro TXT en '_dmarc.tudominio.com' "
            "con 'v=DMARC1' para proteger contra suplantación de identidad"
        )

    if not dkim_ok:
        recommendations.append(
            "Configurar DKIM: Genera claves DKIM con tu proveedor de correo "
            "y añade los registros TXT correspondientes"
        )

    if configured_count == 3:
        recommendations.append(
            "¡Excelente! Tu dominio tiene todas las configuraciones de seguridad de correo recomendadas."
        )

    return EmailSecuritySummary(
        spf_configured=spf_ok,
        dmarc_configured=dmarc_ok,
        dkim_configured=dkim_ok,
        all_configured=(configured_count == 3),
        security_score=score,
        recommendations=recommendations,
    )


# ---------------------------------------------------------------------------
# Endpoints – Información general
# ---------------------------------------------------------------------------

@app.get("/", tags=["Info"])
async def root():
    """Información de la API y listado de endpoints disponibles."""
    return {
        "message": "API de Verificación DNS & Descubrimiento de Dominios",
        "version": "3.0.0",
        "endpoints": {
            # DNS clásico
            "dns_check":       "GET  /api/dns/{domain}                   – Verificación DNS completa (MX, SPF, DMARC, DKIM, blacklists)",
            # Descubrimiento por crt.sh
            "crtsh_domain":    "GET  /api/discover/crtsh/domain/{domain} – Subdominios via Certificate Transparency",
            "crtsh_org":       "GET  /api/discover/crtsh/org/{org}       – Todos los dominios de una organización via crt.sh",
            # Variantes de marca
            "variants":        "GET  /api/discover/variants/{domain}     – Variantes de marca + TLD y verificación DNS",
            "variants_list":   "GET  /api/discover/variants/{domain}/list– Solo la lista de variantes sin verificar",
            # Verificación masiva
            "bulk_check":      "POST /api/discover/bulk                  – Verificación masiva de una lista de dominios",
            # Salud
            "health":          "GET  /api/health                         – Estado del servidor",
            "docs":            "GET  /docs                               – Documentación interactiva Swagger",
        },
    }


@app.get("/api/health", tags=["Info"])
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "version": "3.0.0",
    }


# ---------------------------------------------------------------------------
# Endpoints – Verificación DNS clásica
# ---------------------------------------------------------------------------

@app.get("/api/dns/{domain}", tags=["DNS"])
async def verify_dns(
    domain: str,
    include_whois: bool = Query(
        default=False,
        description="Incluir información WHOIS (edad, registrar). Añade ~3-5 s de latencia."
    ),
):
    """
    Verificación DNS completa de un dominio.

    Incluye: registros MX (con detección de proveedor), SPF, DMARC, DKIM,
    verificación en blacklists y resumen de seguridad.

    **Parámetros:**
    - `include_whois=true` — añade edad del dominio y registrar (+3-5 s).
      Por defecto desactivado para maximizar velocidad.
    """
    try:
        clean_domain = validate_domain(domain)

        dns_checker = DNSChecker()

        loop = asyncio.get_event_loop()
        if include_whois:
            with ThreadPoolExecutor() as executor:
                whois_future = loop.run_in_executor(
                    executor, dns_checker.check_domain_age, clean_domain
                )
                dns_data = await dns_checker.check_all_async(clean_domain)
                domain_age = await whois_future
        else:
            dns_data = await dns_checker.check_all_async(clean_domain)
            domain_age = None

        dns_info = DNSInfo(
            domain=dns_data['domain'],
            mx=MXRecord(**dns_data['mx']),
            spf=SPFRecord(**dns_data['spf']),
            dmarc=DMARCRecord(**dns_data['dmarc']),
            dkim=DKIMRecord(**dns_data['dkim']),
        )

        email_summary = calculate_email_security_summary(dns_info)

        dmarc_details = None
        if dns_data['dmarc'].get('has_dmarc') and dns_data['dmarc'].get('record'):
            dmarc_details = dns_checker.parse_dmarc_detailed(dns_data['dmarc']['record'])

        clean_domain_age = (
            {k: v for k, v in domain_age.items() if k not in ['error', 'has_info']}
            if domain_age else None
        )

        provider = dns_data['mx'].get('provider', 'Unknown')

        return {
            "domain": clean_domain,
            "success": True,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "provider": provider,
            "dns": {
                "mx": dns_info.mx.dict(),
                "spf": dns_info.spf.dict(),
                "dkim": dns_info.dkim.dict(),
                "dmarc": dns_info.dmarc.dict(),
                "dmarc_details": dmarc_details,
            },
            "blacklists": dns_data['blacklists'],
            "domain_age": clean_domain_age,
            "summary": {
                "spf_configured": email_summary.spf_configured,
                "dmarc_configured": email_summary.dmarc_configured,
                "dkim_configured": email_summary.dkim_configured,
                "all_configured": email_summary.all_configured,
            },
        }

    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al verificar DNS: {str(e)}",
        )


# ---------------------------------------------------------------------------
# Endpoints – Descubrimiento via Certificate Transparency (crt.sh)
# ---------------------------------------------------------------------------

@app.get("/api/discover/crtsh/domain/{domain}", tags=["Descubrimiento"])
async def discover_crtsh_by_domain(domain: str):
    """
    Busca en Certificate Transparency (crt.sh) todos los subdominios para
    los que se han emitido certificados SSL que incluyen *.{domain}.

    Muy útil para mapear la infraestructura pública de una empresa.

    - **domain**: Dominio raíz, ej: `example.com`
    """
    try:
        clean_domain = validate_domain(domain)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    discovery = DomainDiscovery()
    result = await discovery.search_crtsh_by_domain(clean_domain)
    result["timestamp"] = datetime.utcnow().isoformat() + "Z"
    return result


@app.get("/api/discover/crtsh/org/{org_name}", tags=["Descubrimiento"])
async def discover_crtsh_by_org(org_name: str):
    """
    Busca en Certificate Transparency (crt.sh) por **nombre de organización**
    (campo O= del certificado). Devuelve TODOS los dominios para los que esa
    empresa ha emitido certificados: dominios principales, secundarios,
    proyectos internos, microsites, etc.

    Esta es la fuente más potente para descubrir el portfolio de dominios
    de una empresa sin necesidad de API key.

    - **org_name**: Nombre de la organización, ej: `Acme Corporation` o `acme`

    **Tip cold email**: Los dominios raíz (`root_domains`) son los más
    interesantes para buscar contactos adicionales.
    """
    if not org_name or len(org_name.strip()) < 2:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El nombre de organización debe tener al menos 2 caracteres.",
        )

    discovery = DomainDiscovery()
    result = await discovery.search_crtsh_by_org(org_name.strip())
    result["timestamp"] = datetime.utcnow().isoformat() + "Z"
    return result


# ---------------------------------------------------------------------------
# Endpoints – Variantes de marca y TLD
# ---------------------------------------------------------------------------

@app.get("/api/discover/variants/{domain}", tags=["Variantes"])
async def discover_variants(
    domain: str,
    max_concurrent: int = Query(default=25, ge=1, le=50, description="Consultas DNS simultáneas"),
    enrich: bool = Query(
        default=False,
        description="Enriquecer dominios activos con DMARC, DKIM y redirección HTTP. "
                    "Añade ~3-5 s. Desactivado por defecto para volumen alto (Clay, etc)."
    ),
):
    """
    Genera todas las variantes de marca (sufijos/prefijos) y TLD para un
    dominio y verifica en paralelo cuáles están activas (resuelven DNS o
    tienen registros MX configurados).

    **Parámetros:**
    - `enrich=false` *(defecto)* — solo DNS+MX, ~5-8 s. Ideal para 30k filas en Clay.
    - `enrich=true` — añade DMARC/DKIM/redirect en dominios activos, ~8-13 s.

    **Campos de respuesta clave:**
    - `active_domains`: dominios que resuelven o tienen MX
    - `with_mx_count`: cuántos tienen correo configurado
    - `all_results`: resultado completo de todos los dominios verificados
    """
    try:
        clean_domain = validate_domain(domain)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    discovery = DomainDiscovery()
    result = await discovery.check_variants_bulk(clean_domain, max_concurrent=max_concurrent, enrich=enrich)
    result["timestamp"] = datetime.utcnow().isoformat() + "Z"
    return result


@app.get("/api/discover/variants/{domain}/list", tags=["Variantes"])
async def list_variants(domain: str):
    """
    Devuelve únicamente la lista de variantes generadas para un dominio,
    **sin** realizar ninguna verificación DNS. Útil para previsualizar
    qué dominios se van a comprobar.

    - **domain**: Dominio base, ej: `prueba.com`
    """
    try:
        clean_domain = validate_domain(domain)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    discovery = DomainDiscovery()
    variants = discovery.generate_variants(clean_domain)

    return {
        "base_domain": clean_domain,
        "total": len(variants),
        "variants": variants,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


# ---------------------------------------------------------------------------
# Endpoints – Verificación masiva personalizada
# ---------------------------------------------------------------------------

@app.post("/api/discover/bulk", tags=["Verificación masiva"])
async def bulk_check(
    request: BulkCheckRequest,
    max_concurrent: int = Query(default=25, ge=1, le=50, description="Consultas DNS simultáneas"),
    enrich: bool = Query(
        default=False,
        description="Enriquecer dominios activos con DMARC, DKIM y redirección HTTP. Desactivado por defecto."
    ),
):
    """
    Verifica en paralelo una lista personalizada de dominios.

    Para cada dominio comprueba:
    - Si resuelve (registro A/AAAA)
    - Si tiene registros MX y qué proveedor de correo usa
    - Si está "likely_used" (resuelve O tiene MX)

    **Límite**: 500 dominios por petición.

    **Ejemplo de body:**
    ```json
    {
      "domains": [
        "pruebago.com",
        "getprueba.com",
        "prueba.es",
        "prueba.io"
      ]
    }
    ```
    """
    discovery = DomainDiscovery()
    result = await discovery.check_domains_bulk(request.domains, max_concurrent=max_concurrent, enrich=enrich)
    result["timestamp"] = datetime.utcnow().isoformat() + "Z"
    return result


# ---------------------------------------------------------------------------
# Procesador local de CSVs (Reachflow UI)
# ---------------------------------------------------------------------------

# Registro en memoria de jobs activos (uno por proceso)
_jobs: Dict[str, Job] = {}


def _get_job(job_id: str) -> Job:
    if job_id in _jobs:
        return _jobs[job_id]
    try:
        job = Job.load(job_id)
        _jobs[job_id] = job
        return job
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' no encontrado")


@app.get("/api/jobs", tags=["CSV Jobs"])
async def list_jobs():
    """Lista todos los jobs guardados (para retomar después de reiniciar)."""
    return {"jobs": Job.list_all()}


@app.post("/api/jobs/upload", tags=["CSV Jobs"])
async def upload_csv(file: UploadFile = File(...)):
    """
    Sube un CSV y devuelve las columnas detectadas + una preview.
    Aún no crea un job — eso lo hace `/api/jobs/create`.
    """
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Archivo vacío")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = content.decode("latin-1")

    reader = csvlib.DictReader(io.StringIO(text))
    columns = reader.fieldnames or []
    preview = []
    total = 0
    for i, row in enumerate(reader):
        if i < 5:
            preview.append(row)
        total += 1

    if not columns:
        raise HTTPException(status_code=400, detail="No se detectaron columnas en el CSV")

    # Guardar temporalmente en data/tmp para crear el job después
    tmp_dir = Path("./data/tmp")
    tmp_dir.mkdir(parents=True, exist_ok=True)
    import uuid as _uuid
    tmp_id = _uuid.uuid4().hex[:12]
    tmp_path = tmp_dir / f"{tmp_id}.csv"
    tmp_path.write_text(text, encoding="utf-8", newline="")

    return {
        "upload_id": tmp_id,
        "filename": file.filename,
        "columns": columns,
        "total_rows": total,
        "preview": preview,
    }


@app.post("/api/jobs/create", tags=["CSV Jobs"])
async def create_job(
    upload_id: str = Form(...),
    filename: str = Form(...),
    domain_column: str = Form(...),
    discover_variants: bool = Form(True),
    variants_mode: str = Form("cascade"),  # cascade | full | cold | none
    per_row_timeout: int = Form(180),
    max_concurrent: int = Form(25),
    parallel_workers: int = Form(5),
    do_whois: bool = Form(False),
    autostart: bool = Form(True),
):
    """Crea un job a partir de un CSV subido previamente."""
    tmp_path = Path("./data/tmp") / f"{upload_id}.csv"
    if not tmp_path.exists():
        raise HTTPException(status_code=404, detail="Upload expirado, vuelve a subir el CSV")
    content = tmp_path.read_bytes()
    try:
        job = Job.create(
            content, filename, domain_column,
            options={
                "discover_variants": discover_variants,
                "variants_mode": variants_mode,
                "per_row_timeout": per_row_timeout,
                "max_concurrent": max_concurrent,
                "parallel_workers": parallel_workers,
                "do_whois": do_whois,
            },
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    _jobs[job.state.id] = job
    try:
        tmp_path.unlink()
    except Exception:
        pass
    if autostart:
        job.start()
    return {"job_id": job.state.id, "snapshot": job.snapshot()}


@app.get("/api/jobs/{job_id}", tags=["CSV Jobs"])
async def get_job(job_id: str):
    job = _get_job(job_id)
    return job.snapshot()


@app.post("/api/jobs/{job_id}/start", tags=["CSV Jobs"])
async def start_job(job_id: str):
    job = _get_job(job_id)
    if job.state.status in ("running",):
        return {"ok": True, "status": job.state.status}
    if job.state.status == "completed":
        raise HTTPException(status_code=400, detail="Job ya completado")
    job.start()
    return {"ok": True, "status": job.state.status}


@app.post("/api/jobs/{job_id}/pause", tags=["CSV Jobs"])
async def pause_job(job_id: str):
    job = _get_job(job_id)
    job.pause()
    return {"ok": True, "status": job.state.status}


@app.post("/api/jobs/{job_id}/resume", tags=["CSV Jobs"])
async def resume_job(job_id: str):
    job = _get_job(job_id)
    if not job.is_running():
        # Reanudar tras reinicio: arrancar de nuevo el loop
        job.start()
    else:
        job.resume()
    return {"ok": True, "status": job.state.status}


@app.post("/api/jobs/{job_id}/skip", tags=["CSV Jobs"])
async def skip_current(job_id: str, worker_id: Optional[int] = None):
    """Cancela el dominio actual de un worker (o de todos si no se especifica)."""
    job = _get_job(job_id)
    job.skip(worker_id=worker_id)
    return {"ok": True}


@app.post("/api/jobs/{job_id}/stop", tags=["CSV Jobs"])
async def stop_job(job_id: str):
    job = _get_job(job_id)
    job.stop()
    return {"ok": True, "status": job.state.status}


@app.delete("/api/jobs/{job_id}", tags=["CSV Jobs"])
async def delete_job(job_id: str):
    job = _get_job(job_id)
    if job.is_running():
        job.stop()
        await asyncio.sleep(0.2)
    import shutil
    shutil.rmtree(job.dir, ignore_errors=True)
    _jobs.pop(job_id, None)
    return {"ok": True}


@app.get("/api/jobs/{job_id}/download", tags=["CSV Jobs"])
async def download_job_csv(job_id: str):
    job = _get_job(job_id)
    if not job.output_csv.exists():
        raise HTTPException(status_code=404, detail="Aún no hay resultados procesados")
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", job.state.input_name or "result.csv")
    if not safe_name.lower().endswith(".csv"):
        safe_name += ".csv"
    sorted_path = job.get_sorted_output_path()
    return FileResponse(
        sorted_path, media_type="text/csv",
        filename=f"reachflow_{safe_name}",
    )


@app.get("/api/jobs/{job_id}/events", tags=["CSV Jobs"])
async def job_events(job_id: str):
    """Server-Sent Events stream con progreso en vivo del job."""
    job = _get_job(job_id)

    async def event_gen():
        q = await job.subscribe()
        try:
            # Mensaje inicial
            yield f"event: hello\ndata: {json.dumps({'job_id': job_id})}\n\n"
            while True:
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=20)
                    payload = json.dumps(msg["data"], default=str)
                    yield f"event: {msg['type']}\ndata: {payload}\n\n"
                except asyncio.TimeoutError:
                    # keep-alive
                    yield ": keepalive\n\n"
        finally:
            job.unsubscribe(q)

    return StreamingResponse(event_gen(), media_type="text/event-stream", headers={
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
        "Connection": "keep-alive",
    })


# ---------------------------------------------------------------------------
# Static UI
# ---------------------------------------------------------------------------

_STATIC_DIR = Path(__file__).parent / "static"
if _STATIC_DIR.exists():
    app.mount("/ui", StaticFiles(directory=str(_STATIC_DIR), html=True), name="ui")


@app.get("/app", include_in_schema=False)
async def app_redirect():
    return RedirectResponse(url="/ui/")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("app.main:app", host="0.0.0.0", port=port, reload=False)
