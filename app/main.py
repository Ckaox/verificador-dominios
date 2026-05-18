"""API para verificación de registros DNS de dominios y descubrimiento de dominios corporativos"""
from fastapi import FastAPI, HTTPException, status, Query
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import re
import os
import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import List

from .models import (
    DNSInfo, EmailSecuritySummary, MXRecord, SPFRecord, DMARCRecord, DKIMRecord,
    BulkCheckRequest,
)
from .utils import DNSChecker, DomainDiscovery


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
):
    """
    Genera todas las variantes de marca (sufijos/prefijos) y TLD para un
    dominio y verifica en paralelo cuáles están activas (resuelven DNS o
    tienen registros MX configurados).

    **Variantes generadas:**
    - **TLD**: `prueba.es`, `prueba.io`, `prueba.ai`, ...
    - **Sufijo**: `pruebago.com`, `pruebanow.com`, `pruebahq.com`, `pruebapro.com`, ...
    - **Prefijo**: `getprueba.com`, `tryprueba.com`, `useprueba.com`, `joinprueba.com`, ...

    **Campos de respuesta clave:**
    - `active_domains`: dominios que resuelven o tienen MX (los más relevantes)
    - `with_mx_count`: cuántos tienen correo configurado (candidatos para cold email)
    - `all_results`: resultado completo de todos los dominios verificados

    - **domain**: Dominio base, ej: `prueba.com`
    """
    try:
        clean_domain = validate_domain(domain)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    discovery = DomainDiscovery()
    result = await discovery.check_variants_bulk(clean_domain, max_concurrent=max_concurrent)
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
    result = await discovery.check_domains_bulk(request.domains, max_concurrent=max_concurrent)
    result["timestamp"] = datetime.utcnow().isoformat() + "Z"
    return result


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("app.main:app", host="0.0.0.0", port=port, reload=False)
