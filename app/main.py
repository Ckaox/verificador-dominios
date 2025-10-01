"""
API para verificación de registros DNS de dominios
"""
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import re
import os
import asyncio
from concurrent.futures import ThreadPoolExecutor

from .models import DNSInfo, EmailSecuritySummary, MXRecord, SPFRecord, DMARCRecord, DKIMRecord
from .utils import DNSChecker


# Crear aplicación FastAPI
app = FastAPI(
    title="Verificador DNS de Dominios",
    description="API para verificar registros DNS y configuración de correo electrónico (MX, SPF, DMARC, DKIM)",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configurar CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def validate_domain(domain: str) -> str:
    """Valida y limpia el formato del dominio"""
    domain = domain.lower()
    domain = re.sub(r'^https?://', '', domain)
    domain = re.sub(r'^www\.', '', domain)
    domain = domain.split('/')[0]
    
    domain_pattern = r'^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$'
    if not re.match(domain_pattern, domain):
        raise ValueError(f"Formato de dominio inválido: {domain}")
    
    return domain


def calculate_email_security_summary(dns_info: DNSInfo) -> EmailSecuritySummary:
    """
    Calcula un resumen de la seguridad del correo electrónico
    
    Args:
        dns_info: Información DNS del dominio
        
    Returns:
        EmailSecuritySummary con puntuación y recomendaciones
    """
    spf_ok = dns_info.spf.has_spf and dns_info.spf.valid
    dmarc_ok = dns_info.dmarc.has_dmarc and dns_info.dmarc.valid
    dkim_ok = dns_info.dkim.has_dkim and dns_info.dkim.valid
    
    configured_count = sum([spf_ok, dmarc_ok, dkim_ok])
    
    # Determinar puntuación
    if configured_count == 3:
        score = "Excellent"
    elif configured_count == 2:
        score = "Good"
    elif configured_count == 1:
        score = "Fair"
    else:
        score = "Poor"
    
    # Generar recomendaciones
    recommendations = []
    
    if not spf_ok:
        recommendations.append(
            "Configurar SPF: Añade un registro TXT con 'v=spf1' para especificar qué servidores pueden enviar correos en nombre de tu dominio"
        )
    
    if not dmarc_ok:
        recommendations.append(
            "Configurar DMARC: Añade un registro TXT en '_dmarc.tudominio.com' con 'v=DMARC1' para proteger contra suplantación de identidad"
        )
    
    if not dkim_ok:
        recommendations.append(
            "Configurar DKIM: Genera claves DKIM con tu proveedor de correo y añade los registros TXT correspondientes"
        )
    
    if configured_count == 3:
        recommendations.append("¡Excelente! Tu dominio tiene todas las configuraciones de seguridad de correo recomendadas.")
    
    return EmailSecuritySummary(
        spf_configured=spf_ok,
        dmarc_configured=dmarc_ok,
        dkim_configured=dkim_ok,
        all_configured=(configured_count == 3),
        security_score=score,
        recommendations=recommendations
    )


@app.get("/")
async def root():
    """Endpoint raíz con información de la API"""
    return {
        "message": "API de Verificación DNS de Dominios",
        "version": "2.0.0",
        "endpoints": {
            "dns": "GET /api/dns/{domain} - Verifica registros DNS",
            "health": "GET /api/health - Estado del servidor",
            "docs": "GET /docs - Documentación interactiva"
        },
        "features": [
            "Verificación de registros MX con detección de proveedor",
            "Validación de SPF",
            "Verificación de DMARC",
            "Búsqueda de registros DKIM",
            "Resumen de seguridad de email"
        ]
    }


@app.get("/api/dns/{domain}")
async def verify_dns(domain: str):
    """
    Verifica los registros DNS de un dominio
    
    Args:
        domain: Dominio a verificar (ej: example.com)
        
    Returns:
        Información DNS completa incluyendo MX, SPF, DMARC, DKIM, blacklists, edad y resumen de seguridad
    """
    try:
        # Validar dominio
        clean_domain = validate_domain(domain)
        
        dns_checker = DNSChecker()
        
        # Ejecutar whois en paralelo (es la operación más lenta)
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor() as executor:
            whois_future = loop.run_in_executor(executor, dns_checker.check_domain_age, clean_domain)
            
            # Mientras tanto, verificar DNS en paralelo (OPTIMIZADO: DKIM y Blacklists en paralelo)
            dns_data = await dns_checker.check_all_async(clean_domain)
            
            # Esperar resultado de whois
            domain_age = await whois_future
        
        # Crear objeto DNS Info
        dns_info = DNSInfo(
            domain=dns_data['domain'],
            mx=MXRecord(**dns_data['mx']),
            spf=SPFRecord(**dns_data['spf']),
            dmarc=DMARCRecord(**dns_data['dmarc']),
            dkim=DKIMRecord(**dns_data['dkim'])
        )
        
        # Calcular resumen de seguridad
        email_summary = calculate_email_security_summary(dns_info)
        
        # Parser DMARC detallado
        dmarc_details = None
        if dns_data['dmarc'].get('has_dmarc') and dns_data['dmarc'].get('record'):
            dmarc_details = dns_checker.parse_dmarc_detailed(dns_data['dmarc']['record'])
        
        return {
            "domain": clean_domain,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "dns": {
                "mx": dns_info.mx.dict(),
                "spf": dns_info.spf.dict(),
                "dmarc": dns_info.dmarc.dict(),
                "dmarc_details": dmarc_details,
                "dkim": dns_info.dkim.dict()
            },
            "blacklists": dns_data['blacklists'],
            "domain_age": domain_age,
            "email_security_summary": email_summary.dict(),
            "success": True
        }
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al verificar DNS: {str(e)}"
        )


@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "version": "2.0.0"
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=port,
        reload=False
    )
