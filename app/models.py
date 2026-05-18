"""Modelos Pydantic para validación de datos"""
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
import re


class DomainInput(BaseModel):
    """Input para verificación de dominio"""
    domain: str = Field(..., description="Dominio a verificar (ej: example.com)")
    check_redirects: bool = Field(True, description="Verificar redirecciones")
    check_dns: bool = Field(True, description="Verificar registros DNS")
    domains_to_check: Optional[List[str]] = Field(None, description="Lista de dominios para verificar si redirigen al dominio principal")

    @validator('domain')
    def validate_domain(cls, v):
        """Valida el formato del dominio"""
        v = v.lower()
        v = re.sub(r'^https?://', '', v)
        v = re.sub(r'^www\.', '', v)
        v = v.split('/')[0]

        domain_pattern = r'^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$'
        if not re.match(domain_pattern, v):
            raise ValueError(f"Formato de dominio inválido: {v}")

        return v

    @validator('domains_to_check')
    def validate_domains_list(cls, v):
        """Valida la lista de dominios"""
        if v is None:
            return v

        cleaned_domains = []
        for domain in v:
            domain = domain.lower()
            domain = re.sub(r'^https?://', '', domain)
            domain = re.sub(r'^www\.', '', domain)
            domain = domain.split('/')[0]
            cleaned_domains.append(domain)

        return cleaned_domains


class MXRecord(BaseModel):
    """Modelo para registro MX"""
    has_mx: bool
    provider: Optional[str] = None
    servers: Optional[List[Dict[str, Any]]] = None
    count: Optional[int] = None
    error: Optional[str] = None


class SPFRecord(BaseModel):
    """Modelo para registro SPF"""
    has_spf: bool
    valid: bool
    record: Optional[str] = None
    mechanisms: Optional[List[str]] = None
    error: Optional[str] = None


class DMARCRecord(BaseModel):
    """Modelo para registro DMARC"""
    has_dmarc: bool
    valid: bool
    record: Optional[str] = None
    policy: Optional[Dict[str, str]] = None
    error: Optional[str] = None


class DKIMRecord(BaseModel):
    """Modelo para registro DKIM"""
    has_dkim: bool
    valid: bool
    records: Optional[List[Dict[str, Any]]] = None
    count: Optional[int] = None
    error: Optional[str] = None
    note: Optional[str] = None


class DNSInfo(BaseModel):
    """Información completa de DNS"""
    domain: str
    mx: MXRecord
    spf: SPFRecord
    dmarc: DMARCRecord
    dkim: DKIMRecord


class RedirectInfo(BaseModel):
    """Información de redirecciones"""
    domain: str
    redirects_to_other_domains: bool
    unique_destinations: List[str]
    destination_count: int
    details: List[Dict[str, Any]]


class DomainsRedirectingInfo(BaseModel):
    """Información de dominios que redirigen al objetivo"""
    target_domain: str
    domains_redirecting: List[Dict[str, Any]]
    count: int


class EmailSecuritySummary(BaseModel):
    """Resumen de seguridad de email"""
    spf_configured: bool
    dmarc_configured: bool
    dkim_configured: bool
    all_configured: bool
    security_score: str  # "Excellent", "Good", "Fair", "Poor"
    recommendations: List[str]


class DomainDiscoveryInput(BaseModel):
    """Input para descubrimiento de dominios"""
    domain: str = Field(..., description="Dominio objetivo")
    verify_redirects: bool = Field(True, description="Verificar si los dominios encontrados realmente redirigen")
    use_crtsh: bool = Field(True, description="Buscar en Certificate Transparency")
    use_google: bool = Field(True, description="Buscar con Google dorks")
    use_commoncrawl: bool = Field(True, description="Buscar en Common Crawl")
    use_censys: bool = Field(False, description="Buscar en Censys (requiere API key)")
    censys_api_key: Optional[str] = Field(None, description="API key de Censys")

    @validator('domain')
    def validate_domain(cls, v):
        """Valida el formato del dominio"""
        v = v.lower()
        v = re.sub(r'^https?://', '', v)
        v = re.sub(r'^www\.', '', v)
        v = v.split('/')[0]

        domain_pattern = r'^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$'
        if not re.match(domain_pattern, v):
            raise ValueError(f"Formato de dominio inválido: {v}")

        return v


class DomainDiscoveryResponse(BaseModel):
    """Respuesta de descubrimiento de dominios"""
    target_domain: str
    total_discovered: int
    discovered_domains: List[str]
    verified_redirects: List[Dict[str, Any]]
    verified_count: int
    sources_used: Dict[str, bool]
    timestamp: str


class DomainVerificationResponse(BaseModel):
    """Respuesta completa de verificación de dominio"""
    domain: str
    timestamp: str
    dns_info: Optional[DNSInfo] = None
    redirect_info: Optional[RedirectInfo] = None
    domains_redirecting_to_target: Optional[DomainsRedirectingInfo] = None
    email_security_summary: Optional[EmailSecuritySummary] = None
    success: bool
    errors: Optional[List[str]] = None


# ---- Modelos para descubrimiento avanzado ----

class BulkCheckRequest(BaseModel):
    """Request para verificación masiva de dominios"""
    domains: List[str] = Field(..., description="Lista de dominios a verificar", min_items=1, max_items=500)

    @validator('domains')
    def validate_domains(cls, v):
        cleaned = []
        for domain in v:
            domain = domain.lower().strip()
            domain = re.sub(r'^https?://', '', domain)
            domain = re.sub(r'^www\.', '', domain)
            domain = domain.split('/')[0]
            if domain:
                cleaned.append(domain)
        return cleaned


class DomainCheckResult(BaseModel):
    """Resultado de verificación de un dominio individual"""
    domain: str
    resolves: bool
    has_mx: bool
    mx_provider: Optional[str] = None
    likely_used: bool


class VariantsCheckResponse(BaseModel):
    """Respuesta de verificación de variantes"""
    base_domain: str
    total_checked: int
    active_count: int
    with_mx_count: int
    active_domains: List[DomainCheckResult]
    all_results: List[DomainCheckResult]
    success: bool


class CrtshDomainResponse(BaseModel):
    """Respuesta de búsqueda en crt.sh por dominio"""
    domain: str
    total: int
    subdomains: List[str]
    subdomains_count: int
    source: str
    success: bool
    error: Optional[str] = None


class CrtshOrgResponse(BaseModel):
    """Respuesta de búsqueda en crt.sh por organización"""
    org: str
    total_entries: int
    domains: List[str]
    root_domains: List[str]
    root_domains_count: int
    source: str
    success: bool
    error: Optional[str] = None
