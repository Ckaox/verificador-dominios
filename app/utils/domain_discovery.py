"""
Descubrimiento de dominios:
  - Certificate Transparency via crt.sh (por dominio y por organización)
  - Variantes de marca (sufijos / prefijos)
  - Variantes de TLD
  - Verificación masiva de resolución DNS + MX
"""
import asyncio
import re
from typing import List, Dict, Set, Optional
from urllib.parse import quote

import httpx
import dns.resolver
import dns.exception

# ---------------------------------------------------------------------------
# Patrones de variantes de marca
# Basados en los ejemplos del usuario + extensión razonada
# ---------------------------------------------------------------------------

# Sufijos que se añaden DESPUÉS de la marca:  prueba + go → pruebago
SUFFIX_VARIANTS: List[str] = [
    # Originales del usuario
    "go", "now", "hq", "pro", "today", "online", "site", "app",
    "one", "plus", "world", "easy", "fast", "hub", "grow", "team",
    "co", "works", "shop", "club",
    # Tecnología / producto
    "labs", "ai", "io", "dev", "tech", "cloud", "base", "connect",
    "link", "net", "platform", "suite", "tools", "api",
    "flow", "stack", "core", "edge", "sync", "dash", "kit", "box", "pulse",
    # Empresa / estructura
    "solutions", "group", "global", "media", "digital", "agency",
    "studio", "space", "zone", "corp", "store", "pay",
    # Brand moderno
    "wise", "open", "free", "lite", "desk", "smart",
]

# Prefijos que se añaden ANTES de la marca:  get + prueba → getprueba
# NOTA: cada prefijo también se usa como sufijo (marca+prefijo)
PREFIX_VARIANTS: List[str] = [
    # Originales del usuario
    "get", "try", "use", "go", "join", "the", "now", "my",
    "start", "with",
    # Acción
    "meet", "run", "find", "build", "make",
    # Identidad / posesivo
    "your", "hey",
    # Modificador
    "on", "new", "all", "top", "pro", "best", "real", "live",
    # B2B
    "team", "work",
    # Adicionales comunes
    "open", "just", "only", "true", "hi", "see", "know", "ask", "send",
]

# TLDs alternativos para el mismo nombre de marca
TLD_VARIANTS: List[str] = [
    "com", "es", "net", "io", "app", "co", "org", "ai",
    "dev", "tech", "info", "biz", "eu", "us",
    "de", "fr", "it", "pt", "mx", "ar", "cl", "br", "lat",
]

# TLDs de múltiples partes para extracción correcta de dominio raíz
_MULTI_PART_TLDS: Set[str] = {
    "co.uk", "com.au", "co.jp", "com.br", "co.nz",
    "org.uk", "net.au", "com.mx", "com.ar",
}


# Servidores DNS públicos rápidos
_FAST_NAMESERVERS = ["1.1.1.1", "8.8.8.8", "1.0.0.1", "8.8.4.4"]


class DomainDiscovery:
    """Clase para descubrimiento de dominios relacionados con una empresa"""

    CRTSH_TIMEOUT = 30    # segundos para peticiones HTTP a crt.sh
    DNS_TIMEOUT = 1.5     # 1.5s suficiente con DNS rápidos; NXDOMAIN responde casi instantáneo

    def __init__(self):
        self.resolver = dns.resolver.Resolver(configure=False)
        self.resolver.nameservers = _FAST_NAMESERVERS
        self.resolver.timeout = self.DNS_TIMEOUT
        self.resolver.lifetime = self.DNS_TIMEOUT

    # ------------------------------------------------------------------
    # Certificate Transparency – crt.sh
    # ------------------------------------------------------------------

    async def search_crtsh_by_domain(self, domain: str) -> Dict:
        """
        Busca en los logs de Certificate Transparency (crt.sh) todos los
        subdominios y dominios para los que se han emitido certificados
        que incluyen *.<domain>.

        Args:
            domain: Dominio raíz, ej: "example.com"

        Returns:
            Dict con subdominios encontrados y metadatos.
        """
        url = f"https://crt.sh/?q=%.{domain}&output=json&deduplicate=Y"
        try:
            async with httpx.AsyncClient(timeout=self.CRTSH_TIMEOUT, follow_redirects=True) as client:
                response = await client.get(url)
                response.raise_for_status()
                data = response.json()

            found: Set[str] = set()
            for entry in data:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lstrip("*.")
                    if name and (name == domain or name.endswith(f".{domain}")):
                        found.add(name.lower())

            subdomains = sorted(d for d in found if d != domain)
            return {
                "domain": domain,
                "total": len(found),
                "subdomains": subdomains,
                "subdomains_count": len(subdomains),
                "source": "crt.sh",
                "success": True,
                "error": None,
            }

        except httpx.TimeoutException:
            return {
                "domain": domain, "success": False,
                "error": "crt.sh timeout (>30 s)",
                "subdomains": [], "subdomains_count": 0, "total": 0,
                "source": "crt.sh",
            }
        except Exception as e:
            return {
                "domain": domain, "success": False, "error": str(e),
                "subdomains": [], "subdomains_count": 0, "total": 0,
                "source": "crt.sh",
            }

    async def search_crtsh_by_org(self, org_name: str) -> Dict:
        """
        Busca en crt.sh por nombre de organización (campo O= del certificado).
        Es la fuente más potente para descubrir TODOS los dominios que una
        empresa ha certificado, incluyendo dominios secundarios y de proyectos.

        Args:
            org_name: Nombre de la organización tal como aparece en el
                      certificado, ej: "Acme Corporation" o "acme"

        Returns:
            Dict con todos los dominios y dominios raíz encontrados.
        """
        url = f"https://crt.sh/?O={quote(org_name)}&output=json"
        try:
            async with httpx.AsyncClient(timeout=self.CRTSH_TIMEOUT, follow_redirects=True) as client:
                response = await client.get(url)
                response.raise_for_status()
                data = response.json()

            found: Set[str] = set()
            for entry in data:
                # name_value puede tener varios dominios separados por \n
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.")
                    if name and "." in name:
                        found.add(name.lower())
                # common_name también puede ser relevante
                cn = entry.get("common_name", "").strip().lstrip("*.")
                if cn and "." in cn:
                    found.add(cn.lower())

            root_domains = self._extract_root_domains(found)

            return {
                "org": org_name,
                "total_entries": len(found),
                "domains": sorted(found),
                "root_domains": sorted(root_domains),
                "root_domains_count": len(root_domains),
                "source": "crt.sh",
                "success": True,
                "error": None,
            }

        except httpx.TimeoutException:
            return {
                "org": org_name, "success": False,
                "error": "crt.sh timeout (>30 s)",
                "domains": [], "root_domains": [],
                "root_domains_count": 0, "total_entries": 0,
                "source": "crt.sh",
            }
        except Exception as e:
            return {
                "org": org_name, "success": False, "error": str(e),
                "domains": [], "root_domains": [],
                "root_domains_count": 0, "total_entries": 0,
                "source": "crt.sh",
            }

    def _extract_root_domains(self, domains: Set[str]) -> Set[str]:
        """Extrae los dominios raíz de un conjunto de FQDNs."""
        root_domains: Set[str] = set()
        for domain in domains:
            parts = domain.split(".")
            if len(parts) < 2:
                continue
            # Detectar TLDs de dos partes (co.uk, com.br, etc.)
            two_part_tld = f"{parts[-2]}.{parts[-1]}"
            if len(parts) >= 3 and two_part_tld in _MULTI_PART_TLDS:
                root_domains.add(".".join(parts[-3:]))
            else:
                root_domains.add(".".join(parts[-2:]))
        return root_domains

    # ------------------------------------------------------------------
    # Generación de variantes de marca y TLD
    # ------------------------------------------------------------------

    def generate_variants(self, domain: str) -> List[str]:
        """
        Genera todas las variantes de marca y TLD para un dominio dado.

        Ejemplo con prueba.com genera:
          - TLD:    prueba.es, prueba.net, prueba.io, ...
          - Sufijo: pruebago.com, pruebanow.com, pruebahq.com, ...
          - Prefijo: getprueba.com, tryprueba.com, goprueba.com, ...

        Args:
            domain: Dominio base, ej: "prueba.com"

        Returns:
            Lista ordenada de variantes sin duplicados.
        """
        parts = domain.rsplit(".", 1)
        if len(parts) != 2:
            return []

        brand = parts[0].lower()
        original_tld = parts[1].lower()

        variants: Set[str] = set()

        # 1) Variantes de TLD (misma marca, diferente TLD)
        for tld in TLD_VARIANTS:
            if tld != original_tld:
                variants.add(f"{brand}.{tld}")

        # 2) Variantes de sufijo (marca + sufijo + TLD original y .com)
        for suffix in SUFFIX_VARIANTS:
            variants.add(f"{brand}{suffix}.{original_tld}")
            if original_tld != "com":
                variants.add(f"{brand}{suffix}.com")

        # 3) Variantes de prefijo — ambas direcciones:
        #    prefijo+marca (getprueba.com) Y marca+prefijo (pruebaget.com)
        for prefix in PREFIX_VARIANTS:
            variants.add(f"{prefix}{brand}.{original_tld}")
            variants.add(f"{brand}{prefix}.{original_tld}")
            if original_tld != "com":
                variants.add(f"{prefix}{brand}.com")
                variants.add(f"{brand}{prefix}.com")

        # Eliminar el dominio original si se coló
        variants.discard(domain)

        return sorted(variants)

    # ------------------------------------------------------------------
    # Verificación DNS de dominios
    # ------------------------------------------------------------------

    def _detect_mx_provider(self, mx_host: str) -> str:
        """Detecta el proveedor de correo a partir del hostname MX."""
        h = mx_host.lower()
        if "google" in h or "gmail" in h:
            return "Google Workspace"
        if "outlook" in h or "microsoft" in h or "protection.outlook" in h:
            return "Microsoft 365"
        if "zoho" in h:
            return "Zoho Mail"
        if "protonmail" in h:
            return "ProtonMail"
        if "yahoodns" in h:
            return "Yahoo Mail"
        return mx_host

    async def _check_single_domain(self, domain: str) -> Dict:
        """
        Verifica si un dominio resuelve (A) y si tiene registros MX.
        Las consultas A y MX se lanzan en PARALELO para reducir latencia.

        Returns:
            Dict con campos: domain, resolves, has_mx, mx_provider, likely_used
        """
        loop = asyncio.get_event_loop()

        async def _resolve_a() -> bool:
            try:
                await loop.run_in_executor(None, self.resolver.resolve, domain, "A")
                return True
            except Exception:
                return False

        async def _resolve_mx() -> Optional[str]:
            """Devuelve el proveedor MX o None si no hay registros."""
            try:
                mx_records = await loop.run_in_executor(
                    None, self.resolver.resolve, domain, "MX"
                )
                for rdata in mx_records:
                    return self._detect_mx_provider(str(rdata.exchange).rstrip("."))
            except Exception:
                pass
            return None

        # Lanzar A y MX simultáneamente — ahorra ~1 RTT por dominio
        resolves, mx_provider = await asyncio.gather(_resolve_a(), _resolve_mx())

        return {
            "domain": domain,
            "resolves": resolves,
            "has_mx": mx_provider is not None,
            "mx_provider": mx_provider,
            "likely_used": resolves or (mx_provider is not None),
        }

    async def check_variants_bulk(self, domain: str, max_concurrent: int = 25) -> Dict:
        """
        Genera variantes del dominio y verifica cuáles están activas en paralelo.

        Args:
            domain:         Dominio base, ej: "prueba.com"
            max_concurrent: Concurrencia máxima de consultas DNS simultáneas

        Returns:
            Dict con resultados agrupados: activos, con MX, y todos.
        """
        variants = self.generate_variants(domain)
        results = await self._check_bulk_with_semaphore(variants, max_concurrent)

        active = [r for r in results if r["likely_used"]]
        with_mx = [r for r in results if r["has_mx"]]

        return {
            "base_domain": domain,
            "total_checked": len(variants),
            "active_count": len(active),
            "with_mx_count": len(with_mx),
            "active_domains": active,
            "all_results": results,
            "success": True,
        }

    async def check_domains_bulk(self, domains: List[str], max_concurrent: int = 25) -> Dict:
        """
        Verifica una lista personalizada de dominios en paralelo.

        Args:
            domains:        Lista de dominios a verificar
            max_concurrent: Concurrencia máxima de consultas DNS simultáneas

        Returns:
            Dict con resultados agrupados.
        """
        results = await self._check_bulk_with_semaphore(domains, max_concurrent)

        active = [r for r in results if r["likely_used"]]
        with_mx = [r for r in results if r["has_mx"]]

        return {
            "total_checked": len(domains),
            "active_count": len(active),
            "with_mx_count": len(with_mx),
            "active_domains": active,
            "all_results": results,
            "success": True,
        }

    async def _check_bulk_with_semaphore(
        self, domains: List[str], max_concurrent: int
    ) -> List[Dict]:
        """Ejecuta _check_single_domain en paralelo con semáforo de concurrencia."""
        semaphore = asyncio.Semaphore(max_concurrent)

        async def _guarded(d: str) -> Dict:
            async with semaphore:
                return await self._check_single_domain(d)

        return list(await asyncio.gather(*[_guarded(d) for d in domains]))
