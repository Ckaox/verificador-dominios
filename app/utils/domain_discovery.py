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
    "dev", "tech", "info", "biz", "eu", "us", "cc",
    "online", "site", "digital", "global",
    "de", "fr", "it", "pt", "mx", "ar", "cl", "br", "lat",
]

# ---------------------------------------------------------------------------
# Subconjuntos optimizados para detección de "cold email infra"
# Estos son los patrones que típicamente usan las empresas para sus dominios
# secundarios de cold outbound, evitando los .com principales.
# ~40 variantes vs ~214 del modo completo → 5x más rápido.
# ---------------------------------------------------------------------------

COLD_EMAIL_SUFFIXES: List[str] = [
    # Específicos de email/outbound
    "mail", "email", "inbox", "outreach", "reply",
    # Genéricos cold-email comunes
    "try", "get", "go", "app", "hq", "team",
    "io", "co", "labs", "now",
]

COLD_EMAIL_PREFIXES: List[str] = [
    "get", "try", "use", "go", "mail", "email",
    "my", "hi", "the", "join", "meet", "with",
]

COLD_EMAIL_TLDS: List[str] = [
    "com", "co", "net", "org", "es", "io", "cc", "eu", "info",
    "online", "site", "tech", "digital", "global", "app",
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

    def generate_variants_mode(self, domain: str, mode: str = "full") -> List[str]:
        """
        Genera variantes según el modo:
          - "full"  → todas (~214) — el set completo
          - "cold"  → solo patrones de cold email infra (~40) — 5x más rápido
          - "none"  → []
        """
        if mode == "none":
            return []
        if mode == "cold":
            return self._generate_variants(domain, COLD_EMAIL_SUFFIXES,
                                           COLD_EMAIL_PREFIXES, COLD_EMAIL_TLDS)
        return self._generate_variants(domain, SUFFIX_VARIANTS,
                                       PREFIX_VARIANTS, TLD_VARIANTS)

    def _generate_variants(self, domain: str, suffixes: List[str],
                           prefixes: List[str], tlds: List[str]) -> List[str]:
        parts = domain.rsplit(".", 1)
        if len(parts) != 2:
            return []
        brand = parts[0].lower()
        original_tld = parts[1].lower()
        variants: Set[str] = set()

        for tld in tlds:
            if tld != original_tld:
                variants.add(f"{brand}.{tld}")
        for suffix in suffixes:
            variants.add(f"{brand}{suffix}.{original_tld}")
            if original_tld != "com":
                variants.add(f"{brand}{suffix}.com")
        for prefix in prefixes:
            variants.add(f"{prefix}{brand}.{original_tld}")
            variants.add(f"{brand}{prefix}.{original_tld}")
            if original_tld != "com":
                variants.add(f"{prefix}{brand}.com")
                variants.add(f"{brand}{prefix}.com")
        variants.discard(domain)
        return sorted(variants)

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

    # ------------------------------------------------------------------
    # Enriquecimiento de dominios activos: DMARC, DKIM y redirección HTTP
    # ------------------------------------------------------------------

    async def _check_dmarc_quick(self, domain: str) -> Dict:
        """Verifica si existe registro DMARC y extrae la política (none/quarantine/reject)."""
        loop = asyncio.get_event_loop()
        try:
            records = await loop.run_in_executor(
                None, self.resolver.resolve, f"_dmarc.{domain}", "TXT"
            )
            for rdata in records:
                txt = str(rdata).strip('"')
                if txt.startswith("v=DMARC1"):
                    m = re.search(r'p=(\w+)', txt)
                    policy = m.group(1).lower() if m else "none"
                    return {"has_dmarc": True, "dmarc_policy": policy}
        except Exception:
            pass
        return {"has_dmarc": False, "dmarc_policy": None}

    async def _check_dkim_quick(self, domain: str) -> Dict:
        """Verifica selectores DKIM comunes en paralelo. Devuelve el primero que encuentre."""
        QUICK_SELECTORS = ["google", "selector1", "selector2", "default", "k1", "mail", "dkim"]
        loop = asyncio.get_event_loop()

        async def _try_selector(sel: str) -> Optional[str]:
            try:
                records = await loop.run_in_executor(
                    None, self.resolver.resolve, f"{sel}._domainkey.{domain}", "TXT"
                )
                for rdata in records:
                    txt = str(rdata).strip('"')
                    if "p=" in txt or "v=DKIM1" in txt:
                        return sel
            except Exception:
                pass
            return None

        found = [s for s in await asyncio.gather(*[_try_selector(s) for s in QUICK_SELECTORS]) if s]
        return {"has_dkim": bool(found), "dkim_selector": found[0] if found else None}

    async def _check_redirect(self, domain: str) -> Dict:
        """
        Comprueba si el dominio redirige a otro dominio.
        Sigue la cadena completa de redirects (hasta 5 saltos) y compara
        el host final con el original. Strip-ea 'www.' antes de comparar.
        """
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        }
        for scheme in ("https", "http"):
            try:
                async with httpx.AsyncClient(
                    timeout=8, follow_redirects=True, verify=False,
                    max_redirects=5, headers=headers,
                ) as client:
                    resp = await client.get(f"{scheme}://{domain}/")
                    final_url = str(resp.url)
                    m = re.search(r'https?://(?:www\.)?([^/?#:]+)', final_url)
                    if m:
                        final_domain = m.group(1).lower()
                        original = domain.lower()
                        # Si el final es el mismo dominio (o subdominio del mismo),
                        # no consideramos que redirija.
                        same = (
                            final_domain == original
                            or final_domain.endswith("." + original)
                            or original.endswith("." + final_domain)
                        )
                        return {
                            "redirects": not same,
                            "redirect_to": final_domain if not same else None,
                            "final_url": final_url,
                        }
                    return {"redirects": False, "redirect_to": None, "final_url": final_url}
            except Exception:
                continue
        return {"redirects": False, "redirect_to": None, "final_url": None}

    async def _enrich_domain(self, result: Dict) -> Dict:
        """Para un dominio activo: añade DMARC, DKIM rápido y redirección HTTP en paralelo."""
        async def _no_redirect() -> Dict:
            return {"redirects": False, "redirect_to": None}

        dmarc, dkim, redirect = await asyncio.gather(
            self._check_dmarc_quick(result["domain"]),
            self._check_dkim_quick(result["domain"]),
            self._check_redirect(result["domain"]) if result["resolves"] else _no_redirect(),
        )
        cold_email_ready = result["has_mx"] and (dmarc["has_dmarc"] or dkim["has_dkim"])
        return {
            **result,
            **dmarc,
            **dkim,
            **redirect,
            "cold_email_ready": cold_email_ready,
        }

    async def check_variants_bulk(self, domain: str, max_concurrent: int = 25, enrich: bool = True) -> Dict:
        """
        Genera variantes del dominio y verifica cuáles están activas en paralelo.

        Args:
            domain:         Dominio base, ej: "prueba.com"
            max_concurrent: Concurrencia máxima de consultas DNS simultáneas
            enrich:         Si True, añade DMARC/DKIM/redirect a los activos (~3-5s extra).
                            Si False, devuelve solo DNS básico — más rápido para volúmenes altos.

        Returns:
            Dict con resultados agrupados: activos, con MX, y todos.
        """
        variants = self.generate_variants(domain)
        results = await self._check_bulk_with_semaphore(variants, max_concurrent)

        active_raw = [r for r in results if r["likely_used"]]
        with_mx = [r for r in results if r["has_mx"]]

        if enrich and active_raw:
            active = list(await asyncio.gather(*[self._enrich_domain(r) for r in active_raw]))
        else:
            active = active_raw

        return {
            "base_domain": domain,
            "total_checked": len(variants),
            "active_count": len(active),
            "with_mx_count": len(with_mx),
            "active_domains": active,
            "all_results": results,
            "success": True,
        }

    async def check_domains_bulk(self, domains: List[str], max_concurrent: int = 25, enrich: bool = True) -> Dict:
        """
        Verifica una lista personalizada de dominios en paralelo.

        Args:
            domains:        Lista de dominios a verificar
            max_concurrent: Concurrencia máxima de consultas DNS simultáneas
            enrich:         Si True, añade DMARC/DKIM/redirect a los activos.

        Returns:
            Dict con resultados agrupados.
        """
        results = await self._check_bulk_with_semaphore(domains, max_concurrent)

        active_raw = [r for r in results if r["likely_used"]]
        with_mx = [r for r in results if r["has_mx"]]

        if enrich and active_raw:
            active = list(await asyncio.gather(*[self._enrich_domain(r) for r in active_raw]))
        else:
            active = active_raw

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
