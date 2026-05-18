"""Utilidades para verificar registros DNS (MX, SPF, DMARC, DKIM)"""
import dns.resolver
import dns.exception
from typing import Dict, List, Optional
import re
import whois
from datetime import datetime
import asyncio


# Servidores DNS públicos rápidos (evitar resolver del sistema que puede ser lento)
_FAST_NAMESERVERS = ["1.1.1.1", "8.8.8.8", "1.0.0.1", "8.8.4.4"]


class DNSChecker:
    """Clase para verificar registros DNS de un dominio"""

    def __init__(self):
        self.resolver = dns.resolver.Resolver(configure=False)
        self.resolver.nameservers = _FAST_NAMESERVERS
        self.resolver.timeout = 3   # reducido de 5 → 3
        self.resolver.lifetime = 3

    def check_mx_records(self, domain: str) -> Dict:
        """
        Verifica los registros MX (Mail Exchange) del dominio

        Args:
            domain: Dominio a verificar

        Returns:
            Dict con información de los registros MX
        """
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')

            servers = []
            mail_provider = "Unknown"

            for rdata in mx_records:
                mx_host = str(rdata.exchange).rstrip('.')
                servers.append({
                    "priority": rdata.preference,
                    "server": mx_host
                })

                # Detectar proveedor de correo
                if 'google' in mx_host.lower() or 'gmail' in mx_host.lower():
                    mail_provider = "Google Workspace (Gmail)"
                elif 'outlook' in mx_host.lower() or 'microsoft' in mx_host.lower():
                    mail_provider = "Microsoft 365 (Outlook)"
                elif 'zoho' in mx_host.lower():
                    mail_provider = "Zoho Mail"
                elif 'protonmail' in mx_host.lower():
                    mail_provider = "ProtonMail"
                elif 'mail.protection.outlook.com' in mx_host.lower():
                    mail_provider = "Microsoft 365"
                elif 'yahoodns' in mx_host.lower():
                    mail_provider = "Yahoo Mail"

            return {
                "has_mx": True,
                "provider": mail_provider,
                "servers": sorted(servers, key=lambda x: x['priority']),
                "count": len(servers)
            }

        except dns.resolver.NoAnswer:
            return {"has_mx": False, "error": "No MX records found"}
        except dns.resolver.NXDOMAIN:
            return {"has_mx": False, "error": "Domain does not exist"}
        except dns.exception.Timeout:
            return {"has_mx": False, "error": "DNS query timeout"}
        except Exception as e:
            return {"has_mx": False, "error": str(e)}

    def check_spf_record(self, domain: str) -> Dict:
        """
        Verifica el registro SPF (Sender Policy Framework)

        Args:
            domain: Dominio a verificar

        Returns:
            Dict con información del SPF
        """
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')

            for rdata in txt_records:
                txt_string = str(rdata).strip('"')

                if txt_string.startswith('v=spf1'):
                    valid = self._validate_spf(txt_string)

                    return {
                        "has_spf": True,
                        "record": txt_string,
                        "valid": valid,
                        "mechanisms": self._parse_spf_mechanisms(txt_string)
                    }

            return {
                "has_spf": False,
                "valid": False,
                "error": "No SPF record found"
            }

        except dns.resolver.NoAnswer:
            return {"has_spf": False, "valid": False, "error": "No TXT records found"}
        except dns.resolver.NXDOMAIN:
            return {"has_spf": False, "valid": False, "error": "Domain does not exist"}
        except Exception as e:
            return {"has_spf": False, "valid": False, "error": str(e)}

    def check_dmarc_record(self, domain: str) -> Dict:
        """
        Verifica el registro DMARC (Domain-based Message Authentication)

        Args:
            domain: Dominio a verificar

        Returns:
            Dict con información del DMARC
        """
        try:
            dmarc_domain = f"_dmarc.{domain}"
            txt_records = dns.resolver.resolve(dmarc_domain, 'TXT')

            for rdata in txt_records:
                txt_string = str(rdata).strip('"')

                if txt_string.startswith('v=DMARC1'):
                    policy_info = self._parse_dmarc_policy(txt_string)

                    return {
                        "has_dmarc": True,
                        "record": txt_string,
                        "valid": True,
                        "policy": policy_info
                    }

            return {
                "has_dmarc": False,
                "valid": False,
                "error": "No DMARC record found"
            }

        except dns.resolver.NoAnswer:
            return {"has_dmarc": False, "valid": False, "error": "No DMARC record found"}
        except dns.resolver.NXDOMAIN:
            return {"has_dmarc": False, "valid": False, "error": "DMARC record not configured"}
        except Exception as e:
            return {"has_dmarc": False, "valid": False, "error": str(e)}

    async def _check_dkim_selector_async(self, domain: str, selector: str) -> Optional[Dict]:
        """Verifica un selector DKIM específico de forma asíncrona"""
        try:
            dkim_domain = f"{selector}._domainkey.{domain}"
            loop = asyncio.get_event_loop()
            txt_records = await loop.run_in_executor(
                None,
                dns.resolver.resolve,
                dkim_domain,
                'TXT'
            )

            for rdata in txt_records:
                txt_string = str(rdata).strip('"')

                if 'v=DKIM1' in txt_string or 'k=' in txt_string or 'p=' in txt_string:
                    return {
                        "selector": selector,
                        "record": txt_string,
                        "valid": True
                    }
        except Exception:
            pass
        return None

    async def check_dkim_record_async(self, domain: str) -> Dict:
        """
        Verifica el registro DKIM en paralelo (DomainKeys Identified Mail)

        Args:
            domain: Dominio a verificar

        Returns:
            Dict con información del DKIM
        """
        common_selectors = [
            # Genéricos
            "default", "dkim", "mail", "email", "smtp",
            # Google Workspace
            "google", "google1", "google2", "gmail",
            # Microsoft 365
            "selector1", "selector2", "s1", "s2",
            # Proveedores populares
            "k1", "k2", "k3",
            "mailgun", "sendgrid", "amazonses", "mandrill"
        ]

        tasks = [self._check_dkim_selector_async(domain, sel) for sel in common_selectors]
        results = await asyncio.gather(*tasks)

        found_records = [r for r in results if r is not None]

        if found_records:
            return {
                "has_dkim": True,
                "valid": True,
                "records": found_records,
                "count": len(found_records)
            }
        else:
            return {
                "has_dkim": False,
                "valid": False,
                "error": "No DKIM records found for common selectors",
                "note": "DKIM requires a specific selector. Common selectors were tested."
            }

    def _validate_spf(self, spf_record: str) -> bool:
        """Valida sintaxis básica de SPF"""
        if not spf_record.startswith('v=spf1'):
            return False

        if not re.search(r'[~\-\+\?]all', spf_record):
            return False

        return True

    def _parse_spf_mechanisms(self, spf_record: str) -> List[str]:
        """Extrae los mecanismos del registro SPF"""
        mechanisms = []
        parts = spf_record.split()

        for part in parts[1:]:  # Saltar 'v=spf1'
            if part.startswith(('ip4:', 'ip6:', 'include:', 'a:', 'mx:', 'ptr:', 'exists:')):
                mechanisms.append(part)
            elif part in ['~all', '-all', '+all', '?all']:
                mechanisms.append(part)

        return mechanisms

    def _parse_dmarc_policy(self, dmarc_record: str) -> Dict:
        """Extrae información de política del registro DMARC"""
        policy_info = {}

        parts = dmarc_record.split(';')
        for part in parts:
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                key = key.strip()
                value = value.strip()

                if key == 'p':
                    policy_info['policy'] = value
                elif key == 'sp':
                    policy_info['subdomain_policy'] = value
                elif key == 'pct':
                    policy_info['percentage'] = value
                elif key == 'rua':
                    policy_info['aggregate_reports'] = value
                elif key == 'ruf':
                    policy_info['forensic_reports'] = value

        return policy_info

    async def _check_single_blacklist_async(self, query: str, bl_name: str, bl_type: str, extra_info: Dict = None) -> Optional[Dict]:
        """Verifica una blacklist específica de forma asíncrona"""
        try:
            loop = asyncio.get_event_loop()
            result_dns = await loop.run_in_executor(
                None,
                self.resolver.resolve,
                query,
                'A'
            )
            if result_dns:
                for rdata in result_dns:
                    ip_str = str(rdata)
                    if ip_str.startswith('127.0.0.'):
                        result = {"blacklist": bl_name, "type": bl_type}
                        if extra_info:
                            result.update(extra_info)
                        return result
            return None
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            return None
        except Exception:
            return None

    async def check_blacklists_async(self, domain: str) -> Dict:
        """
        Verifica si el dominio o sus IPs MX están en blacklists (RBL/DNSBL)
        Usa las blacklists más importantes en paralelo (OPTIMIZADO)

        Args:
            domain: Dominio a verificar

        Returns:
            Dict con información de blacklists
        """
        blacklists = {
            "domain": [
                "dbl.spamhaus.org",
                "multi.surbl.org",
                "fresh.spameatingmonkey.net"
            ],
            "ip": [
                "sbl.spamhaus.org",
                "xbl.spamhaus.org",
                "bl.spamcop.net",
                "b.barracudacentral.org",
                "bl.mailspike.net",
                "bl.spameatingmonkey.net",
                "spam.spamrats.com",
                "drone.abuse.ch"
            ]
        }

        results = {
            "domain_blacklisted": False,
            "ip_blacklisted": False,
            "blacklists_checked": 0,
            "blacklists_listed": 0,
            "listed_in": [],
            "mx_ips_checked": []
        }

        tasks = []

        for bl in blacklists["domain"]:
            query = f"{domain}.{bl}"
            tasks.append(self._check_single_blacklist_async(query, bl, "domain"))
            results["blacklists_checked"] += 1

        mx_ips = []
        try:
            loop = asyncio.get_event_loop()
            mx_records = await loop.run_in_executor(None, dns.resolver.resolve, domain, 'MX')

            for mx in mx_records:
                mx_host = str(mx.exchange).rstrip('.')
                try:
                    ip_records = await loop.run_in_executor(None, dns.resolver.resolve, mx_host, 'A')
                    for ip in ip_records:
                        ip_str = str(ip)
                        if ip_str not in mx_ips:
                            mx_ips.append(ip_str)
                            results["mx_ips_checked"].append(ip_str)

                            reversed_ip = '.'.join(reversed(ip_str.split('.')))

                            for bl in blacklists["ip"]:
                                query = f"{reversed_ip}.{bl}"
                                tasks.append(self._check_single_blacklist_async(
                                    query, bl, "ip",
                                    {"ip": ip_str, "mx_server": mx_host}
                                ))
                                results["blacklists_checked"] += 1
                except Exception:
                    pass
        except Exception:
            pass

        check_results = await asyncio.gather(*tasks)

        issues = []
        for result in check_results:
            if result is not None:
                if result["type"] == "domain":
                    issues.append(f"Domain listed on {result['blacklist']}")
                elif result["type"] == "ip":
                    issues.append(f"IP {result['ip']} listed on {result['blacklist']}")

        if len(issues) == 0:
            status = "clean"
        elif len(issues) <= 2:
            status = "warning"
        else:
            status = "critical"

        return {
            "status": status,
            "issues": issues,
            "ips_checked": results["mx_ips_checked"],
            "checked": results["blacklists_checked"]
        }

    def parse_dmarc_detailed(self, dmarc_record: str) -> Dict:
        """
        Parser detallado de DMARC

        Args:
            dmarc_record: Registro DMARC completo

        Returns:
            Dict con información detallada de DMARC
        """
        details = {
            "policy": None,
            "subdomain_policy": None,
            "percentage": 100,
            "alignment_spf": "relaxed",
            "alignment_dkim": "relaxed",
            "aggregate_reports": [],
            "forensic_reports": [],
            "report_format": None,
            "report_interval": None,
            "failure_options": None
        }

        if not dmarc_record:
            return details

        parts = dmarc_record.split(';')
        for part in parts:
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                key = key.strip().lower()
                value = value.strip()

                if key == 'p':
                    details['policy'] = value
                elif key == 'sp':
                    details['subdomain_policy'] = value
                elif key == 'pct':
                    details['percentage'] = int(value)
                elif key == 'aspf':
                    details['alignment_spf'] = value
                elif key == 'adkim':
                    details['alignment_dkim'] = value
                elif key == 'rua':
                    details['aggregate_reports'] = [r.strip() for r in value.split(',')]
                elif key == 'ruf':
                    details['forensic_reports'] = [r.strip() for r in value.split(',')]
                elif key == 'rf':
                    details['report_format'] = value
                elif key == 'ri':
                    details['report_interval'] = value
                elif key == 'fo':
                    details['failure_options'] = value

        return details

    def check_domain_age(self, domain: str) -> Dict:
        """
        Obtiene la edad del dominio mediante WHOIS

        Args:
            domain: Dominio a verificar

        Returns:
            Dict con información de edad del dominio
        """
        try:
            w = whois.whois(domain)

            creation_date = None
            expiration_date = None
            updated_date = None
            age_days = None

            if hasattr(w, 'creation_date') and w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date

                if creation_date:
                    age_days = (datetime.now() - creation_date).days

            if hasattr(w, 'expiration_date') and w.expiration_date:
                if isinstance(w.expiration_date, list):
                    expiration_date = w.expiration_date[0]
                else:
                    expiration_date = w.expiration_date

            if hasattr(w, 'updated_date') and w.updated_date:
                if isinstance(w.updated_date, list):
                    updated_date = w.updated_date[0]
                else:
                    updated_date = w.updated_date

            registrar = getattr(w, 'registrar', None)

            return {
                "has_info": True,
                "creation_date": creation_date.isoformat() if creation_date else None,
                "expiration_date": expiration_date.isoformat() if expiration_date else None,
                "updated_date": updated_date.isoformat() if updated_date else None,
                "age_days": age_days,
                "age_years": round(age_days / 365, 1) if age_days else None,
                "registrar": registrar,
                "is_new": age_days < 365 if age_days else None,
                "error": None
            }

        except Exception as e:
            return {
                "has_info": False,
                "creation_date": None,
                "expiration_date": None,
                "updated_date": None,
                "age_days": None,
                "age_years": None,
                "registrar": None,
                "is_new": None,
                "error": str(e)
            }

    async def check_all_async(self, domain: str) -> Dict:
        """
        Verifica todos los registros DNS de correo en paralelo (OPTIMIZADO)

        Args:
            domain: Dominio a verificar

        Returns:
            Dict con toda la información DNS
        """
        dkim_task = self.check_dkim_record_async(domain)
        blacklists_task = self.check_blacklists_async(domain)

        mx = self.check_mx_records(domain)
        spf = self.check_spf_record(domain)
        dmarc = self.check_dmarc_record(domain)

        dkim, blacklists = await asyncio.gather(dkim_task, blacklists_task)

        return {
            "domain": domain,
            "mx": mx,
            "spf": spf,
            "dmarc": dmarc,
            "dkim": dkim,
            "blacklists": blacklists
        }
