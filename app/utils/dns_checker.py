"""
Utilidades para verificar registros DNS (MX, SPF, DMARC, DKIM)
"""
import dns.resolver
import dns.exception
from typing import Dict, List, Optional
import re
import whois
from datetime import datetime
import asyncio


class DNSChecker:
    """Clase para verificar registros DNS de un dominio"""
    
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5
    
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
                    # Validar sintaxis básica
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
            # DMARC siempre se busca en _dmarc.dominio
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
            # Ejecutar en thread pool para no bloquear
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
        except:
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
        # Selectores comunes a probar (top 20 más comunes)
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
        
        # Verificar todos los selectores en paralelo
        tasks = [self._check_dkim_selector_async(domain, sel) for sel in common_selectors]
        results = await asyncio.gather(*tasks)
        
        # Filtrar resultados válidos
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
                "error": f"No DKIM records found for common selectors",
                "note": "DKIM requires a specific selector. Common selectors were tested."
            }
    
    def _validate_spf(self, spf_record: str) -> bool:
        """Valida sintaxis básica de SPF"""
        if not spf_record.startswith('v=spf1'):
            return False
        
        # Debe terminar con un mecanismo all
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
            await loop.run_in_executor(
                None,
                dns.resolver.resolve,
                query,
                'A'
            )
            # Si llega aquí, está listado
            result = {"blacklist": bl_name, "type": bl_type}
            if extra_info:
                result.update(extra_info)
            return result
        except:
            return None
    
    async def check_blacklists_async(self, domain: str) -> Dict:
        """
        Verifica si el dominio o sus IPs MX están en blacklists (RBL/DNSBL)
        Usa las 20 blacklists más importantes en paralelo (OPTIMIZADO)
        
        Args:
            domain: Dominio a verificar
            
        Returns:
            Dict con información de blacklists
        """
        # Top 20 blacklists más importantes (seleccionadas por reputación y velocidad)
        blacklists = {
            # Domain-based blacklists (top 5)
            "domain": [
                "dbl.spamhaus.org",        # La más importante
                "multi.surbl.org",          # Muy usada
                "dbl.nordspam.com",
                "rhsbl.sorbs.net",
                "fresh.spameatingmonkey.net"
            ],
            # IP-based blacklists (top 15)
            "ip": [
                "zen.spamhaus.org",         # La más importante (ZEN incluye SBL+XBL+PBL)
                "bl.spamcop.net",           # SpamCop muy respetada
                "b.barracudacentral.org",   # Barracuda
                "dnsbl.sorbs.net",          # SORBS aggregate
                "psbl.surriel.com",         # Passive Spam Block List
                "bl.mailspike.net",         # MailSpike
                "dnsbl-1.uceprotect.net",   # UCEProtect Level 1
                "bl.spameatingmonkey.net",  # SEM
                "spam.spamrats.com",        # SpamRats
                "bl.blocklist.de",          # Blocklist.de
                "dyna.spamrats.com",        # SpamRats Dynamic
                "drone.abuse.ch",           # Abuse.ch
                "combined.abuse.ch",        # Abuse.ch Combined
                "pbl.spamhaus.org",         # Policy Block List
                "bl.nordspam.com"           # Nordspam
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
        
        # Verificar dominio en blacklists de dominio (en paralelo)
        for bl in blacklists["domain"]:
            query = f"{domain}.{bl}"
            tasks.append(self._check_single_blacklist_async(query, bl, "domain"))
            results["blacklists_checked"] += 1
        
        # Obtener IPs de servidores MX
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
                            
                            # Reversar la IP para consulta RBL
                            reversed_ip = '.'.join(reversed(ip_str.split('.')))
                            
                            # Verificar IP en blacklists (en paralelo)
                            for bl in blacklists["ip"]:
                                query = f"{reversed_ip}.{bl}"
                                tasks.append(self._check_single_blacklist_async(
                                    query, bl, "ip",
                                    {"ip": ip_str, "mx_server": mx_host}
                                ))
                                results["blacklists_checked"] += 1
                except:
                    pass
        except:
            pass
        
        # Ejecutar todas las verificaciones en paralelo
        check_results = await asyncio.gather(*tasks)
        
        # Procesar resultados
        for result in check_results:
            if result is not None:
                results["blacklists_listed"] += 1
                results["listed_in"].append(result)
                
                if result["type"] == "domain":
                    results["domain_blacklisted"] = True
                elif result["type"] == "ip":
                    results["ip_blacklisted"] = True
        
        results["is_blacklisted"] = results["domain_blacklisted"] or results["ip_blacklisted"]
        
        return results
    
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
        Esta función puede ser lenta (2-5 segundos)
        
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
            
            # WHOIS puede devolver listas o valores únicos
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
        # Ejecutar DKIM y Blacklists en paralelo (las operaciones más lentas)
        dkim_task = self.check_dkim_record_async(domain)
        blacklists_task = self.check_blacklists_async(domain)
        
        # Estas son rápidas, ejecutarlas normalmente
        mx = self.check_mx_records(domain)
        spf = self.check_spf_record(domain)
        dmarc = self.check_dmarc_record(domain)
        
        # Esperar resultados paralelos
        dkim, blacklists = await asyncio.gather(dkim_task, blacklists_task)
        
        return {
            "domain": domain,
            "mx": mx,
            "spf": spf,
            "dmarc": dmarc,
            "dkim": dkim,
            "blacklists": blacklists
        }
