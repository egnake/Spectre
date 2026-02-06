"""
Spectre Scanner Module
All reconnaissance functions with async support
"""

import socket
import ssl
import asyncio
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from concurrent.futures import ThreadPoolExecutor
import whois
import requests

# Thread pool for blocking operations
executor = ThreadPoolExecutor(max_workers=10)

# CVE Database (internal dictionary for known vulnerabilities)
CVE_DATABASE = {
    "nginx": {
        "1.18": ["CVE-2021-23017", "CVE-2021-3618"],
        "1.19": ["CVE-2021-23017"],
        "1.20": ["CVE-2021-23017"],
    },
    "apache": {
        "2.4.49": ["CVE-2021-41773", "CVE-2021-42013"],
        "2.4.50": ["CVE-2021-42013"],
        "2.4.51": [],
    },
    "php": {
        "7.4": ["CVE-2021-21702", "CVE-2021-21703"],
        "8.0": ["CVE-2021-21703"],
    },
    "openssl": {
        "1.0.2": ["CVE-2020-1971", "CVE-2021-3449"],
        "1.1.1": ["CVE-2021-3449", "CVE-2021-3450"],
    },
}


async def run_in_executor(func, *args):
    """Run blocking function in thread executor"""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(executor, func, *args)


# =============================================================================
# WHOIS & REGISTRAR INTELLIGENCE
# =============================================================================
def _whois_lookup_sync(domain: str) -> Dict[str, Any]:
    """Synchronous Whois lookup"""
    try:
        w = whois.whois(domain)
        
        # Handle creation date
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        # Handle expiration date
        expiration_date = w.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        
        # Calculate days until expiry
        days_until_expiry = None
        expiry_warning = False
        if expiration_date:
            if isinstance(expiration_date, datetime):
                days_until_expiry = (expiration_date - datetime.now()).days
                expiry_warning = days_until_expiry < 30
        
        # Handle name servers
        name_servers = w.name_servers
        if isinstance(name_servers, list):
            name_servers = [ns.lower() if isinstance(ns, str) else ns for ns in name_servers[:5]]
        elif name_servers:
            name_servers = [name_servers.lower()]
        else:
            name_servers = []
        
        return {
            "success": True,
            "registrar": w.registrar or "Unknown",
            "organization": w.org or "Not disclosed",
            "creation_date": str(creation_date) if creation_date else "Unknown",
            "expiration_date": str(expiration_date) if expiration_date else "Unknown",
            "days_until_expiry": days_until_expiry,
            "expiry_warning": expiry_warning,
            "name_servers": name_servers,
            "registrant_country": w.country or "Unknown",
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "registrar": "N/A",
            "organization": "N/A",
            "creation_date": "N/A",
            "expiration_date": "N/A",
            "days_until_expiry": None,
            "expiry_warning": False,
            "name_servers": [],
            "registrant_country": "N/A",
        }


async def whois_lookup(domain: str) -> Dict[str, Any]:
    """Async Whois lookup wrapper"""
    return await run_in_executor(_whois_lookup_sync, domain)


# =============================================================================
# IP & HOSTING ANALYSIS
# =============================================================================
def _ip_analysis_sync(domain: str) -> Dict[str, Any]:
    """Synchronous IP and hosting analysis"""
    try:
        # Resolve domain to IP
        ip_address = socket.gethostbyname(domain)
        
        # Get geolocation data from ip-api.com
        response = requests.get(
            f"http://ip-api.com/json/{ip_address}?fields=status,country,city,isp,org,as,proxy,hosting",
            timeout=5
        )
        geo_data = response.json()
        
        if geo_data.get("status") == "success":
            isp = geo_data.get("isp", "Unknown")
            
            # Detect WAF/Proxy
            waf_detected = False
            waf_provider = None
            waf_keywords = ["cloudflare", "akamai", "fastly", "incapsula", "sucuri", "aws", "google"]
            for keyword in waf_keywords:
                if keyword in isp.lower() or keyword in geo_data.get("org", "").lower():
                    waf_detected = True
                    waf_provider = keyword.capitalize()
                    break
            
            return {
                "success": True,
                "ip_address": ip_address,
                "country": geo_data.get("country", "Unknown"),
                "city": geo_data.get("city", "Unknown"),
                "isp": isp,
                "organization": geo_data.get("org", "Unknown"),
                "asn": geo_data.get("as", "Unknown"),
                "is_proxy": geo_data.get("proxy", False),
                "is_hosting": geo_data.get("hosting", False),
                "waf_detected": waf_detected,
                "waf_provider": waf_provider,
            }
        else:
            return {
                "success": True,
                "ip_address": ip_address,
                "country": "Unknown",
                "city": "Unknown",
                "isp": "Unknown",
                "organization": "Unknown",
                "asn": "Unknown",
                "is_proxy": False,
                "is_hosting": False,
                "waf_detected": False,
                "waf_provider": None,
            }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "ip_address": "N/A",
            "country": "N/A",
            "city": "N/A",
            "isp": "N/A",
            "organization": "N/A",
            "asn": "N/A",
            "is_proxy": False,
            "is_hosting": False,
            "waf_detected": False,
            "waf_provider": None,
        }


async def ip_analysis(domain: str) -> Dict[str, Any]:
    """Async IP analysis wrapper"""
    return await run_in_executor(_ip_analysis_sync, domain)


# =============================================================================
# SSL/TLS CERTIFICATE AUDIT
# =============================================================================
def _ssl_analysis_sync(domain: str) -> Dict[str, Any]:
    """Synchronous SSL certificate analysis"""
    try:
        context = ssl.create_default_context()
        
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                protocol_version = ssock.version()
                
                # Parse certificate dates
                not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                
                # Calculate days remaining
                days_remaining = (not_after - datetime.now()).days
                
                # Extract issuer
                issuer_parts = dict(x[0] for x in cert['issuer'])
                issuer = issuer_parts.get('organizationName', issuer_parts.get('commonName', 'Unknown'))
                
                # Extract subject
                subject_parts = dict(x[0] for x in cert['subject'])
                subject = subject_parts.get('commonName', domain)
                
                # Get SANs (Subject Alternative Names)
                san_list = []
                for san_type, san_value in cert.get('subjectAltName', []):
                    if san_type == 'DNS':
                        san_list.append(san_value)
                
                return {
                    "success": True,
                    "issuer": issuer,
                    "subject": subject,
                    "valid_from": not_before.strftime('%Y-%m-%d'),
                    "valid_to": not_after.strftime('%Y-%m-%d'),
                    "days_remaining": days_remaining,
                    "protocol_version": protocol_version,
                    "san_count": len(san_list),
                    "serial_number": cert.get('serialNumber', 'Unknown'),
                    "is_expired": days_remaining < 0,
                    "expiring_soon": 0 < days_remaining < 30,
                }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "issuer": "N/A",
            "subject": "N/A",
            "valid_from": "N/A",
            "valid_to": "N/A",
            "days_remaining": None,
            "protocol_version": "N/A",
            "san_count": 0,
            "serial_number": "N/A",
            "is_expired": False,
            "expiring_soon": False,
        }


async def ssl_analysis(domain: str) -> Dict[str, Any]:
    """Async SSL analysis wrapper"""
    return await run_in_executor(_ssl_analysis_sync, domain)


# =============================================================================
# HISTORICAL DATA (MOCK)
# =============================================================================
async def get_historical_data(domain: str) -> Dict[str, Any]:
    """Generate mock historical data for Pro Feature demonstration"""
    # Simulated historical data
    return {
        "success": True,
        "is_mock": True,
        "pro_feature": True,
        "previous_registrars": [
            {"registrar": "GoDaddy LLC", "period": "2018-2020"},
            {"registrar": "Namecheap Inc", "period": "2015-2018"},
            {"registrar": "Network Solutions", "period": "2010-2015"},
        ],
        "drop_history": [
            {"date": "2010-03-15", "event": "Domain registered"},
            {"date": "2015-06-20", "event": "Transferred to Namecheap"},
            {"date": "2018-11-10", "event": "Transferred to GoDaddy"},
            {"date": "2020-05-25", "event": "Transferred to current registrar"},
        ],
        "ownership_changes": 3,
        "total_age_years": 14,
    }


# =============================================================================
# SUBDOMAIN DISCOVERY (crt.sh)
# =============================================================================
def _subdomain_discovery_sync(domain: str) -> Dict[str, Any]:
    """Synchronous subdomain discovery via Certificate Transparency"""
    try:
        response = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=10,
            headers={"User-Agent": "Spectre/1.0"}
        )
        
        if response.status_code == 200:
            data = response.json()
            
            # Extract unique subdomains
            subdomains = set()
            for entry in data:
                name_value = entry.get("name_value", "")
                # Handle multiple names separated by newlines
                for name in name_value.split("\n"):
                    name = name.strip().lower()
                    if name and "*" not in name and name != domain:
                        subdomains.add(name)
            
            # Sort and limit to top 10
            subdomain_list = sorted(list(subdomains))[:10]
            
            return {
                "success": True,
                "subdomains": subdomain_list,
                "total_found": len(subdomains),
                "displayed": len(subdomain_list),
                "source": "crt.sh (Certificate Transparency)",
            }
        else:
            return {
                "success": False,
                "error": f"HTTP {response.status_code}",
                "subdomains": [],
                "total_found": 0,
                "displayed": 0,
                "source": "crt.sh",
            }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "subdomains": [],
            "total_found": 0,
            "displayed": 0,
            "source": "crt.sh",
        }


async def subdomain_discovery(domain: str) -> Dict[str, Any]:
    """Async subdomain discovery wrapper"""
    return await run_in_executor(_subdomain_discovery_sync, domain)


# =============================================================================
# TECH STACK & VULNERABILITY DETECTION
# =============================================================================
def _tech_detection_sync(domain: str) -> Dict[str, Any]:
    """Synchronous technology and CVE detection"""
    try:
        response = requests.get(
            f"https://{domain}",
            timeout=5,
            headers={"User-Agent": "Spectre/1.0"},
            allow_redirects=True
        )
        
        headers = response.headers
        technologies = []
        vulnerabilities = []
        
        # Analyze Server header
        server = headers.get("Server", "")
        if server:
            technologies.append({"name": "Server", "value": server})
            
            # Check for CVEs
            server_lower = server.lower()
            for tech, versions in CVE_DATABASE.items():
                if tech in server_lower:
                    for version, cves in versions.items():
                        if version in server:
                            for cve in cves:
                                vulnerabilities.append({
                                    "technology": f"{tech} {version}",
                                    "cve": cve,
                                    "source": "Server header",
                                })
        
        # Analyze X-Powered-By
        powered_by = headers.get("X-Powered-By", "")
        if powered_by:
            technologies.append({"name": "X-Powered-By", "value": powered_by})
            
            # Check for CVEs
            powered_lower = powered_by.lower()
            for tech, versions in CVE_DATABASE.items():
                if tech in powered_lower:
                    for version, cves in versions.items():
                        if version in powered_by:
                            for cve in cves:
                                vulnerabilities.append({
                                    "technology": f"{tech} {version}",
                                    "cve": cve,
                                    "source": "X-Powered-By header",
                                })
        
        # Other interesting headers
        interesting_headers = [
            "X-AspNet-Version",
            "X-AspNetMvc-Version",
            "X-Generator",
            "X-Drupal-Cache",
            "X-Varnish",
            "X-Cache",
            "CF-RAY",
            "X-Amz-Cf-Id",
        ]
        
        for header in interesting_headers:
            value = headers.get(header)
            if value:
                technologies.append({"name": header, "value": value})
        
        # Security headers check
        security_headers = {
            "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
            "Content-Security-Policy": headers.get("Content-Security-Policy"),
            "X-Frame-Options": headers.get("X-Frame-Options"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options"),
            "X-XSS-Protection": headers.get("X-XSS-Protection"),
        }
        
        missing_security_headers = [k for k, v in security_headers.items() if not v]
        
        return {
            "success": True,
            "technologies": technologies,
            "vulnerabilities": vulnerabilities,
            "has_vulnerabilities": len(vulnerabilities) > 0,
            "security_headers": security_headers,
            "missing_security_headers": missing_security_headers,
            "headers_analyzed": len(headers),
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "technologies": [],
            "vulnerabilities": [],
            "has_vulnerabilities": False,
            "security_headers": {},
            "missing_security_headers": [],
            "headers_analyzed": 0,
        }


async def tech_detection(domain: str) -> Dict[str, Any]:
    """Async tech detection wrapper"""
    return await run_in_executor(_tech_detection_sync, domain)


# =============================================================================
# FULL SCAN ORCHESTRATOR
# =============================================================================
async def full_scan(domain: str) -> Dict[str, Any]:
    """Execute all scans concurrently and return combined results"""
    start_time = datetime.now()
    
    # Run all scans concurrently
    results = await asyncio.gather(
        whois_lookup(domain),
        ip_analysis(domain),
        ssl_analysis(domain),
        get_historical_data(domain),
        subdomain_discovery(domain),
        tech_detection(domain),
        return_exceptions=True
    )
    
    end_time = datetime.now()
    scan_duration = (end_time - start_time).total_seconds()
    
    # Handle any exceptions in results
    processed_results = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            processed_results.append({"success": False, "error": str(result)})
        else:
            processed_results.append(result)
    
    return {
        "domain": domain,
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "scan_duration_seconds": round(scan_duration, 2),
        "whois": processed_results[0],
        "ip_hosting": processed_results[1],
        "ssl": processed_results[2],
        "historical": processed_results[3],
        "subdomains": processed_results[4],
        "tech_stack": processed_results[5],
    }
