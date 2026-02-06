"""
Spectre Backend API
FastAPI application for domain reconnaissance
"""

from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from urllib.parse import urlparse
import re

from scanner import full_scan

# Initialize FastAPI app
app = FastAPI(
    title="Spectre API",
    description="Stealthy domain reconnaissance API for security researchers",
    version="1.0.0",
)

# Enable CORS for Chrome Extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for extension
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def extract_domain(input_str: str) -> str:
    """Extract clean domain from URL or domain string"""
    # Remove protocol if present
    if "://" in input_str:
        parsed = urlparse(input_str)
        domain = parsed.netloc
    else:
        domain = input_str
    
    # Remove www. prefix
    if domain.startswith("www."):
        domain = domain[4:]
    
    # Remove port if present
    if ":" in domain:
        domain = domain.split(":")[0]
    
    # Remove path if present
    if "/" in domain:
        domain = domain.split("/")[0]
    
    # Basic validation
    if not domain or len(domain) < 3:
        raise ValueError("Invalid domain")
    
    # Check for valid domain format
    domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$|^[a-zA-Z0-9]\.[a-zA-Z]{2,}$'
    if not re.match(domain_pattern, domain):
        # Try to extract just the domain part for subdomains
        parts = domain.split(".")
        if len(parts) >= 2:
            # Take last two parts as base domain
            domain = ".".join(parts[-2:])
    
    return domain.lower()


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "online",
        "service": "Spectre API",
        "version": "1.0.0",
        "message": "Ghost protocol active. Ready for reconnaissance.",
    }


@app.get("/scan")
async def scan_domain(domain: str = Query(..., description="Domain or URL to scan")):
    """
    Perform comprehensive reconnaissance on a domain.
    
    Returns:
        JSON object containing:
        - whois: Registrar and domain ownership info
        - ip_hosting: IP address, geolocation, ISP details
        - ssl: Certificate information and validity
        - historical: Mock historical ownership data
        - subdomains: Discovered subdomains from CT logs
        - tech_stack: Technology detection with CVE warnings
    """
    try:
        # Extract and validate domain
        clean_domain = extract_domain(domain)
        
        # Perform full scan
        results = await full_scan(clean_domain)
        
        return JSONResponse(content=results)
    
    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid domain format: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Scan failed: {str(e)}"
        )


@app.get("/health")
async def health_check():
    """Detailed health check"""
    return {
        "status": "healthy",
        "modules": {
            "whois": "operational",
            "ip_analysis": "operational",
            "ssl_analysis": "operational",
            "subdomain_discovery": "operational",
            "tech_detection": "operational",
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
