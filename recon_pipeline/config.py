"""
Carrega configuração e API keys a partir de um arquivo .env
(veja .env.example). Nunca commite o .env real no Git.
"""
import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv é opcional; variáveis de ambiente também funcionam direto


class Config:
    HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")
    INTELX_API_KEY = os.getenv("INTELX_API_KEY", "")
    NUCLEI_SEVERITY = os.getenv("NUCLEI_SEVERITY", "medium,high,critical")
    NMAP_TOP_PORTS = os.getenv("NMAP_TOP_PORTS", "1000")
    OUTPUT_BASE_DIR = os.getenv("OUTPUT_BASE_DIR", "output")

    @classmethod
    def validate_osint_keys(cls):
        missing = []
        if not cls.HIBP_API_KEY:
            missing.append("HIBP_API_KEY")
        if not cls.INTELX_API_KEY:
            missing.append("INTELX_API_KEY")
        return missing
