"""
ETAPA 3 — OSINT de exposição de credenciais
Have I Been Pwned (HIBP) -> Intelligence X

Diferente das etapas anteriores, aqui usamos APIs diretamente via `requests`
em vez de binários de linha de comando. Ambas exigem API key própria
(veja .env.example). Use apenas contra e-mails/domínios que você tem
autorização para investigar.
"""
import time
import requests
from pathlib import Path
from ..utils import save_json, log
from ..config import Config

HIBP_BASE_URL = "https://haveibeenpwned.com/api/v3"
INTELX_BASE_URL = "https://2.intelx.io"  # endpoint padrão da API paga/free tier


def run_hibp(emails: list, outdir: Path) -> dict:
    """
    Consulta o HIBP para cada e-mail de uma lista (ex: e-mails coletados
    via OSINT nas etapas anteriores, ou fornecidos manualmente).
    Respeita o rate limit da API gratuita (~1.5s entre requisições).
    """
    if not Config.HIBP_API_KEY:
        return {"tool": "hibp", "skipped": True, "reason": "HIBP_API_KEY não configurada no .env"}
    if not emails:
        return {"tool": "hibp", "skipped": True, "reason": "nenhum e-mail fornecido"}

    headers = {"hibp-api-key": Config.HIBP_API_KEY, "user-agent": "recon-pipeline"}
    results = {}

    for email in emails:
        url = f"{HIBP_BASE_URL}/breachedaccount/{email}"
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                results[email] = resp.json()
            elif resp.status_code == 404:
                results[email] = []  # sem vazamentos conhecidos
            else:
                results[email] = {"error": f"status {resp.status_code}"}
        except requests.RequestException as e:
            results[email] = {"error": str(e)}
        time.sleep(1.6)  # respeita o rate limit da API

    out_file = outdir / "hibp.json"
    save_json(results, out_file)
    breached_count = sum(1 for v in results.values() if isinstance(v, list) and v)
    log.info(f"HIBP: {breached_count}/{len(emails)} e-mails com vazamentos conhecidos.")
    return {"tool": "hibp", "success": True, "emails_checked": len(emails),
            "breached_count": breached_count, "file": str(out_file)}


def run_intelx(query: str, outdir: Path) -> dict:
    """
    Busca o domínio/termo na Intelligence X (phonebook search),
    útil para achar e-mails, subdomínios e vazamentos indexados.
    """
    if not Config.INTELX_API_KEY:
        return {"tool": "intelx", "skipped": True, "reason": "INTELX_API_KEY não configurada no .env"}

    headers = {"x-key": Config.INTELX_API_KEY, "user-agent": "recon-pipeline"}

    try:
        search_resp = requests.post(
            f"{INTELX_BASE_URL}/phonebook/search",
            headers=headers,
            json={"term": query, "maxresults": 100, "media": 0, "target": 0},
            timeout=15,
        )
        search_resp.raise_for_status()
        search_id = search_resp.json().get("id")
        if not search_id:
            return {"tool": "intelx", "success": False, "reason": "sem search id retornado"}

        time.sleep(3)  # dá tempo pro IntelX processar a busca

        result_resp = requests.get(
            f"{INTELX_BASE_URL}/phonebook/search/result",
            headers=headers,
            params={"id": search_id, "limit": 1000},
            timeout=15,
        )
        result_resp.raise_for_status()
        data = result_resp.json()

        out_file = outdir / "intelx.json"
        save_json(data, out_file)
        selectors = data.get("selectors", [])
        log.info(f"Intelligence X encontrou {len(selectors)} seletores (e-mails, domínios, etc).")
        return {"tool": "intelx", "success": True, "count": len(selectors), "file": str(out_file)}

    except requests.RequestException as e:
        log.error(f"Erro ao consultar Intelligence X: {e}")
        return {"tool": "intelx", "success": False, "reason": str(e)}


def run_phase3(domain: str, outdir: Path, emails: list = None) -> dict:
    """Executa a Etapa 3 completa."""
    log.info(f"=== ETAPA 3: OSINT de exposição de {domain} ===")
    summary = {
        "hibp": run_hibp(emails or [], outdir),
        "intelx": run_intelx(domain, outdir),
    }
    save_json(summary, outdir / "phase3_summary.json")
    return summary
