"""
ETAPA 1 — Reconhecimento inicial
Subfinder -> Whois -> DNSX -> HTTPX -> Nmap -> Nuclei -> Subzy

Cada função recebe o domínio alvo e o diretório de saída, executa a
ferramenta correspondente e retorna um resumo (dict) usado no relatório final.
"""
from pathlib import Path
from ..utils import run_command, check_tool_installed, save_lines, read_lines, parse_jsonl, save_json, log
from ..config import Config


def run_subfinder(domain: str, outdir: Path) -> dict:
    """Enumera subdomínios de forma passiva."""
    if not check_tool_installed("subfinder"):
        return {"tool": "subfinder", "skipped": True}

    out_file = outdir / "subfinder.txt"
    result = run_command(["subfinder", "-d", domain, "-silent", "-o", str(out_file)])
    subdomains = read_lines(out_file)
    log.info(f"Subfinder encontrou {len(subdomains)} subdomínios.")
    return {"tool": "subfinder", "success": result["success"], "count": len(subdomains), "file": str(out_file)}


def run_whois(domain: str, outdir: Path) -> dict:
    """Consulta WHOIS do domínio raiz."""
    if not check_tool_installed("whois"):
        return {"tool": "whois", "skipped": True}

    out_file = outdir / "whois.txt"
    result = run_command(["whois", domain])
    out_file.write_text(result["stdout"], encoding="utf-8")
    return {"tool": "whois", "success": result["success"], "file": str(out_file)}


def run_dnsx(outdir: Path) -> dict:
    """Resolve e valida os subdomínios encontrados pelo Subfinder."""
    subfinder_file = outdir / "subfinder.txt"
    if not check_tool_installed("dnsx") or not subfinder_file.exists():
        return {"tool": "dnsx", "skipped": True}

    out_file = outdir / "dnsx.json"
    result = run_command(
        ["dnsx", "-l", str(subfinder_file), "-json", "-silent", "-o", str(out_file)]
    )
    resolved = parse_jsonl(out_file.read_text(encoding="utf-8")) if out_file.exists() else []
    log.info(f"DNSX resolveu {len(resolved)} registros.")
    return {"tool": "dnsx", "success": result["success"], "count": len(resolved), "file": str(out_file)}


def run_httpx(outdir: Path) -> dict:
    """Identifica quais subdomínios respondem via HTTP/HTTPS e coleta metadados (título, status, tech)."""
    subfinder_file = outdir / "subfinder.txt"
    if not check_tool_installed("httpx") or not subfinder_file.exists():
        return {"tool": "httpx", "skipped": True}

    out_file = outdir / "httpx.json"
    result = run_command(
        ["httpx", "-l", str(subfinder_file), "-json", "-silent",
         "-status-code", "-title", "-tech-detect", "-o", str(out_file)]
    )
    live_hosts = parse_jsonl(out_file.read_text(encoding="utf-8")) if out_file.exists() else []
    urls = [h["url"] for h in live_hosts if "url" in h]
    save_lines(urls, outdir / "live_urls.txt")
    log.info(f"HTTPX encontrou {len(live_hosts)} hosts ativos.")
    return {"tool": "httpx", "success": result["success"], "count": len(live_hosts), "file": str(out_file)}


def run_nmap(outdir: Path) -> dict:
    """Faz scan de portas nos hosts vivos identificados pelo HTTPX."""
    live_urls_file = outdir / "live_urls.txt"
    if not check_tool_installed("nmap") or not live_urls_file.exists():
        return {"tool": "nmap", "skipped": True}

    hosts = [u.split("//")[-1].split("/")[0] for u in read_lines(live_urls_file)]
    hosts = sorted(set(h.split(":")[0] for h in hosts))
    if not hosts:
        return {"tool": "nmap", "skipped": True, "reason": "sem hosts vivos"}

    out_file = outdir / "nmap.xml"
    result = run_command(
        ["nmap", "-sV", "--top-ports", Config.NMAP_TOP_PORTS, "-oX", str(out_file), *hosts],
        timeout=1800,
    )
    log.info(f"Nmap escaneou {len(hosts)} hosts (top {Config.NMAP_TOP_PORTS} portas).")
    return {"tool": "nmap", "success": result["success"], "hosts_scanned": len(hosts), "file": str(out_file)}


def run_nuclei(outdir: Path) -> dict:
    """Roda templates de vulnerabilidades conhecidas contra os hosts vivos."""
    live_urls_file = outdir / "live_urls.txt"
    if not check_tool_installed("nuclei") or not live_urls_file.exists():
        return {"tool": "nuclei", "skipped": True}

    out_file = outdir / "nuclei.json"
    result = run_command(
        ["nuclei", "-l", str(live_urls_file), "-severity", Config.NUCLEI_SEVERITY,
         "-json-export", str(out_file), "-silent"],
        timeout=1800,
    )
    findings = parse_jsonl(out_file.read_text(encoding="utf-8")) if out_file.exists() else []
    log.info(f"Nuclei encontrou {len(findings)} findings (severidade: {Config.NUCLEI_SEVERITY}).")
    return {"tool": "nuclei", "success": result["success"], "count": len(findings), "file": str(out_file)}


def run_subzy(outdir: Path) -> dict:
    """Checa possíveis subdomain takeovers nos subdomínios encontrados."""
    subfinder_file = outdir / "subfinder.txt"
    if not check_tool_installed("subzy") or not subfinder_file.exists():
        return {"tool": "subzy", "skipped": True}

    out_file = outdir / "subzy.txt"
    result = run_command(
        ["subzy", "run", "--targets", str(subfinder_file), "--hide_fails"]
    )
    out_file.write_text(result["stdout"], encoding="utf-8")
    vulnerable = [l for l in result["stdout"].splitlines() if "VULNERABLE" in l.upper()]
    log.info(f"Subzy sinalizou {len(vulnerable)} possíveis takeovers.")
    return {"tool": "subzy", "success": result["success"], "count": len(vulnerable), "file": str(out_file)}


def run_phase1(domain: str, outdir: Path) -> dict:
    """Executa a Etapa 1 completa, na ordem correta (cada etapa alimenta a próxima)."""
    log.info(f"=== ETAPA 1: Reconhecimento inicial de {domain} ===")
    summary = {
        "subfinder": run_subfinder(domain, outdir),
        "whois": run_whois(domain, outdir),
        "dnsx": run_dnsx(outdir),
        "httpx": run_httpx(outdir),
        "nmap": run_nmap(outdir),
        "nuclei": run_nuclei(outdir),
        "subzy": run_subzy(outdir),
    }
    save_json(summary, outdir / "phase1_summary.json")
    return summary
