"""
ETAPA 2 — Descoberta profunda
GAU -> S3Scanner -> Katana -> ExifTool

Aprofunda o reconhecimento: URLs históricas (arquivo.org/wayback),
buckets S3 mal configurados, crawling ativo e metadados de arquivos
públicos encontrados (PDFs, imagens, docs).
"""
import requests
from pathlib import Path
from ..utils import run_command, check_tool_installed, save_lines, read_lines, log


# Extensões de arquivo interessantes para análise de metadados (ExifTool)
METADATA_EXTENSIONS = (".pdf", ".docx", ".doc", ".xlsx", ".pptx", ".jpg", ".jpeg", ".png", ".tiff")


def run_gau(domain: str, outdir: Path) -> dict:
    """Busca URLs históricas indexadas (Wayback Machine, Common Crawl, OTX)."""
    if not check_tool_installed("gau"):
        return {"tool": "gau", "skipped": True}

    out_file = outdir / "gau.txt"
    result = run_command(["gau", "--subs", domain], timeout=600)
    urls = [l for l in result["stdout"].splitlines() if l.strip()]
    save_lines(urls, out_file)
    log.info(f"GAU coletou {len(urls)} URLs históricas.")
    return {"tool": "gau", "success": result["success"], "count": len(urls), "file": str(out_file)}


def run_s3scanner(domain: str, outdir: Path) -> dict:
    """
    Gera permutações comuns de nomes de bucket a partir do domínio
    (ex: empresa, empresa-backup, empresa-dev, empresa-static) e testa com s3scanner.
    """
    if not check_tool_installed("s3scanner"):
        return {"tool": "s3scanner", "skipped": True}

    base_name = domain.split(".")[0]
    suffixes = ["", "-backup", "-backups", "-dev", "-staging", "-prod", "-static",
                "-assets", "-media", "-public", "-files", "-data", "-www"]
    candidates = [f"{base_name}{s}" for s in suffixes]

    candidates_file = outdir / "s3_candidates.txt"
    save_lines(candidates, candidates_file)

    out_file = outdir / "s3scanner.txt"
    result = run_command(["s3scanner", "scan", "--bucket-file", str(candidates_file)])
    out_file.write_text(result["stdout"], encoding="utf-8")
    found = [l for l in result["stdout"].splitlines() if "bucket_exists" in l.lower() or "found" in l.lower()]
    log.info(f"S3Scanner testou {len(candidates)} nomes candidatos, {len(found)} possíveis achados.")
    return {"tool": "s3scanner", "success": result["success"], "candidates_tested": len(candidates),
            "count": len(found), "file": str(out_file)}


def run_katana(outdir: Path) -> dict:
    """Faz crawling ativo a partir dos hosts vivos encontrados na Etapa 1."""
    live_urls_file = outdir / "live_urls.txt"
    if not check_tool_installed("katana") or not live_urls_file.exists():
        return {"tool": "katana", "skipped": True}

    out_file = outdir / "katana.txt"
    result = run_command(
        ["katana", "-list", str(live_urls_file), "-silent", "-o", str(out_file), "-d", "2"],
        timeout=900,
    )
    urls = read_lines(out_file)
    log.info(f"Katana encontrou {len(urls)} URLs via crawling.")
    return {"tool": "katana", "success": result["success"], "count": len(urls), "file": str(out_file)}


def _download_candidate_files(outdir: Path, max_files: int = 20) -> list:
    """Baixa uma amostra de arquivos (PDF/imagens/docs) encontrados pelo GAU e Katana."""
    urls = set(read_lines(outdir / "gau.txt")) | set(read_lines(outdir / "katana.txt"))
    candidate_urls = [u for u in urls if u.lower().endswith(METADATA_EXTENSIONS)][:max_files]

    downloads_dir = outdir / "downloaded_files"
    downloads_dir.mkdir(exist_ok=True)
    downloaded_paths = []

    for url in candidate_urls:
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                filename = url.split("/")[-1].split("?")[0] or "file"
                filepath = downloads_dir / filename
                filepath.write_bytes(resp.content)
                downloaded_paths.append(filepath)
        except requests.RequestException:
            continue

    return downloaded_paths


def run_exiftool(outdir: Path) -> dict:
    """Baixa uma amostra de arquivos públicos e extrai metadados (autor, GPS, software)."""
    if not check_tool_installed("exiftool"):
        return {"tool": "exiftool", "skipped": True}

    downloaded_files = _download_candidate_files(outdir)
    if not downloaded_files:
        return {"tool": "exiftool", "skipped": True, "reason": "nenhum arquivo candidato encontrado"}

    out_file = outdir / "exiftool.json"
    result = run_command(["exiftool", "-json", *[str(f) for f in downloaded_files]])
    out_file.write_text(result["stdout"], encoding="utf-8")
    log.info(f"ExifTool analisou {len(downloaded_files)} arquivos.")
    return {"tool": "exiftool", "success": result["success"], "count": len(downloaded_files), "file": str(out_file)}


def run_phase2(domain: str, outdir: Path) -> dict:
    """Executa a Etapa 2 completa."""
    log.info(f"=== ETAPA 2: Descoberta profunda de {domain} ===")
    summary = {
        "gau": run_gau(domain, outdir),
        "s3scanner": run_s3scanner(domain, outdir),
        "katana": run_katana(outdir),
        "exiftool": run_exiftool(outdir),
    }
    from ..utils import save_json
    save_json(summary, outdir / "phase2_summary.json")
    return summary
