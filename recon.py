#!/usr/bin/env python3
"""
Recon Pipeline — automação de reconhecimento ofensivo em 3 etapas.

Uso:
    python recon.py all example.com
    python recon.py phase1 example.com
    python recon.py phase2 example.com
    python recon.py phase3 example.com --emails emails.txt
    python recon.py report example.com

⚠️  Use apenas contra domínios/alvos para os quais você tem autorização
    explícita (programas de bug bounty, labs próprios, CTFs como HTB/THM).
"""
import argparse
import sys
from pathlib import Path

from recon_pipeline.utils import ensure_output_dir, log
from recon_pipeline.modules.phase1_recon import run_phase1
from recon_pipeline.modules.phase2_discovery import run_phase2
from recon_pipeline.modules.phase3_osint import run_phase3
from recon_pipeline.report import generate_report


def load_emails(path: str) -> list:
    if not path:
        return []
    p = Path(path)
    if not p.exists():
        log.warning(f"Arquivo de e-mails '{path}' não encontrado.")
        return []
    return [l.strip() for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]


def confirm_authorization(target: str) -> bool:
    print(f"\n⚠️  Você confirma que possui autorização explícita para testar '{target}'? [s/N] ", end="")
    resp = input().strip().lower()
    return resp == "s"


def main():
    parser = argparse.ArgumentParser(description="Recon Pipeline — automação de reconhecimento ofensivo.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    for cmd in ("phase1", "phase2", "phase3", "all"):
        sp = subparsers.add_parser(cmd, help=f"Executa {cmd}")
        sp.add_argument("domain", help="Domínio alvo (ex: example.com)")
        sp.add_argument("--yes", action="store_true", help="Pula a confirmação de autorização")
        if cmd in ("phase3", "all"):
            sp.add_argument("--emails", help="Arquivo .txt com e-mails para checar no HIBP (um por linha)")

    report_parser = subparsers.add_parser("report", help="Gera/regera o relatório Markdown a partir dos dados existentes")
    report_parser.add_argument("domain", help="Domínio alvo já processado")

    args = parser.parse_args()

    if args.command != "report" and not args.yes:
        if not confirm_authorization(args.domain):
            log.error("Autorização não confirmada. Encerrando.")
            sys.exit(1)

    outdir = ensure_output_dir(args.domain)

    if args.command == "phase1":
        run_phase1(args.domain, outdir)
    elif args.command == "phase2":
        run_phase2(args.domain, outdir)
    elif args.command == "phase3":
        emails = load_emails(getattr(args, "emails", None))
        run_phase3(args.domain, outdir, emails)
    elif args.command == "all":
        run_phase1(args.domain, outdir)
        run_phase2(args.domain, outdir)
        emails = load_emails(getattr(args, "emails", None))
        run_phase3(args.domain, outdir, emails)

    report_path = generate_report(args.domain, outdir)
    log.info(f"Relatório gerado em: {report_path}")


if __name__ == "__main__":
    main()
