"""
Consolida os resumos (phase1_summary.json, phase2_summary.json,
phase3_summary.json) em um único relatório Markdown legível.
"""
import json
from pathlib import Path
from datetime import datetime


def _tool_line(name: str, data: dict) -> str:
    if data.get("skipped"):
        reason = data.get("reason", "ferramenta indisponível")
        return f"- **{name}**: ⏭️ pulado ({reason})"
    if not data.get("success", True):
        return f"- **{name}**: ❌ falhou na execução"
    count = data.get("count")
    extra = f" — {count} resultado(s)" if count is not None else ""
    return f"- **{name}**: ✅ ok{extra}"


def generate_report(target: str, outdir: Path) -> Path:
    report_path = outdir / "REPORT.md"
    lines = [
        f"# Relatório de Reconhecimento — {target}",
        f"\n_Gerado em {datetime.now().strftime('%d/%m/%Y %H:%M')}_\n",
        "> ⚠️ Este relatório deve ser usado apenas contra alvos para os quais você tem autorização explícita.\n",
    ]

    phase_files = {
        "Etapa 1 — Reconhecimento inicial": outdir / "phase1_summary.json",
        "Etapa 2 — Descoberta profunda": outdir / "phase2_summary.json",
        "Etapa 3 — OSINT de exposição": outdir / "phase3_summary.json",
    }

    total_findings = 0

    for phase_title, phase_file in phase_files.items():
        lines.append(f"## {phase_title}\n")
        if not phase_file.exists():
            lines.append("_Etapa não executada._\n")
            continue

        summary = json.loads(phase_file.read_text(encoding="utf-8"))
        for tool_name, tool_data in summary.items():
            lines.append(_tool_line(tool_name, tool_data))
            if isinstance(tool_data.get("count"), int):
                total_findings += tool_data["count"]
        lines.append("")

    lines.insert(3, f"**Total de itens coletados/encontrados em todas as etapas: {total_findings}**\n")

    # Destaques de segurança (Nuclei + Subzy + HIBP) ficam no topo, se existirem
    highlights = []
    p1 = phase_files["Etapa 1 — Reconhecimento inicial"]
    if p1.exists():
        p1_data = json.loads(p1.read_text(encoding="utf-8"))
        nuclei_count = p1_data.get("nuclei", {}).get("count", 0)
        subzy_count = p1_data.get("subzy", {}).get("count", 0)
        if nuclei_count:
            highlights.append(f"🔴 **{nuclei_count} vulnerabilidade(s)** sinalizada(s) pelo Nuclei — ver `nuclei.json`")
        if subzy_count:
            highlights.append(f"🟠 **{subzy_count} possível(is) subdomain takeover(s)** — ver `subzy.txt`")

    p3 = phase_files["Etapa 3 — OSINT de exposição"]
    if p3.exists():
        p3_data = json.loads(p3.read_text(encoding="utf-8"))
        breached = p3_data.get("hibp", {}).get("breached_count", 0)
        if breached:
            highlights.append(f"🔴 **{breached} e-mail(s) com vazamentos conhecidos** — ver `hibp.json`")

    if highlights:
        lines.insert(4, "## 🚩 Destaques\n" + "\n".join(highlights) + "\n")

    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path
