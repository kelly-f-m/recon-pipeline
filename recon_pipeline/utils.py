"""
Utilitários centrais do pipeline: execução de comandos externos,
logging colorido e gerenciamento de diretórios de saída.
"""
import subprocess
import shutil
import logging
import json
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("recon-pipeline")


def check_tool_installed(tool_name: str) -> bool:
    """Verifica se uma ferramenta está disponível no PATH."""
    found = shutil.which(tool_name) is not None
    if not found:
        log.warning(f"Ferramenta '{tool_name}' não encontrada no PATH. Pulando etapa.")
    return found


def run_command(cmd: list, timeout: int = 600, capture_output: bool = True) -> dict:
    """
    Executa um comando externo de forma segura.
    Retorna dict com stdout, stderr, returncode e status de sucesso.
    """
    log.info(f"Executando: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture_output,
            text=True,
            timeout=timeout,
        )
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }
    except FileNotFoundError:
        log.error(f"Comando não encontrado: {cmd[0]}")
        return {"success": False, "stdout": "", "stderr": "comando não encontrado", "returncode": -1}
    except subprocess.TimeoutExpired:
        log.error(f"Timeout ao executar: {' '.join(cmd)}")
        return {"success": False, "stdout": "", "stderr": "timeout", "returncode": -1}


def ensure_output_dir(target: str, base_dir: str = "output") -> Path:
    """Cria (se necessário) e retorna o diretório de saída para um alvo."""
    outdir = Path(base_dir) / target
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir


def save_json(data, path: Path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def save_lines(lines, path: Path):
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(set(l.strip() for l in lines if l.strip()))))


def read_lines(path: Path) -> list:
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip()]


def parse_jsonl(text: str) -> list:
    """Faz parse de saída no formato JSON Lines (uma linha JSON por resultado)."""
    results = []
    for line in text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return results
