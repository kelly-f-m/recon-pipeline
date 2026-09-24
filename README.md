# Recon Pipeline

Pipeline de reconhecimento ofensivo automatizado em 3 etapas, que encadeia 13 ferramentas
consagradas de OSINT e enumeração em um único fluxo, gerando um relatório Markdown
consolidado ao final.

Construído para acelerar a fase de reconhecimento em testes de intrusão autorizados,
programas de bug bounty e labs de estudo (HackTheBox, TryHackMe).

## ⚠️ Aviso legal e ético

Esta ferramenta deve ser usada **exclusivamente** contra alvos para os quais você possui
**autorização explícita** (contrato de pentest, programa de bug bounty com escopo definido,
domínio próprio, ou máquinas de laboratório como HTB/THM). Escanear infraestrutura de
terceiros sem permissão é ilegal no Brasil (Lei 12.737/2012 e Marco Civil da Internet) e na
maioria dos países. O autor não se responsabiliza pelo uso indevido desta ferramenta.

## Etapas do pipeline

| Etapa | Ferramentas | Objetivo |
|---|---|---|
| **1 — Reconhecimento inicial** | Subfinder, Whois, DNSX, HTTPX, Nmap, Nuclei, Subzy | Mapear subdomínios, validar DNS, identificar hosts vivos, portas abertas, vulnerabilidades conhecidas e subdomain takeovers |
| **2 — Descoberta profunda** | GAU, S3Scanner, Katana, ExifTool | Encontrar URLs históricas, buckets S3 expostos, crawling ativo e metadados de arquivos públicos |
| **3 — OSINT de exposição** | Have I Been Pwned, Intelligence X | Verificar vazamentos de credenciais e histórico de exposição de e-mails/domínio |

Cada etapa depende dos resultados da anterior (ex: HTTPX usa a lista de subdomínios do
Subfinder; Nmap usa os hosts vivos do HTTPX), então rodar `all` na ordem é o fluxo recomendado.

## Instalação

### Opção A — Docker (recomendado)

```bash
git clone https://github.com/kelly-f-m/recon-pipeline.git
cd recon-pipeline
cp .env.example .env   # preencha suas API keys
docker build -t recon-pipeline .
docker run --rm -it -v $(pwd)/output:/app/output --env-file .env recon-pipeline all example.com
```

### Opção B — Instalação manual (Linux/Kali)

```bash
# Ferramentas Go (ProjectDiscovery + outras)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/LukaSikic/subzy@latest

# Ferramentas via apt
sudo apt install nmap whois libimage-exiftool-perl

# S3Scanner (Python)
pip install s3scanner

# Dependências Python do projeto
git clone https://github.com/kelly-f-m/recon-pipeline.git
cd recon-pipeline
pip install -r requirements.txt
cp .env.example .env   # preencha suas API keys
```

Certifique-se de que `$GOPATH/bin` (geralmente `~/go/bin`) está no seu `PATH`.

## API Keys necessárias (Etapa 3)

| Serviço | Onde obter | Camada gratuita? |
|---|---|---|
| Have I Been Pwned | https://haveibeenpwned.com/API/Key | Não (pago, valor baixo) |
| Intelligence X | https://intelx.io/product-free-search-api | Sim (free tier limitado) |

Sem essas chaves, a Etapa 3 é pulada automaticamente (o pipeline não quebra).

## Uso

```bash
# Pipeline completo
python recon.py all example.com

# Só uma etapa específica
python recon.py phase1 example.com
python recon.py phase2 example.com
python recon.py phase3 example.com --emails emails.txt

# Regerar o relatório a partir de dados já coletados
python recon.py report example.com

# Pular a confirmação interativa de autorização (útil em CI/scripts)
python recon.py all example.com --yes
```

Os resultados de cada ferramenta ficam salvos em `output/<domínio>/` (JSON/txt brutos +
`REPORT.md` consolidado).

## Estrutura do projeto

```
recon-pipeline/
├── recon.py                        # CLI principal
├── recon_pipeline/
│   ├── utils.py                    # execução de comandos, logging
│   ├── config.py                   # carrega API keys do .env
│   ├── report.py                   # gera o REPORT.md final
│   └── modules/
│       ├── phase1_recon.py
│       ├── phase2_discovery.py
│       └── phase3_osint.py
├── output/                         # resultados por domínio (git-ignored)
├── Dockerfile
├── requirements.txt
└── .env.example
```

## Roadmap / próximos passos

- [ ] Adicionar suporte a Shodan na Etapa 1 (banners de serviços expostos)
- [ ] Exportar relatório também em HTML com gráficos
- [ ] Agendamento via cron/Docker para monitoramento contínuo de mudanças
- [ ] Notificações via webhook (Discord/Slack) quando novos findings aparecerem

## Autora

Kelly Ferreira Morais — [github.com/kelly-f-m](https://github.com/kelly-f-m)
