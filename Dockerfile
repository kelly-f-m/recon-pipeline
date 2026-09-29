# ---- Estágio 1: compila as ferramentas Go ----
# Usamos uma versão ESTÁVEL do Go (não "tip" — tip é o branch de
# desenvolvimento do compilador, muda todo dia e não é reprodutível).
FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git

ENV GOPATH=/root/go
ENV PATH=$PATH:/root/go/bin

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest && \
    go install -v github.com/LukaSikic/subzy@latest

# ---- Estágio 2: imagem final, enxuta ----
# Alpine em vez de Debian bookworm: base bem menor, muito menos CVEs
# na camada do SO. E como é multi-stage, o compilador Go nem entra
# na imagem final — só os binários já prontos.
FROM alpine:3.20

RUN apk add --no-cache \
    python3 py3-pip \
    nmap whois exiftool \
    ca-certificates

# Copia só os binários compilados no estágio anterior
COPY --from=builder /root/go/bin/* /usr/local/bin/

# S3Scanner (Python)
RUN pip3 install --no-cache-dir --break-system-packages s3scanner

# Atualiza templates do Nuclei
RUN nuclei -update-templates || true

WORKDIR /app
COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

COPY . .

ENTRYPOINT ["python3", "recon.py"]
CMD ["--help"]
