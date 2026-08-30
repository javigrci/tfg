# Anclar a Debian 12 (Bookworm) para estabilidad de nombres de paquetes
FROM python:3.12-slim-bookworm

# ── Dependencias de sistema ────────────────────────────────────────────────
# WeasyPrint (renderizado PDF), nmap, Perl + módulos para nikto
RUN apt-get update && apt-get install -y --no-install-recommends \
    # WeasyPrint
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libharfbuzz0b \
    libfontconfig1 \
    # Herramientas de escaneo
    nmap \
    # Perl + módulos requeridos por nikto
    perl \
    libwww-perl \
    libnet-ssleay-perl \
    libcrypt-ssleay-perl \
    # Necesario para clonar nikto y descargar el release de nuclei
    git \
    ca-certificates \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# ── Nikto ─────────────────────────────────────────────────────────────────
# No está en los repos de Debian — se instala desde el repo oficial
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && chmod +x /opt/nikto/program/nikto.pl \
    && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# ── Nuclei ────────────────────────────────────────────────────────────────
# Binario Go, no está en los repos de Debian — se descarga el último release
# oficial de GitHub (misma filosofía que el `git clone --depth 1` de nikto:
# siempre la última versión, sin pin manual que haya que actualizar a mano).
RUN NUCLEI_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
        | grep -oP '"tag_name":\s*"v\K[^"]+') \
    && curl -sL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -o /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip -d /usr/local/bin \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip

# ── Wapiti en venv aislado ────────────────────────────────────────────────
# wapiti3==3.1.8 requiere httpx==0.24.1, incompatible con el resto de la app.
# Se instala en su propio venv y se expone el binario en PATH.
RUN python -m venv /opt/wapiti-venv \
    && /opt/wapiti-venv/bin/pip install --no-cache-dir wapiti3 \
    && ln -sf /opt/wapiti-venv/bin/wapiti /usr/local/bin/wapiti

# ── Aplicación Python ──────────────────────────────────────────────────────
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
