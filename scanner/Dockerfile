FROM python:3.12-slim-bookworm

# Instalar herramientas de seguridad disponibles en repos + git para nikto
RUN apt-get update -yqq && \
    apt-get install -y --no-install-recommends \
    nmap \
    libpcap-dev \
    dnsutils \
    curl \
    git \
    perl \
    libnet-ssleay-perl \
    && git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl \
    && apt-get purge -y git \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY scanner/requirements.txt ./scanner/requirements.txt
RUN pip install --no-cache-dir -r scanner/requirements.txt

COPY app/ ./app/
COPY scanner/ ./scanner/

CMD ["python", "scanner/vuln_scanner.py"]
