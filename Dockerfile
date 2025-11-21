FROM python:3.11-slim AS base

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    ldap-utils \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY crypto_utils.py .
COPY client_crypto.py .

FROM base AS server

COPY dossier_server/ ./dossier_server/
RUN mkdir -p storage user_keys

EXPOSE 65432

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python3 -c "import socket; s=socket.socket(); s.connect(('localhost', 65432)); s.close()" || exit 1

CMD ["python3", "dossier_server/server.py"]

FROM base AS client

COPY dossier_client/ ./dossier_client/
RUN mkdir -p user_keys temp_uploads temp_downloads

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/healthz').read()" || exit 1

CMD ["python3", "dossier_client/app.py"]
