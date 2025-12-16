FROM python:3.11-slim AS base

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    ldap-utils \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copier les modules lib (nouvelle structure)
COPY lib/ /app/lib/

# ============================================================================
# Stage serveur de stockage
# ============================================================================
FROM base AS server

# Désactiver le buffering Python pour voir les logs en temps réel
ENV PYTHONUNBUFFERED=1

COPY storage_server/ /app/storage_server/
RUN mkdir -p /app/storage /app/user_keys

EXPOSE 65432

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python3 -c "import socket; s=socket.socket(); s.connect(('localhost', 65432)); s.close()" || exit 1

CMD ["python3", "storage_server/server.py"]

# ============================================================================
# Stage client web Flask
# ============================================================================
FROM base AS client

# Désactiver le buffering Python pour voir les logs en temps réel
ENV PYTHONUNBUFFERED=1

COPY web_client/ /app/web_client/
RUN mkdir -p /app/user_keys /app/temp_uploads /app/temp_downloads /app/data/security_config

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python3 -c "import socket; s=socket.socket(); s.settimeout(5); s.connect(('localhost', 5000)); s.close()" || exit 1

CMD ["python3", "web_client/app.py"]
