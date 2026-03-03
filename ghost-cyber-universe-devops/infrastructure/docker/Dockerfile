# Dockerfile sécurisé pour Ghost Cyber Universe
# Multi-stage build avec sécurité renforcée

# Stage 1: Build environment
FROM python:3.11-slim as builder

# Utilisateur non-root pour la sécurité
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Variables d'environnement sécurisées
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Mise à jour des packages et installation des dépendances de build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Installation des dépendances Python
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Runtime environment
FROM python:3.11-slim as runtime

# Utilisateur non-root
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Variables d'environnement sécurisées
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/home/appuser/.local/bin:$PATH"

# Mise à jour des packages et installation des dépendances runtime uniquement
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copie des packages depuis le stage builder
COPY --from=builder /root/.local /home/appuser/.local

# Création du répertoire de travail
WORKDIR /app

# Copie du code source
COPY --chown=appuser:appuser . .

# Changement vers l'utilisateur non-root
USER appuser

# Exposition du port (non-root ne peut pas utiliser < 1024)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Point d'entrée sécurisé
ENTRYPOINT ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]

# Labels de sécurité
LABEL maintainer="Ghost Cyber Universe Team" \
      version="1.0.0" \
      description="Secure containerized application" \
      security.scan="enabled" \
      security.non-root="true" \
      security.read-only="false"
