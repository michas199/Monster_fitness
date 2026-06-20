FROM python:3.12-slim

# Variáveis de ambiente
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependências do sistema
RUN apt-get update && apt-get install -y --no-install-recommends \
    default-libmysqlclient-dev gcc pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Dependências Python
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Código da aplicação
COPY . .

# Usuário não-root por segurança
RUN adduser --disabled-password --gecos '' mfuser && chown -R mfuser:mfuser /app
USER mfuser

EXPOSE 5000

# Gunicorn com 4 workers para produção
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", \
     "--worker-class", "sync", "--timeout", "60", \
     "--access-logfile", "-", "--error-logfile", "-", \
     "app:app"]
