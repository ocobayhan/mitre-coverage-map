FROM python:3.12-slim

WORKDIR /app

RUN groupadd --system soc && useradd --system --gid soc --home-dir /app soc

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Canli veritabani /app/instance altinda tutulur; bu klasor docker-compose.yml
# icinde named volume olarak mount edilir. Uygulama kodu (image) ile veri
# (volume) boylece ayri kalir.
RUN mkdir -p /app/instance /app/backups \
    && chown -R soc:soc /app

ENV SOC_DB_PATH=/app/instance/soc.db \
    SOC_HOST=0.0.0.0 \
    SOC_PORT=8000 \
    PYTHONUNBUFFERED=1

USER soc

EXPOSE 8000

CMD ["python", "serve.py"]
