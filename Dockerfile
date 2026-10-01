FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GMAIL_OAUTH_DB_PATH=/data/oauth_tokens.db

WORKDIR /app

RUN addgroup --system gcpgoat && adduser --system --ingroup gcpgoat gcpgoat

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .

RUN mkdir /data && chown gcpgoat:gcpgoat /data
USER gcpgoat

EXPOSE 8000
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)"

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--access-logfile", "-", "gcp_goat.web:create_app()"]
