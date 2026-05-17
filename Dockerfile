FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir -r requirements.txt


FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        nmap \
        ufw \
    && (apt-get install -y --no-install-recommends suricata || true) \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /usr/sbin/nologin cybervolt \
    && mkdir -p /app/logs /app/data \
    && chown -R cybervolt:cybervolt /app

COPY --from=builder /opt/venv /opt/venv
COPY --chown=cybervolt:cybervolt . /app

USER cybervolt

HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD python3 health.py >/dev/null && curl -fsS "https://api.telegram.org/bot${TELEGRAM_TOKEN}/getMe" >/dev/null || exit 1

CMD ["python3", "intel_bot.py"]
