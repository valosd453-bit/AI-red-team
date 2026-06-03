FROM python:3.11-slim

RUN useradd -m -u 1000 user

# Browser deps for Playwright (bookworm-compatible subset; --with-deps fills gaps)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    gcc \
    curl \
    ca-certificates \
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libdbus-1-3 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libpango-1.0-0 \
    libcairo2 \
    libasound2 \
    libxshmfence1 \
    fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ENV PLAYWRIGHT_BROWSERS_PATH=/app/ms-playwright

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && mkdir -p /app/ms-playwright \
    && playwright install --with-deps chromium \
    && chown -R user:user /app/ms-playwright

COPY --chown=user:user . .

RUN python -c "from agathon.garak_catalog import probe_count, COLD_START_MIN_PROBES; n=probe_count(); print(f'garak_probes={n}'); assert n >= COLD_START_MIN_PROBES, f'expected {COLD_START_MIN_PROBES}+ got {n}'"

USER user

ENV PORT=7860
EXPOSE 7860

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-7860}"]
