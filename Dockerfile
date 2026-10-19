# Kavalu Labs Security Engine — container image
#
# Use this when you want the Selenium browser module to work (headless
# Chromium) on the host. On Render: set `runtime: docker` in render.yaml and
# Render will build this file instead of using the native Python runtime.
#
# Python is pinned to 3.12 because the pinned lxml==5.2.1 has no wheels for
# 3.13+ and would compile from source.

FROM python:3.12-slim-bookworm

# Chromium + driver for the DOM/console browser module, plus the shared
# libraries headless Chrome needs on Debian.
RUN apt-get update && apt-get install -y --no-install-recommends \
        chromium \
        chromium-driver \
        fonts-liberation \
        libasound2 \
        libgbm1 \
        libnss3 \
        libxss1 \
        libxshmfence1 \
        libxrandr2 \
        libatk-bridge2.0-0 \
        libatk1.0-0 \
        libcups2 \
        libpango-1.0-0 \
        libcairo2 \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    CHROME_BIN=/usr/bin/chromium \
    CHROMEDRIVER_PATH=/usr/bin/chromedriver \
    PORT=10000

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 10000

# --workers 1: scan state lives in the process (core/scanner.py active_scans).
# --threads 16: each SSE connection (/api/scan/stream) occupies a thread.
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:$PORT --workers 1 --threads 16 --timeout 300 app:app"]
