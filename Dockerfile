# Kavalu Security Engine — container image
#
# Use this when you want the Selenium browser module to work (headless
# Chromium) on the host. On Render: set `runtime: docker` in render.yaml and
# Render will build this file instead of using the native Python runtime.
#
# Python 3.12 is the version the test suite and CI exercise most closely
# (CI also runs 3.10 and 3.11). Move to a newer minor only after adding it to
# the CI matrix in .github/workflows/ci.yml.

FROM python:3.15-slim-bookworm

LABEL org.opencontainers.image.title="Kavalu Security Engine" \
      org.opencontainers.image.description="Web application security assessment engine with an OWASP Top 10:2021 mapped dashboard and API" \
      org.opencontainers.image.source="https://github.com/vinayakanw/vnw_kavalu_security_engine" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.authors="Vinayaka N Walshettar <https://www.nayaka100.in/>"

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

# Marks the container unhealthy if the API stops answering. Uses Python because
# curl is not installed in the slim base image.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/api/history' % os.environ.get('PORT', '10000'), timeout=3)"]

# --workers 1: scan state lives in the process (core/scanner.py active_scans).
# --threads 16: each SSE connection (/api/scan/stream) occupies a thread.
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:$PORT --workers 1 --threads 16 --timeout 300 app:app"]
