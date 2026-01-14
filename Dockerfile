FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Chromium + chromedriver for Selenium
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       chromium \
       chromium-driver \
       ca-certificates \
       fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

# Let selenium find chromium in Debian
ENV CHROME_BIN=/usr/bin/chromium

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app /app/app

EXPOSE 8080

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
