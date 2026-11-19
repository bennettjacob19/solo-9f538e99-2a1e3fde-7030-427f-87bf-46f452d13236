FROM python:3.11-slim

WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

ENV PYTHONUNBUFFERED=1 \
    DB_PATH=/data/app.db \
    ROUND_DB_DIR=/data/rounds

# The console starts each regression round's authoritative endpoint and
# resolver itself (child processes with per-round ports and databases).
CMD ["python", "-m", "app.web"]
