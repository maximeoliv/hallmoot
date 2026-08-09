FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MOOT_DB_PATH=/data/hallmoot.sqlite3

WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin instance \
 && mkdir -p /data && chown instance:instance /data
USER 10001

EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8787/healthz',timeout=3)"

# 0.0.0.0 *inside the container namespace* is not public exposure: what decides
# reachability is the host-side publish in compose, pinned to one address.
CMD ["uvicorn", "app.asgi:app", "--host", "0.0.0.0", "--port", "8787"]
