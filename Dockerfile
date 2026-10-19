# doku-agent – schlankes Python-Image, läuft als unprivilegierter Benutzer.

# --- Build: Wheels bauen (keine Build-Werkzeuge im Laufzeit-Image) ---------
FROM python:3.12.14-slim-bookworm AS builder
WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip wheel --no-cache-dir --wheel-dir /wheels .

# --- Laufzeit --------------------------------------------------------------
FROM python:3.12.14-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DOKU_AGENT_CONFIG=/config/config.yaml
RUN groupadd --system --gid 10001 doku \
    && useradd --system --uid 10001 --gid doku --home-dir /data --no-create-home doku \
    && mkdir -p /data /config && chown doku:doku /data
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels doku-agent && rm -rf /wheels
USER doku
WORKDIR /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4).status == 200 else 1)"]
ENTRYPOINT ["doku-agent"]
CMD ["serve"]
