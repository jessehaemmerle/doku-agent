# doku-agent – schlankes Python-Image, läuft als unprivilegierter Benutzer.

# --- Build: Abhängigkeiten und Paket in eine venv installieren --------------
FROM python:3.12.14-slim-bookworm AS builder
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
WORKDIR /build
# Erst nur die Abhängigkeiten aus pyproject.toml: diese Schicht bleibt im Build-Cache, solange sich nur der
# Code ändert (sonst würden bei jeder Codeänderung alle Pakete neu geladen)
COPY pyproject.toml ./
RUN python -c "import tomllib; print('\n'.join(tomllib.load(open('pyproject.toml', 'rb'))['project']['dependencies']))" \
        > requirements.txt \
    && pip install --no-cache-dir -r requirements.txt
COPY README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir --no-deps . && pip uninstall --yes pip

# --- Laufzeit --------------------------------------------------------------
# Nur die fertige venv übernehmen: keine Wheels, die als eigene Schicht im Image blieben (ein späteres rm
# verkleinert das Image nicht), keine Build-Werkzeuge
FROM python:3.12.14-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:$PATH \
    DOKU_AGENT_CONFIG=/config/config.yaml
RUN groupadd --system --gid 10001 doku \
    && useradd --system --uid 10001 --gid doku --home-dir /data --no-create-home doku \
    && mkdir -p /data /config && chown doku:doku /data
COPY --from=builder /opt/venv /opt/venv
USER doku
WORKDIR /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4).status == 200 else 1)"]
ENTRYPOINT ["doku-agent"]
CMD ["serve"]
