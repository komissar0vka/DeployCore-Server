FROM golang:1.25-bookworm AS agent
WORKDIR /src
COPY apps/agent/go.mod apps/agent/go.sum ./
RUN go mod download
COPY apps/agent/*.go apps/agent/VERSION apps/agent/setup.ps1 ./
RUN GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -mod=readonly -trimpath -buildvcs=false -o /out/deploycore-agent.exe .

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY apps/server/requirements.txt .
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates msitools osslsigncode wixl \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --no-cache-dir -r requirements.txt \
    && useradd --system --uid 10001 deploycore \
    && install -d -m 0700 -o deploycore /var/lib/deploycore/packages
COPY --from=agent /out/deploycore-agent.exe /opt/deploycore/agent/
COPY apps/agent/VERSION apps/agent/configured-agent.wxs /opt/deploycore/agent/
COPY apps/server/deploycore ./deploycore
COPY apps/server/alembic.ini .
COPY apps/server/migrations ./migrations
USER 10001
CMD ["sh", "-c", "python -m deploycore.migrate && exec python -m uvicorn deploycore.main:app --host 0.0.0.0 --port 8000 --no-proxy-headers"]
