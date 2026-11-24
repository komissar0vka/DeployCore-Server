# syntax=docker/dockerfile:1
FROM golang:1.27.4-bookworm AS agent
WORKDIR /src
COPY apps/agent/go.mod apps/agent/go.sum ./
RUN go mod download
COPY apps/agent/*.go apps/agent/VERSION apps/agent/setup.ps1 ./
RUN GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -mod=readonly -trimpath -buildvcs=false -o /out/deploycore-agent.exe .

FROM debian:trixie-slim AS authenticode
ADD --checksum=sha256:109c711ac07fc2ce1e3756d6247d92bbf23e55c4aa809a4b34cca3c4f2913fc6 \
    https://github.com/mtrojnar/osslsigncode/releases/download/2.16/osslsigncode-2.16-linux-amd64.tar.gz /tmp/osslsigncode.tar.gz
RUN mkdir /out && tar -xzf /tmp/osslsigncode.tar.gz -C /out --strip-components=1

FROM python:3.12-slim-trixie
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY apps/server/requirements.txt .
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates openssl msitools wixl \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --no-cache-dir -r requirements.txt \
    && useradd --system --uid 10001 deploycore \
    && install -d -m 0700 -o deploycore /var/lib/deploycore/packages /var/lib/deploycore/cloud
COPY --from=authenticode /out/osslsigncode /usr/local/bin/osslsigncode
COPY --from=authenticode /out/COPYING.txt /out/LICENSE.txt /usr/local/share/doc/osslsigncode/
COPY --from=agent /out/deploycore-agent.exe /opt/deploycore/agent/
COPY apps/agent/VERSION apps/agent/configured-agent.wxs apps/agent/upgrade-agent.ps1 /opt/deploycore/agent/
COPY apps/server/deploycore ./deploycore
COPY apps/server/alembic.ini .
COPY apps/server/migrations ./migrations
USER 10001
CMD ["sh", "-c", "python -m deploycore.migrate && exec python -m uvicorn deploycore.main:app --host 0.0.0.0 --port 8000 --no-proxy-headers"]
