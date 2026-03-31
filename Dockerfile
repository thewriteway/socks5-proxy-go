# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM golang:1.21-alpine AS builder

WORKDIR /src

# Copy module files first so layer is cached when only source changes.
COPY go.mod ./
RUN go mod download

COPY . .

# Build a statically linked binary (no CGO, no libc dependency).
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /out/gosocks5 ./cmd/proxy

# ── Stage 2: minimal runtime image ────────────────────────────────────────────
FROM scratch

# Copy TLS root certificates so the proxy can validate upstream TLS (optional).
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

COPY --from=builder /out/gosocks5 /gosocks5

# SOCKS5 default port
EXPOSE 1080

# Environment variable defaults (override at runtime).
ENV PROXY_ADDR=0.0.0.0:1080

ENTRYPOINT ["/gosocks5"]
