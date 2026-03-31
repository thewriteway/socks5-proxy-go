# socks5-proxy-go

A lightweight SOCKS5 proxy server written in Go, Docker-ready.
Inspired by [armon/go-socks5](https://github.com/armon/go-socks5) but simplified to zero dependencies.

## Features

| Feature | Supported |
|---|---|
| CONNECT (TCP tunnel) | ✅ |
| No-auth mode | ✅ |
| Username / password auth (RFC 1929) | ✅ |
| IPv4, IPv6, domain names | ✅ |
| Custom destination allow-list | ✅ |
| Graceful shutdown | ✅ |
| Docker / scratch image | ✅ |
| BIND / UDP ASSOCIATE | ❌ (not needed for most use-cases) |

## Quick Start

### Run locally

```sh
go run ./cmd/proxy
# Proxy now listening on 0.0.0.0:1080
```

Test with curl:

```sh
curl --socks5 127.0.0.1:1080 https://ifconfig.me
```

### Docker (no auth)

```sh
docker compose up -d proxy
curl --socks5 127.0.0.1:1080 https://ifconfig.me
```

### Docker (user/password auth)

```sh
PROXY_USER=alice PROXY_PASS=s3cr3t docker compose --profile auth up -d
curl --socks5-hostname alice:s3cr3t@127.0.0.1:1081 https://ifconfig.me
```

### Build image manually

```sh
docker build -t socks5-proxy-go .
docker run -p 1080:1080 socks5-proxy-go
```

## Configuration

All settings are controlled via environment variables.

| Variable | Default | Description |
|---|---|---|
| `PROXY_ADDR` | `0.0.0.0:1080` | Listen address and port |
| `PROXY_USER` | *(unset)* | Username for auth; if unset, no-auth mode |
| `PROXY_PASS` | *(unset)* | Password for auth |
| `PROXY_ALLOW_HOSTS` | *(unset)* | Comma-separated allow-list of FQDNs/IPs; if unset, all hosts are allowed |

### Allow-list example

Only permit traffic to `example.com` and `api.github.com`:

```sh
PROXY_ALLOW_HOSTS=example.com,api.github.com go run ./cmd/proxy
```

## Using as a library

```go
import "github.com/example/socks5-proxy-go/socks5"

srv := socks5.New(socks5.Config{
    Credentials: socks5.Credentials{"alice": "s3cr3t"},
})
log.Fatal(srv.ListenAndServe("tcp", ":1080"))
```

## Architecture

```
client ──SOCKS5──► [gosocks5] ──TCP──► upstream host
                        │
                   1. negotiate auth method
                   2. read CONNECT request
                   3. resolve FQDN (if any)
                   4. dial upstream
                   5. send success reply
                   6. bidirectional io.Copy relay
```
