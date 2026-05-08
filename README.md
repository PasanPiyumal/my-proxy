# SOCKS5 Proxy (Node.js)

This repository includes a simple SOCKS5 proxy server built with Node.js standard library (`node:net`) for the Proxy Infrastructure intern take-home assessment.

## Features

- Accepts incoming SOCKS5 client connections.
- Supports username/password authentication (RFC 1929).
- Handles TCP `CONNECT` tunneling to destination hosts.
- Logs each connection with source IP/port and destination host/port.
- Configurable listening port by environment variable.

## Run The Proxy

1. Install dependencies:

```bash
npm install
```

2. Start the SOCKS5 proxy:

```bash
npm run proxy:start
```

Optional environment variables:

- `PROXY_PORT` (default: `1080`)
- `PROXY_USERNAME` (default: `proxyuser`)
- `PROXY_PASSWORD` (default: `proxypass`)

Example:

```bash
PROXY_PORT=1080 PROXY_USERNAME=proxyuser PROXY_PASSWORD=proxypass npm run proxy:start
```

For PowerShell:

```powershell
$env:PROXY_PORT="1080"
$env:PROXY_USERNAME="proxyuser"
$env:PROXY_PASSWORD="proxypass"
npm run proxy:start
```

## Example Test

Use curl through the SOCKS5 proxy to fetch your IP information:

```bash
curl --socks5-hostname proxyuser:proxypass@127.0.0.1:1080 https://ipinfo.io
```

If you are running this from PowerShell, use `curl.exe` instead of `curl`:

```powershell
curl.exe --socks5-hostname "proxyuser:proxypass@127.0.0.1:1080" https://ipinfo.io
```

You should see a JSON response from `ipinfo.io` and a connection log line in the proxy terminal.

## Reflection Note

See `REFLECTION.md`.

