# Cernity Vantage

Analyst workspace over the live SIEM + a native metrics/health dashboard (Overview).

- Metrics, dashboard & configuration setup: [docs/metrics-setup.md](docs/metrics-setup.md)

## Quick start

Cernity Vantage is config-driven — every endpoint, host, and token is supplied via the
environment (server-side only; the browser never receives them).

```bash
cp .env.example .env      # then edit .env with your SIEM / bus / API endpoints + tokens
docker compose up -d      # builds the image and starts Vantage
open http://localhost:8899
```

Or run the published image directly:

```bash
docker run -d --env-file .env -p 8899:8899 -v vantage-data:/data cernity/cernity-vantage:latest
```

See [docs/metrics-setup.md](docs/metrics-setup.md) for the Overview dashboard (Prometheus or
InfluxDB backends) and the metrics adapter contract. `.env` is gitignored — never commit real
hosts or tokens.

## License

Source-available, **not** open source. Cernity Vantage is licensed under
**[PolyForm Perimeter License 1.0.1](LICENSE)** — use, modify, and self-host it for any purpose
**except** offering a product that competes with Cernity. Same license as
[cernityndr](https://github.com/cernity/cernityndr).
