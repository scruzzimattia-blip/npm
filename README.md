# Nginx Proxy Manager Monitor

Security-focused traffic analytics for **Nginx Proxy Manager** (nginx access logs) with real-time attack detection, CrowdSec integration, and an interactive Streamlit dashboard.

## Architecture

```
┌─────────────────────┐     ┌─────────────┐     ┌─────────────┐
│   NPM / nginx       │────▶│   Worker    │────▶│ PostgreSQL  │
│   access.log        │     │  (parser)   │     │     DB      │
└─────────────────────┘     └─────────────┘     └─────────────┘
                                    │                    │
                                    ▼                    ▼
                             ┌─────────────┐     ┌─────────────┐
                             │  CrowdSec   │     │  Streamlit  │
                             │   (ban)     │     │  dashboard  │
                             └─────────────┘     └─────────────┘
```

## Features

- **Real-time log processing** — Parses nginx **combined** access logs (file watcher; default for NPM)
- **Legacy Traefik JSON** — Set `ACCESS_LOG_FORMAT=traefik` if you still use Traefik JSON lines
- **Attack detection** — Pattern matching for common attack vectors (SQLi, LFI, path traversal, etc.)
- **Geo blocking** — Block traffic by country
- **Rate limiting** — Soft-ban IPs with high error rates (Redis-backed)
- **CrowdSec** — Auto-ban via LAPI
- **Threat scoring** — Risk score per IP
- **Login attempt tracking** — Brute-force hints on `/wp-login`, `/admin`, etc.
- **Dashboard** — Overview, security, traffic, investigator, live, system

## Requirements

- Docker & Docker Compose
- PostgreSQL 15+
- Redis (optional, for rate limiting)
- CrowdSec LAPI (optional)
- Nginx Proxy Manager access log mounted into the worker (e.g. `data/logs/fallback_access.log` or a `proxy-host-*_access.log`)

## Setup

```bash
cp .env.example .env
# Edit .env with your secrets

docker compose up -d
```

Point `docker-compose.yml` volume paths at your NPM `data` directory and the log file you want to analyze (see comments in the compose file).

### Environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection | `postgresql://user:password@db:5432/traefik_stats` |
| `ACCESS_LOG_FORMAT` | `nginx` (combined) or `traefik` (JSON lines) | `nginx` |
| `LOG_FILE` | Path inside worker container | `/app/logs/access.log` |
| `CROWDSEC_LAPI_URL` | CrowdSec API URL | `http://crowdsec:8080` |
| `CROWDSEC_LAPI_KEY` | CrowdSec API key | - |
| `CROWDSEC_MACHINE_PASSWORD` | CrowdSec machine password | - |
| `CROWDSEC_CLIENT_ID` | Origin / User-Agent id for LAPI decisions | `npm-proxy-monitor` |
| `ABUSEIPDB_API_KEY` | AbuseIPDB for IP reputation | - |
| `REDIS_URL` | Redis for rate limiting | - |
| `RETENTION_DAYS` | Log retention | `30` |
| `IGNORED_IPS` | IPs to skip (comma-separated) | - |
| `ATTACK_PATTERNS` | Custom patterns (comma-separated) | - |
| `LOG_FORMAT` | `json` for worker structured logs | - |
| `DISCORD_WEBHOOK` | Discord notification URL | - |

## Dashboard tabs

1. **Dashboard** — Overview, metrics, timeline
2. **Security** — Attacks, geography, CrowdSec
3. **Traffic** — Flows, endpoints, bandwidth
4. **Investigator** — IP lookup, CrowdSec, AbuseIPDB
5. **Live** — Latest requests
6. **System** — DB stats, threat leaders, geo blocking

## Testing

```bash
pytest tests/ -v
```

## Project layout

```
├── app.py              # Streamlit dashboard
├── worker.py           # Log parser & attack detector
├── models.py           # SQLAlchemy models
├── crowdsec.py         # CrowdSec LAPI client
├── data_service.py     # Dashboard data
├── docker-compose.yml  # Full stack
├── Dockerfile          # Streamlit app
├── Dockerfile.worker   # Worker
└── tests/              # Tests
```

## CI/CD

GitHub Actions (`.github/workflows/ci.yml`): tests on push/PR; Docker images `ghcr.io/<repo>-app` and `ghcr.io/<repo>-worker` on `main`.

## Notes

- **Host header**: nginx combined logs do not include `$host`; `request_host` may be empty unless you use a custom log format in NPM.
- **CrowdSec**: Use the `crowdsecurity/nginx` collection and mount the same log file as in the compose example (`/var/log/nginx/access.log` inside the CrowdSec container). Adjust `./crowdsec_config` acquisitions if needed.
- **GeoIP**: City/ASN MMDB paths as in compose.
- **Database name**: Still `traefik_stats` by default for compatibility with existing volumes; rename in compose if you prefer.

## License

MIT
