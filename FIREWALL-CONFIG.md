# CrowdSec Firewall Bouncer Configuration

## Overview

The CrowdSec firewall bouncer (`crowdsec-firewall-bouncer`) can block traffic at multiple levels:

- **Host traffic** (INPUT chain)
- **Docker container traffic** (DOCKER-USER chain)
- **Forwarded traffic** (FORWARD chain)

## Current setup

1. **CrowdSec LAPI**: Running in Docker (e.g. service `crowdsec`), often exposed on host port `8082`
2. **Firewall bouncer**: On the host, connects to LAPI on `localhost:8082`
3. **iptables chains**: INPUT, FORWARD, DOCKER-USER
4. **ipset**: e.g. `crowdsec-blacklists-0` for fast IP matching

### Configuration file

Location: `/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml`

Key settings:

```yaml
mode: iptables
api_url: http://localhost:8082/
api_key: <your-bouncer-api-key>
deny_action: DROP
iptables_chains:
  - INPUT
  - FORWARD
  - DOCKER-USER
```

## Verification commands

### Firewall bouncer status

```bash
sudo systemctl status crowdsec-firewall-bouncer
```

### iptables

```bash
sudo iptables -L CROWDSEC_CHAIN -n -v
sudo iptables -L INPUT -n -v | grep CROWDSEC
sudo iptables -L DOCKER-USER -n -v | grep CROWDSEC
sudo iptables -L FORWARD -n -v | grep CROWDSEC
```

### ipset

```bash
sudo ipset list crowdsec-blacklists-0
```

### CrowdSec decisions

```bash
docker exec npm-stats-crowdsec cscli decisions list
```

(Use your CrowdSec container name if different.)

## Testing blocking

### Manual block via dashboard

1. Open the monitor UI (e.g. `http://localhost:8501`
2. **CrowdSec** tab → manual decision
3. Ban IP, duration, reason

### Verify block

1. `docker exec npm-stats-crowdsec cscli decisions list`
2. `sudo ipset list crowdsec-blacklists-0 | grep <IP>`
3. `sudo iptables -L CROWDSEC_CHAIN -n -v`

## Troubleshooting

### Firewall bouncer not starting

```bash
sudo tail -f /var/log/crowdsec-firewall-bouncer.log
```

### IP not blocked

1. Decision exists in CrowdSec
2. Bouncer is running and connected to LAPI
3. iptables rules present
4. ipset contains the IP

### Docker traffic not blocked

Ensure `DOCKER-USER` is listed under `iptables_chains` in the bouncer config.

## Notes

- Bouncer sync interval is often configurable (e.g. every 10 seconds)
- Decisions expire according to CrowdSec rules
- This stack reads **Nginx Proxy Manager** access logs for detection; blocking is still done by CrowdSec / firewall bouncer as you configure on the host
