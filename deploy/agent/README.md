# Deploying the CertManager Datacenter Agent (Scanner)

The agent is a small Python process you place on a machine inside each
network you want to discover certificates in (datacenter, office LAN,
remote site). It registers with the central platform, polls for jobs,
runs scanners (TLS network sweep and/or AD CS enumeration), and submits
discovered certificates back to the central inventory.

One codebase, three deployment modes: **Windows service**, **Linux
systemd**, or **Docker container**.

## How the agent works

```
┌─────────────────────┐        HTTPS (outbound only)       ┌──────────────┐
│  Central CertManager │◄──────────────────────────────────│ Agent (poll) │
│  API + inventory     │   register/heartbeat/jobs/results │              │
└─────────────────────┘                                    └──────┬───────┘
       ▲                                                         │
       │ admin approves agent, configures scan targets           ▼
       └──────────────────────────────────────────────  TLS handshakes / PowerShell
                                                          against the local network
```

- **Mode A (polling)** is the default: the agent only makes outbound HTTPS
  connections to the central API — no inbound ports, no VPN needed.
- **Agent types**: `tls_scanner` (CIDR + port TLS sweeps), `adcs` (PowerShell
  enumeration of a Microsoft CA), `generic` (both).
- **Air-gap mode**: for fully isolated networks, jobs can be delivered and
  results exported as HMAC-signed JSON files (see below).

## 1. Central-side preparation

Each agent needs three things before it can work:

1. **A datacenter entry** with a short code (used during registration):
   ```bash
   curl -X POST https://api.example.com/api/v1/datacenters \
     -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -d '{"name":"Berlin DC","code":"ber"}'
   ```
2. **A pre-shared key** (`CERTMGMT_AGENT__PSK` in the central server's
   environment — it is the registration secret for every agent; one value
   for the whole deployment).
3. **Admin approval**: every new agent registers as `unapproved`. An
   administrator must approve it before it can fetch jobs or submit
   results (UI: Admin → Agents, or `PATCH /api/v1/agents/{id}/approve`).
   The agent's API token lives 30 days and it re-registers automatically —
   no token rotation ceremony needed.

> Keep the PSK protected. It is written to the agent's config file at
> install time; the installers below set restrictive file permissions.

## 2. Install: Windows

The agent runs on any Windows 10/11 or Server host. Requirements:
Python 3.12+ and (for the service mode) [NSSM](https://nssm.cc/).

```powershell
# One-time: create the config (run this wherever the agent will live)
certmanager agent init `
  --url https://api.example.com `
  --psk <psk> `
  --agent-type tls_scanner `
  --datacenter-code ber `
  --name ber-agent-01 `
  --config-path C:\ProgramData\CertManager\agent_config.json

# Edit the config: TLS ranges/ports, listener off for TLS-only agents
notepad C:\ProgramData\CertManager\agent_config.json

# Install as a service (NSSM required; the script hardens the config ACLs)
deploy\agent\install.ps1 -ConfigPath C:\ProgramData\CertManager\agent_config.json

# Or run in the foreground for testing:
certmanager agent run --config C:\ProgramData\CertManager\agent_config.json
```

For a TLS-only agent, set in the config:

```json
"tls_cidr_ranges": ["10.0.0.0/24"],
"tls_ports": [443, 8443],
"listener_enabled": false
```

## 3. Install: Linux (systemd)

One command does the whole thing — it creates the `certmgr` service user,
writes the systemd unit, hardens the config permissions, and enables +
starts the service. Run it as root:

```bash
sudo python3 -m venv /opt/certmanager-agent/.venv
sudo /opt/certmanager-agent/.venv/bin/pip install certmanager
sudo /opt/certmanager-agent/.venv/bin/certmanager agent init \
    --url https://api.example.com --psk <psk> --config-path /opt/certmanager-agent/agent_config.json
sudo /opt/certmanager-agent/.venv/bin/certmanager agent install-service \
    --config-path /opt/certmanager-agent/agent_config.json
```

That's it — `systemctl status certmanager-agent` shows the service, logs via
`journalctl -u certmanager-agent -f`. Re-running `install-service` after
config changes is safe (it restarts the unit).

Manual alternative: the unit template also ships as
[`certmanager-agent.service`](certmanager-agent.service) with a full
walkthrough in its comments; copy it to `/etc/systemd/system/`, adjust the
venv path, then `systemctl daemon-reload && systemctl enable --now
certmanager-agent`.

## 4. Install: Docker

Build the image (or pull from your registry) and mount config + data dir:

```bash
docker build -f docker/Dockerfile.agent -t certmanager-agent .
docker run -d --name certmanager-agent \
  -v /etc/certmanager/agent_config.json:/app/agent_config.json \
  -v /var/lib/certmanager-agent:/app/agent_data \
  certmanager-agent
```

- From a container on the same Docker host as the platform, reach the API
  at `http://host.docker.internal:8000` (Docker Desktop) or via the compose
  network name.
- The container needs network reachability to the targets it scans.

## 5. Configuration reference (`agent_config.json`)

| Key | Meaning |
|---|---|
| `api_url` | Central API base URL, e.g. `https://api.example.com` |
| `psk` | Deployment pre-shared key (see §1) |
| `agent_name` | Unique per agent — also the identity shown in the UI |
| `agent_type` | `tls_scanner` \| `adcs` \| `generic` |
| `datacenter_code` | Code of the datacenter created in §1 |
| `poll_interval` | Seconds between job polls (default 30) |
| `tls_cidr_ranges` / `tls_ports` | Default TLS sweep targets (CIDR list / port list) |
| `tls_timeout` / `tls_max_hosts_per_cidr` | Handshake timeout (s); per-CIDR host cap (default 256 — raises a log warning when truncating) |
| `listener_enabled` / `listener_port` | Connector listener for AD CS agents (see §7) |
| `adcs_ca_server` / `adcs_ca_name` | AD CS targets (Windows CA) |

## 6. Scan targets and triggering

Scan targets can be set centrally (no config-file edits needed after
deployment) and override the agent defaults:

```bash
# Set recurring targets
curl -X PATCH https://api.example.com/api/v1/agents/<agent_id>/scan-targets \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"cidr_ranges":["10.0.0.0/24"],"ports":[443,8443],"scan_schedule":"weekly"}'

# Trigger a scan now — the agent executes it on its next poll
curl -X POST https://api.example.com/api/v1/agents/<agent_id>/scan-targets/scan \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"cidr_ranges":["10.0.0.0/24"],"ports":[443,8443]}'
```

A weekly Celery beat task also creates scheduled TLS jobs for every agent
whose `scan_schedule` is `daily` or `weekly`.

The scanner is deliberately permissive: it accepts TLS 1.0+ and legacy
ciphers (embedded printers/IoT often negotiate nothing newer), never
verifies certificates (metadata harvesting), and caps concurrency and
CIDR sizes. It only performs TLS handshakes on the configured ports —
no port sweeping beyond the list, no exploitation.

## 7. AD CS agents and the connector listener

For `adcs` / `generic` agents, the agent also serves a local HTTP(S)
listener (`listener_port`, default 8443) so the central **AD CS
connector** can reach back into the datacenter. This is the only inbound
socket; it authenticates callers with the agent's permanent token, which
is printed **once** at first registration and stored in the agent's local
data dir.

- Keep `listener_enabled: false` for pure TLS-scanning agents.
- Mutual TLS: set `listener_ssl_cert`, `listener_ssl_key`, and
  `listener_ssl_ca` (client CA) in the config to require client
  certificates on top of the bearer token.
- The CA config on the central side needs `agent_base_url`, `ca_server`,
  `ca_name`, and the agent token in the credential config.

## 8. Air-gap mode (no network path to central)

```bash
# On the isolated host: run a job from a file, export signed results
certmanager agent run-job job.json --output results.json

# On a machine with central access: verify + import
certmanager import-data results.json --token $TOKEN
```

Job files and exports are HMAC-signed with the deployment PSK; imports
are rejected unless the signature verifies.

## 9. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Logs: `Auth rejected (403) on /agents/...` | Agent is not approved yet — approve it in Admin → Agents |
| `agent_auth_failure_reregistering` in logs | Normal: the 30-day token expired or the agent was re-registered; it re-registers with the PSK automatically |
| Scan completes with `checked: 0, errors: 0` | Nothing answered TLS on those ports — probe manually (`echo > /dev/tcp/host/port`); plain-HTTP services won't appear |
| Scan reports `errors` on a host that curl can reach | The endpoint's TLS stack rejects modern handshakes; the scanner already falls back to legacy TLS — check the agent version |
| Listener start failure (`Port in use`) | Another process owns `listener_port` — change it, or set `listener_enabled: false` for TLS-only agents |
| Container can't reach the API | Use `http://host.docker.internal:8000` on Docker Desktop; on Linux use `--network host` or the compose network |
| `Registration failed` | Wrong PSK or datacenter code, or the API is unreachable from the agent host |

## 10. Security notes

- Only the PSK (config file) and the permanent agent token (data dir)
  sit on disk; JWTs never do. The Windows installer ACLs the config file;
  the systemd unit instructions use `chmod 600`.
- Agent → central traffic is plain HTTPS; the scanner accepts any
  certificate the target presents (by design — discovery, not trust).
- Scanning generates TLS handshakes from the agent's IP toward every
  host in the configured CIDR — coordinate with network owners first.
