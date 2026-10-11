# Let's Encrypt / ACME

CertManager can issue, renew, and revoke real certificates from Let's
Encrypt (or any ACME-compatible CA) using the DNS-01 challenge via
Cloudflare. Unlike AWS ACM and Azure Key Vault, there is no managed
backend holding the private key for you — this connector generates a key,
gets it signed, and hands it back to **you** to deploy.

## How it's different from the other connectors

| | AWS ACM / Azure Key Vault | ACME / Let's Encrypt |
|---|---|---|
| Private key | Held by the cloud provider | Generated here, encrypted at rest, **you download and deploy it** |
| Discovery | Lists everything in the account/vault | No "list everything" API — the CA entry must declare the `domains` it manages; discovery surfaces existing Let's Encrypt certs for those domains via crt.sh |
| Revocation | AWS ACM: not possible (no API). Azure: disables the cert. | **Real** revocation, signed by the account key |
| Renewal | Automatic (AWS) / new version (Azure) | A fresh issuance for the same name set — no in-place renewal in the ACME protocol |

## Setup

### 1. Cloudflare API token

Create a token at **Cloudflare dashboard → My Profile → API Tokens** with
**Zone → DNS → Edit** permission scoped to the zone(s) covering the
domains you'll issue for. The platform only ever creates/deletes a single
`_acme-challenge.<domain>` TXT record per issuance — it never touches any
other DNS record.

### 2. Add the authority

In the UI: **Authorities → Add Authority → Let's Encrypt / ACME**.

- **Contact Email** — required by the ACME protocol for expiry notices.
- **Domains** — every domain this CA entry will issue for. There's no way
  to ask Let's Encrypt "what have I issued" — this list is also what
  scheduled discovery scans crt.sh for.
- **Directory** — defaults to **staging**. Test your setup there first:
  Let's Encrypt's production rate limits (50 certs/registered domain/week,
  5 duplicate certs/week, 5 failed validations/account/hostname/hour) are
  real and shared across your whole account. Staging certs aren't
  publicly trusted but exercise the exact same code path.
- **Cloudflare API Token** / **Zone ID** — the zone ID is optional and
  resolved automatically from the domain if left blank.

### 3. Issue a certificate

**Authorities** page → the authority's row → **Issue** → enter the common
name and any additional SANs. This dispatches an async job (DNS-01
validation + CA processing commonly takes 30–180 seconds) — watch it via
the job status panel, or poll `GET /api/v1/scans/{id}` directly.

When it completes, a **Download Key** button appears. The response is a
JSON object with `private_key_pem`, `certificate_pem`, `chain_pem`, and
`fullchain_pem` — pick whichever your target server wants (nginx wants
cert + key as separate files; HAProxy wants them combined — `fullchain_pem`
+ `private_key_pem` concatenated covers that case).

**The key bundle expires 48 hours after issuance** and is then
permanently deleted, downloaded or not. Save it somewhere durable as soon
as you download it.

### 4. Renewal

**Authorities** page → **Renew** → paste in the certificate's inventory
ID (from the Certificates page). This re-issues for the exact domain set
the certificate already covers — not whatever the authority's `domains`
list currently says, which can drift over time.

A scheduled job also auto-renews every ACME-issued certificate within 30
days of expiry, without anyone clicking anything — the same encrypted,
time-boxed download flow applies, so check back on the Certificates page
periodically (or wire up an alert rule on expiry) if you rely on this.

## Troubleshooting

- **"No Cloudflare zone found"** — the domain (or its registrable parent,
  e.g. `example.com` for `www.example.com`) isn't in the Cloudflare
  account the API token belongs to.
- **DNS validation timeout** — almost always one of:
  1. The TXT record didn't propagate in time (rare with Cloudflare, but
     possible under load) — just retry.
  2. A **CAA record** on the domain restricts which CAs may issue for it
     and doesn't list `letsencrypt.org`. Check with `dig CAA yourdomain.com`.
  3. The Cloudflare API token's permission doesn't actually cover DNS
     edit on that zone.
- **Rate limited** — you're on the production directory and hit one of
  Let's Encrypt's weekly/hourly limits. Switch to staging to keep testing,
  and wait out the window before retrying production.
- **Key bundle download returns 410** — it's past its 48-hour expiry and
  has been purged. Trigger a fresh issuance or renewal.
- **Key bundle download returns 403** — only admins (or a role explicitly
  granted the `certificates:download_key` permission) can retrieve
  private key material, regardless of broader `authorities:read` access.
