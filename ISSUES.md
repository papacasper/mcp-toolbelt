# Known Issues — papacasper.com mail deliverability

Found via `email_deliverability_check` (src/tools/dns.ts) run against `papacasper.com` on 2026-08-26.

## 1. Missing reverse DNS (PTR) on the mail server IP

**Symptom:** `email_deliverability_check` reports:
> MX host mail.papacasper.com (15.204.209.89) has no reverse DNS (PTR) record — many receiving servers penalize this

**Why it matters:** Many receiving mail servers do a forward-confirmed reverse DNS check (FCrDNS) — they look up the PTR record for the connecting IP and expect it to resolve back to a hostname that matches (or is consistent with) the sending domain. No PTR record is one of the most common reasons legitimate mail lands in spam or gets rejected outright.

**Fix:** PTR records are controlled by whoever owns the IP block — that's OVH here (`15.204.209.89`, AS16276 OVH SAS), not Cloudflare or papacasper.com's own DNS zone. Cloudflare/your own nameservers can never fix this since they only control forward lookups (domain → IP).

Set via the OVH API (`POST /ip/{ip}/reverse` to create, `PUT` to update an existing one) using an API token scoped to `GET /ip/*` and `POST /ip/*/reverse`, generated at https://api.us.ovhcloud.com/createToken/ (note: US account uses the `.us.ovhcloud.com` endpoints, not `api.ovh.com`).

**Status: RESOLVED 2026-08-26.** Set `15.204.209.89` → `mail.papacasper.com.` via the OVH API. Verified live:
```
$ dig +short -x 15.204.209.89
mail.papacasper.com.
```
The scoped API token (`papacasper-ptr-fix2`, 1-day validity, GET /ip/* + POST /ip/*/reverse only) was left to expire naturally rather than manually revoked — the new OVH Manager nav doesn't have an easily discoverable API-token deletion page (checked My Account > Advanced settings, no direct link found).

## 2. DMARC policy is `p=none`

**Symptom:**
```
v=DMARC1; p=none; rua=mailto:postmaster@papacasper.com; fo=1
```
`email_deliverability_check` flags: "DMARC policy is 'none' — monitoring only, no enforcement against spoofing"

**Why it matters:** `p=none` means DMARC is in report-only mode — spoofed mail claiming to be from `papacasper.com` won't be rejected or quarantined by receiving servers that honor DMARC, it'll just get reported back to `postmaster@papacasper.com` (if the receiver even sends reports). No actual anti-spoofing enforcement.

**Fix:** Tighten the DMARC record in DNS (done via Cloudflare API, zone `papacasper.com`):
```
v=DMARC1; p=quarantine; rua=mailto:postmaster@papacasper.com; fo=1
```
Watch DMARC aggregate reports for a while before moving to `p=reject`, which is the strongest setting but risks rejecting legitimate mail if anything is still misconfigured.

**Status: RESOLVED 2026-08-26.** Updated the `_dmarc.papacasper.com` TXT record (Cloudflare record ID `a336b6c6fecece0f6281cde65b835acf`) from `p=none` to `p=quarantine`. Verified live via `dig +short TXT _dmarc.papacasper.com @1.1.1.1`. Next step (not yet done): monitor DMARC aggregate reports at `postmaster@papacasper.com`, then consider moving to `p=reject` once confident nothing legitimate is failing.

## Things that are already fine (no action needed)

- **SPF**: present, 2 lookups (well under the RFC 7208 cap of 10) — `v=spf1 mx a ip4:15.204.209.89 ip6:2604:2dc0:101:200::368 -all`
- **DKIM**: found under the `mail` selector, valid RSA key present
- **DNSBL**: clean on SpamCop and Barracuda. Spamhaus Zen returned an inconclusive/rate-limited response (`listed: null`), not an actual listing — re-check later if delivery issues persist.

---

## Update — 2026-08-26

Both issues above are resolved, verified independently via 8.8.8.8 and 1.1.1.1:
- PTR: `15.204.209.89` -> `mail.papacasper.com.`
- DMARC: `v=DMARC1; p=quarantine; rua=mailto:postmaster@papacasper.com; fo=1`
