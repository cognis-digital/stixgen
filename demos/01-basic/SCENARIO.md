# Demo 01 — Basic: phishing-campaign IOC bundle

## Scenario

Your SOC triaged a phishing campaign and pulled a handful of indicators out of
the sandbox + mail gateway logs. You own this data and want to share it with a
partner ISAC as a clean, valid **STIX 2.1 bundle** — not a messy CSV.

The feed mixes formats the way real feeds do: a **defanged** URL and domain
(`hxxp`, `[.]`), an IPv4 and an IPv6 C2 address, an MD5 and a SHA-256 sample
hash, a sender email, and a CVE the dropper exploits. There's also one junk line
to prove the classifier rejects garbage instead of emitting invalid STIX.

## Input

[`iocs.txt`](./iocs.txt) — one IOC per line; `#` comments allowed.

## Run it

Human-readable triage table:

```sh
python -m stixgen build demos/01-basic/iocs.txt --format table
```

Shareable HTML report (the "UI" — open in a browser):

```sh
python -m stixgen build demos/01-basic/iocs.txt \
    --producer "Greenway SOC" --label phishing --label campaign-bluefin \
    --format html -o report.html
```

STIX 2.1 bundle for your TIP/SIEM pipeline:

```sh
python -m stixgen build demos/01-basic/iocs.txt --format json > bundle.json
```

## Expected

- 9 IOCs classified as valid STIX objects (URL, domain, 2 IPs, 2 hashes,
  email, CVE — the CVE becomes a `vulnerability` SDO, the rest `indicator`s).
- 1 unrecognized line dropped.
- Defanged `hxxp[:]//evil[.]example[.]com/...` and `bad[.]example[.]net` are
  refanged before classification.
- Exit code **2** because valid IOCs ("findings") were produced — lets a
  pipeline branch on "did we get anything?".
- The emitted bundle validates as STIX 2.1: every object carries
  `spec_version`, deterministic `id`s, `created`/`modified`, and indicators
  carry a `pattern` + `pattern_type: stix`.
