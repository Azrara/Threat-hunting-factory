# Threat Hunting Factory

An end to end platform that automates hypothesis driven threat hunting: pick the hypothesis, upload
the evidence, and get a complete report with observations, original log extracts, cyber risk, cyber
impact and recommendations. Access is scoped per tenant and per user.

![status](https://img.shields.io/badge/tests-463%20passing-86BC25) ![detections](https://img.shields.io/badge/detections-101-000000) ![techniques](https://img.shields.io/badge/ATT%26CK%20techniques-75-000000)

## What it does

1. **Choose a hypothesis.** 26 hypotheses across three families: threat intelligence scenarios tied to
   named actors, standard technique based hunts, and mathematical hunts built on Shannon entropy,
   Fourier analysis, frequency stacking, robust outlier detection and Benford's law.
2. **Collect the right evidence.** Each hypothesis declares the data sources it needs, in what format,
   and how to collect them.
3. **Upload an archive.** Zip, tar, tar.gz or a single log file. The engine extracts it with path and
   size protections.
4. **The engine analyses everything.** Every file is sniffed, matched to a parser, normalised into one
   common schema and pushed through the detection library.
5. **Read and export the report.** Observations carry the description, the original log line, the cyber
   risk, the cyber impact and the recommendation. Export to PDF or JSON.
6. **Track the programme.** The home dashboard aggregates hunts, observations, ATT&CK coverage,
   telemetry analysed and risk over time.

## Quick start

```bash
git clone https://github.com/Azrara/Threat-hunting-factory.git
cd Threat-hunting-factory
./run.sh                     # creates the virtual environment on first run
```

Open http://127.0.0.1:8000 and sign in to the demonstration workspace:

| Field                | Value                |
|----------------------|----------------------|
| Workspace identifier | `demo`               |
| Email                | `analyst@demo.local` |
| Password             | `HuntFactory2026`    |

Generate a realistic evidence archive to try it out:

```bash
.venv/bin/python tools/generate_sample_evidence.py sample-evidence.zip
```

The archive contains Windows Security events, Sysmon XML, Linux auth logs, web access logs, Zeek DNS,
firewall flows, AWS CloudTrail and a Microsoft 365 audit export, with a small number of real attack
behaviours planted inside a large volume of benign activity.

Run the test suite:

```bash
make test          # or: .venv/bin/python -m pytest
```

## The detection engine

The engine is the core of the project. It is dependency free Python, so it runs anywhere.

### Universal log parsing

Files are sniffed and scored against every parser, with a free text fallback that still extracts
timestamps and indicators. Supported formats:

| Family     | Formats |
|------------|---------|
| Structured | JSON, NDJSON, JSON Lines, pretty printed JSON documents, CSV, TSV, semicolon and pipe delimited, key value (logfmt) |
| Windows    | Binary `.evtx`, exported event XML, Sysmon operational, PowerShell script block, Windows JSON exports |
| Unix       | Syslog RFC 3164 and RFC 5424, ISO prefixed syslog, `auth.log`, `secure`, sudo, PAM, useradd |
| Web        | Apache and Nginx common and combined log format, W3C extended (IIS) |
| Network    | Zeek TSV (`conn.log`, `dns.log`, `http.log`), flow exports, Suricata EVE JSON |
| Appliance  | CEF (ArcSight), LEEF (QRadar) |
| Cloud      | AWS CloudTrail (`Records` wrapper or one event per line), Microsoft 365 unified audit, Entra ID sign ins |
| Fallback   | Any free text, with timestamp recovery, key value extraction and indicator extraction |

Every record is normalised into an Elastic Common Schema style document through a field alias table
covering several hundred vendor field names, plus content based classification so that a plain CSV of
flows is still recognised as network telemetry.

### Detection styles

| Style | Count | What it does |
|-------|-------|--------------|
| `pattern` | 73 | Single event matching on normalised fields or raw text |
| `threshold` | 13 | Sliding window counting per group, with distinct value counting for spraying and scanning |
| `sequence` | 2 | Ordered stages that must occur for the same entity inside a window |
| `statistical` | 13 | Whole dataset mathematics |

The engine performs one pass over the events. Rules declare keywords and event codes that build an
inverted index, so only the candidate rules are evaluated per record rather than the whole library.

### The mathematics

| Model | Method |
|-------|--------|
| Beacon detection | Timestamps per source and destination pair are binned at a quarter of the median interval, mean centred and transformed with an iterative radix 2 fast Fourier transform. The dominant peak power is compared against the mean spectrum and combined with the coefficient of variation and the jitter ratio into a beacon score. |
| Domain generation | Shannon entropy, consonant ratio, longest consonant run, digit ratio and length are combined into a randomness score, then grouped by registrable parent domain. |
| Encoded payloads | Shannon entropy of long command line tokens, with hashes and identifiers excluded. |
| Long tail stacking | Frequency counting of process images, process lineage and user agents, reporting the tail with its share of the population. |
| Outlier detection | Modified z scores based on the median absolute deviation, with the mean absolute deviation as the fallback, scored inside peer groups so accounts are never compared against addresses. |
| Transfer analysis | Chi square test of leading digit frequencies against Benford's law, plus a Gini coefficient of egress concentration. |
| Temporal profiling | Hour of day profiling per account and robust burst detection over the binned timeline. |

### Coverage

101 detections mapping to 75 MITRE ATT&CK techniques across credential access, execution, persistence,
privilege escalation, defense evasion, discovery, lateral movement, collection, command and control,
exfiltration and impact, for Windows, Linux, containers, web applications, network telemetry and the
cloud control plane.

## Hypothesis catalogue

| Family | Examples |
|--------|----------|
| Threat intelligence | Ransomware deployment precursors, commercial command and control beaconing, cloud identity intrusion, help desk social engineering, living off the land intrusions, edge service exploitation, business email compromise |
| Technique | Credential access, persistence sweep, lateral movement, privilege escalation, defense evasion, discovery, exfiltration, phishing execution chain, brute force, cloud control plane, container workloads, insider data access |
| Mathematical | Fourier beaconing, Shannon entropy, long tail stacking, robust outlier detection, Benford's law, temporal profiling, full spectrum analysis |

## Architecture

```
app/
  main.py              FastAPI application, static hosting, lifespan
  config.py            Settings, limits, persisted signing key
  models.py            Tenant, User, Hunt, Observation, AuditLog
  security.py          bcrypt hashing and JSON web tokens
  deps.py              Authentication and role dependencies
  hunt_service.py      Background execution and persistence
  routers/             auth, catalog, hunts, reports, stats, admin
  reporting/           Deloitte styled PDF renderer
  engine/
    ingest.py          Archive extraction with zip slip and size protections
    parsers.py         Format detection and every parser
    fieldmap.py        Vendor field to common schema aliases
    timeparse.py       Timestamp recognition
    event.py           The normalised event model
    stats_math.py      Entropy, FFT, z scores, Benford, Gini
    executor.py        Single pass rule execution and aggregation
    runner.py          Extract, parse, detect, score
    catalog.py         Hypotheses and data source definitions
    rules/             The detection library
web/                   Vanilla JavaScript interface, no build step
tests/                 463 tests
tools/                 Sample evidence generator
```

## Multi tenancy and roles

Every hunt, observation and report is scoped to a tenant. Cross tenant reads return 404 rather than
403 so that resource existence is not disclosed. Three roles are available:

| Role | Can run hunts | Can manage members |
|------|---------------|--------------------|
| `admin` | yes | yes |
| `analyst` | yes | no |
| `viewer` | no | no |

## Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `THF_DATA_DIR` | `./data` | Database, uploads and signing key |
| `THF_DATABASE_URL` | `sqlite:///data/thf.db` | Any SQLAlchemy URL, PostgreSQL included |
| `THF_JWT_SECRET` | generated and persisted | Token signing key |
| `THF_JWT_TTL_MINUTES` | `720` | Session lifetime |
| `THF_MAX_ARCHIVE_BYTES` | `536870912` | Upload size limit |
| `THF_MAX_UNCOMPRESSED_BYTES` | `2147483648` | Extraction size limit |
| `THF_MAX_EVENTS` | `750000` | Records analysed per hunt |
| `THF_SEED_DEMO` | `1` | Create the demonstration workspace on start up |

## API

The OpenAPI documentation is served at `/docs`. The main endpoints:

```
POST   /api/auth/register              create a workspace and its administrator
POST   /api/auth/login                 authenticate against a workspace
GET    /api/hypotheses                 the catalogue, filterable by family and search
GET    /api/hypotheses/{id}            detail with the data sources and detections
GET    /api/data-sources               how to collect each data source
GET    /api/rules                      the detection library
POST   /api/hunts                      upload evidence and queue an analysis
GET    /api/hunts/{id}                 status, progress, summary and coverage
GET    /api/hunts/{id}/observations    the observations, filterable
GET    /api/hunts/{id}/report.pdf      the styled PDF report
GET    /api/hunts/{id}/report.json     the machine readable report
GET    /api/stats/overview             workspace statistics for the dashboard
```

## Limitations

Findings are derived only from the evidence supplied. The absence of an observation is not proof that
the activity did not occur: the relevant telemetry may not have been collected, may have rotated
before collection, or may fall outside the period covered by the archive. Every observation should be
validated against the source system before an operational decision is taken.

## Notes on the visual identity

The interface and the reports follow a Deloitte inspired palette (black, white, greys and the green
accent). The product is not affiliated with, endorsed by, or produced by Deloitte, and uses no
Deloitte trademark or logo.
