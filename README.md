# Startup Security Shield (S³)

A PII detection and redaction middleware. It scans text and documents, redacts
the sensitive parts, scores the privacy risk, and can optionally produce a
privacy advisory using an LLM that only ever sees anonymized data.

Status: working prototype / capstone project. It is built to be run, read, and
extended. It is not a hardened production service. See
[LEARNINGS.md](LEARNINGS.md) for the honest list of what works, what does not,
and what I would do next.

## What it does

- Detects 20+ categories of PII (SSN, payment card, bank account, medical,
  credentials, identity documents, contact info, and more) using Microsoft
  Presidio and spaCy, plus custom regex recognizers.
- Redacts detected values and returns the cleaned text.
- Scores overall privacy risk on a 0-100 scale and recommends an action
  (allow, caution, warn, review, block).
- Maps findings to GDPR, HIPAA, PCI DSS, CCPA, and SOC 2.
- Lets an admin define custom entity types at runtime through the UI or API.
- Optionally calls an LLM for a written advisory. The model receives only an
  anonymized summary, never raw sensitive data.

## How it works

```
            ┌────────────┐   detect    ┌─────────────────────┐
 text/file ─►  Presidio   ├────────────►  risk scoring        │
            │  + spaCy    │             │  (s3_core, pure)     │
            │  + regex    │             └─────────┬───────────┘
            └─────┬───────┘                       │ score + decision
                  │ redact                        ▼
                  ▼                       ┌─────────────────────┐
            redacted text                 │  optional LLM        │
                                          │  advisory (anonymized│
                                          │  input only)         │
                                          └─────────────────────┘
```

The scoring and decision logic lives in `s3_core.py`, which has no framework or
ML dependencies and is unit tested. `main.py` is the FastAPI app that wires
detection, auth, persistence, and the UI around that core.

## Quickstart (local)

Requires Python 3.10+.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m spacy download en_core_web_sm

cp .env.example .env          # then edit .env
export JWT_SECRET_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
export ALLOW_DEMO_USERS=1     # enables demo logins for local use

uvicorn main:app --reload
```

Open http://localhost:8000 for the UI, or http://localhost:8000/docs for the
interactive API docs.

## Run with Docker

```bash
docker build -t s3 .
docker run -e JWT_SECRET_KEY=change-me -e ALLOW_DEMO_USERS=1 -p 8000:8000 s3
```

## Configuration

All configuration is via environment variables. See `.env.example` for the full
list. The ones that matter most:

| Variable | Default | Purpose |
| --- | --- | --- |
| `JWT_SECRET_KEY` | ephemeral | Signs JWTs. Set it, or tokens reset on restart. |
| `CORS_ORIGINS` | localhost | Comma-separated allowed browser origins. |
| `ALLOW_DEMO_USERS` | `0` | Enables demo accounts for local use only. |
| `MAX_FAILED_LOGINS` | `5` | Failed attempts before a temporary lockout. |
| `LOGIN_LOCKOUT_MINUTES` | `15` | Lockout duration. |
| `LLM_ENABLED` | `0` | Turns the optional advisory on. |
| `LLM_BASE_URL` | empty | OpenAI-compatible endpoint for the advisory. |

## API overview

| Method | Path | Notes |
| --- | --- | --- |
| POST | `/auth/login` | Returns a JWT. Rate limited, with lockout. |
| POST | `/redact_json` | Redact and score a block of text. |
| POST | `/redact_file` | Redact and score an uploaded .txt/.csv/.pdf. |
| GET | `/custom_entities` | List custom entity types. |
| POST | `/custom_entities` | Create one (admin only). |
| GET | `/stats`, `/scan_history` | Usage analytics. |
| GET | `/audit_log` | Audit trail. |
| GET | `/health` | Liveness and feature flags. |

## Security features

- Bcrypt password hashing (required, no weak fallback).
- JWT auth with role-based access control via a reusable dependency.
- Per-endpoint rate limiting and login brute-force lockout.
- Security headers (HSTS, X-Frame-Options, nosniff, CSP, referrer policy).
- Explicit CORS allowlist (no wildcard-with-credentials).
- Custom regex patterns are checked for the obvious ReDoS shape before use.
- The LLM advisory receives only anonymized text.
- Audit logging of auth events and redaction actions (no raw PII is logged).

## Testing

```bash
pytest -q
```

The suite covers the scoring algorithm, risk banding, decision thresholds, and
the regex safety guard. These run without Presidio or a database.

## Known limitations

Detection accuracy is not yet benchmarked, storage is single-process SQLite,
and some state is in memory. The full list and the reasoning behind the design
are in [LEARNINGS.md](LEARNINGS.md). Read that before trusting the tool with
anything real.

## License

Add a LICENSE file before publishing (MIT or Apache 2.0 are common choices).
