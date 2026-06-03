# Design notes and learnings

This is the honest companion to the README. It records why the system is built
the way it is, what it does not do, and what I would change next. It exists
because a privacy tool that hides its own weaknesses is not trustworthy.

## Design decisions

### Risk scoring is its own pure module

The scoring and decision logic lives in `s3_core.py` with no FastAPI, Presidio,
or database imports. That makes the most interesting part of the system fast to
test and easy to reason about. The algorithm combines four ideas:

- Diminishing returns, so ten copies of one email do not dominate the score.
- A diversity multiplier, because many different PII types is a worse leak than
  many copies of one.
- A volume factor, so larger documents nudge the score up.
- A sigmoid that maps unbounded raw risk into 0-100 and never hard-pins at 100.

The weights and decay factors are reasonable starting points, not validated
constants. See the accuracy limitation below.

### Anonymize before the LLM, always

The optional advisory builds its prompt from a fully anonymized copy of the
text, replacing every detected span by offset. The point of the product is to
keep sensitive data away from third-party models, so the advisory must not be
the thing that leaks it.

### Bcrypt is required, not best-effort

An earlier version fell back to unsalted SHA-256 if bcrypt was missing. Security
defaults should fail loudly rather than silently downgrade, so the app now
refuses to start without bcrypt.

### Authorization comes from the token

Roles are read from the verified JWT and enforced with a single reusable
dependency. No endpoint trusts a role passed in the request body or query
string.

### SQLite with WAL

WAL mode plus a busy timeout reduces "database is locked" errors under the
concurrency this service sees. It is still a single-node store.

## Known limitations

These are listed roughly in order of how much they matter.

1. **Detection accuracy is not benchmarked.** There is no labeled test set and
   no precision/recall numbers. Several regex recognizers are intentionally
   broad (a 5-digit zip, an 8-to-17-digit account number) and will produce
   false positives. For a tool whose whole job is detection, this is the
   biggest gap. The fix is a labeled corpus and a reported precision/recall per
   entity type, with the broad patterns tuned against it.
2. **State in memory.** The login lockout counters and the usage stats live in
   process memory, so they reset on restart and are not shared across workers.
   A shared store (Redis) is the next step for horizontal scaling.
3. **Single-node SQLite.** Fine for a demo, not for multiple instances. A move
   to Postgres would remove the single-writer constraint.
4. **No token revocation.** JWTs are valid until they expire. Logout is client
   side only. A token version or a short-lived-access-plus-refresh design would
   allow real revocation.
5. **Database connection hygiene.** Each call opens its own SQLite connection
   and closes it on the happy path, but not always in a `finally`. The clean
   fix is a single `db_conn()` context manager used everywhere. This was left
   as a focused follow-up rather than a sweeping untested change.
6. **Custom regex is still a risk surface.** The ReDoS guard catches the obvious
   nested-quantifier shape, but it is a heuristic, not a proof. Running
   untrusted patterns against arbitrary text deserves a real timeout or a
   non-backtracking engine.
7. **Pydantic v1-style validators.** The `@validator` decorator still works
   under Pydantic v2 but is deprecated. Migrating to `field_validator` is a
   small, worthwhile cleanup.
8. **Monolithic file and inline UI.** The whole UI is one large inline HTML/JS
   string, which is why the CSP still needs `unsafe-inline`. Splitting the
   frontend into static assets would let the CSP tighten and make the code far
   easier to navigate.

## Threat model summary

- **Assets:** the sensitive data in submitted text and files, the audit trail,
  and admin-defined detection rules.
- **Adversaries:** an unauthenticated caller, a low-privilege user trying to act
  as admin, and a malicious admin supplying a pathological regex.
- **Mitigations in place:** auth on every data endpoint, RBAC for admin actions,
  rate limiting and login lockout, anonymization before any external call, a
  ReDoS guard, and audit logging that never records raw PII.
- **Known gaps:** the accuracy and revocation issues above, and the fact that
  the LLM advisory still trusts whatever endpoint `LLM_BASE_URL` points at.

## What I would do next

1. Build the labeled evaluation set and publish precision/recall. This is the
   single change that most improves both the product and its credibility.
2. Move login lockout and stats to a shared store.
3. Add token revocation (token version or refresh tokens).
4. Introduce the `db_conn()` context manager across the data layer.
5. Split the UI out of the Python file so the CSP can drop `unsafe-inline`.
