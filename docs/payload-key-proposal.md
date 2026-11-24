# Proposal — purpose-bound payload key and bounded payload lifetime

**Status: awaiting owner authorization. Nothing in this document has been applied.**
FF-03 (architect round 2, item 1C). The current implementation is unchanged and
remains as described in "Today" below.

## Why this needs a decision rather than a patch

Two properties of the encrypted `fill-forms` payload are currently *conventions*
enforced by code shape, not *guarantees* enforced by the system:

1. **Key separation.** Ciphertext is an AES-256-GCM payload keyed from
   `PHASE1_SECRET_ENCRYPTION_KEY`. The same key encrypts Phase-1 tool secrets
   (`takePhase1Secret`). Separation exists only because the two call sites use
   different AAD strings and prefixes. A future call site that forgets one of them
   produces ciphertext that a different subsystem will happily decrypt.
2. **Payload lifetime.** The TTL is `max(60, ceil(abandonedGraceMs()/1000))`, i.e.
   it is derived from the job-silence heuristics — currently `max(4×jobTimeout, 24h)`,
   so ≥24 h. It is a *retention* heuristic reused as a *cryptographic* lifetime. It
   also has no upper bound: a deployment that raised `JOB_TIMEOUT_MS` would silently
   extend how long form values live in Redis, and nothing records that.

Neither is a bug that a patch can fix, because both change an operational guarantee.
They are therefore proposed here for approval.

## Proposed change A — HKDF purpose-derived keys

Derive a per-purpose subkey from the single root secret instead of using it directly:

```
payload_key = HKDF-SHA256(
  ikm  = PHASE1_SECRET_ENCRYPTION_KEY,
  salt = "dip:v1:" || purpose,          // rendered as the HKDF salt
  info = purpose,                       // domain separation
  len  = 32)
```

with `purpose ∈ { "fill-forms/fields", "phase1/secret" }`.

| | Today | Proposed |
| --- | --- | --- |
| Root material | one key | one key (unchanged) |
| Which key encrypts fields | root, reused | derived `fill-forms/fields` subkey |
| Cross-purpose decryption | blocked by AAD convention | blocked by cryptography |
| AAD / prefix / TTL | unchanged | unchanged |
| New env vars | — | **none** |
| Migration | — | none: no ciphertext survives a redeploy (TTL ≤ 24 h) |

**Cost.** One `node:crypto` `hkdf` call per operation (microseconds), cached per
process. No new dependency — `crypto.hkdf` is built in. No schema change.

**Risk.** During a rolling deploy, an old process writes ciphertext with the root
key while a new process tries to read it with the subkey. Because both processes
also share the TTL, a job could outlive the rollover. Mitigation, if approved:
decrypt under the subkey, and on `auth tag mismatch` retry once under the root key,
counting the fallback; remove the fallback after one deploy cycle.

## Proposed change B — bounded payload lifetime

Decouple cryptographic lifetime from the retention heuristic:

```
ttl = clamp(
  ceil(abandonedGraceMs()/1000),     // never shorter than the queue may need
  60,                                // floor, unchanged
  PAYLOAD_MAX_TTL_SECONDS)           // ceiling, new, default 86_400 (24 h), max 7 d
```

* The **floor** logic is untouched, so no live job can lose its payload to a
  shorter TTL than today.
* The **ceiling** is new and bounded. A configuration that would otherwise keep
  form values for a week is refused loudly at startup rather than silently obeyed.
* Every payload write logs `ttl_seconds` and `ttl_capped: boolean`, so the effective
  lifetime is observable instead of inferred.

**Cost.** One config entry, one log field. **Risk.** If an approved deployment
genuinely needs >24 h of payload retention (e.g. a very long human-review queue),
the cap must be raised deliberately — which is exactly the point.

## Explicitly not proposed

* Rotating the root secret. Out of scope, and it would invalidate in-flight jobs.
* Changing the Redis key prefix or the AAD. Both stay byte-identical, so nothing
  already written becomes unreadable for a reason other than the key change above.
* Any change to what is stored. Field values stay encrypted; only the key they are
  encrypted *under* would change.

## Decision requested

1. Approve, reject, or amend **A** (purpose-derived keys) — independently of **B**.
2. Approve, reject, or amend **B** (bounded TTL), and if approved, confirm the
   default ceiling of 24 h.
3. Confirm the rolling-deploy fallback for **A** is acceptable, or require a
   maintenance-window cutover instead.

Until this is answered, the code keeps today's behaviour, and the round-2 report
records FF-03's key/lifetime item as **BLOCKED ON OWNER AUTHORIZATION** rather than
as fixed.
