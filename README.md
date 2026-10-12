# IncidentProof

A standalone GenLayer Intelligent Contract that verifies software incident claims against committed public evidence.

An operator commits a statement, timeline, root cause, remediation and an immutable evidence manifest. Leader and validators independently retrieve exact snapshot bytes, authenticate SHA-256 and length, and interpret qualitative claims. Each independently derives three findings and evaluates contradictions, sufficiency and trustworthiness. Validators require matching decision fields and evidence receipts; wording and selected quotations may differ. No wallet UI, backend, tokens, custody or payment accounting.

## Outcomes

| Outcome | Rule |
|---|---|
| VERIFIED | All three axes supported, sufficient/trustworthy, all snapshots authenticated |
| PARTIALLY_VERIFIED | One or two axes supported, other axes unknown, sufficient/trustworthy, all snapshots authenticated |
| DISPUTED | A material contradiction backed by an authenticated citation |
| INSUFFICIENT | No authenticated evidence, missing/mismatched snapshots, inadequate trust/coverage, or no supported axes |

Contradictions take precedence over incomplete evidence; a missing document never erases an authenticated contradiction. A network consensus failure is **not** an INSUFFICIENT verdict: it leaves the incident committed with no final write.

## Interface

- `commit_incident(incident_id, claims_json, manifest_json, deadline)` returns commitment hash. Operator is the sender. Claims require statement/timeline/root_cause/remediation strings. Deadline is transaction Unix seconds + 60 seconds to 30 days.
- `verify_incident(incident_id)` operator-only, once, before or at deadline; returns decision hash.
- `expire_incident(incident_id)` anyone after deadline; terminal EXPIRED state.
- `get_incident`, `history_count`, `get_history(offset, limit)` provide immutable claims, verdict and paginated append-only events.

IDs are unique per contract; canonical claim/manifest commitments are unique across operators and IDs. There are no updates, deletion, privileged overrides or upgrades. Correction means a new incident with changed evidence/claims; the old history remains intact. Each assessment belongs to the exact committed scope, not a universal guarantee that an operator told the truth.

## Evidence transport

Version 1 deliberately accepts only canonical HTTPS `raw.githubusercontent.com/owner/repo/<40 lowercase commit hex>/path.{txt,json,md,csv,log}` snapshots. Export public postmortems, status records, logs and test reports there with provenance. Mutable branch URLs, custom hosts, credentials, ports, escapes, queries and fragments are rejected. This narrow transport makes SSRF and canonicalization review tractable. Hashes authenticate copies, not their origin or truth.

1–5 snapshots; 16,000 bytes each; 48,000 total committed bytes; 8,000 claim-input bytes; 4,000 manifest-input bytes. Wrong status, byte length, hash, UTF-8 or fetch errors produce unavailable/mismatch receipts. Only authenticated UTF-8 reaches the model. LLM responses capped at 10,000 bytes, three exact-substring citations per axis (12–240 characters). No document instructions or uncommitted links are followed.

## Development

Python 3.12: `pip install -r requirements-dev.txt`, `genvm-lint check contracts/incidentproof.py`, `pytest -q`.
The source pins stable Studio's v0.2.16 runner hash, observed from its template on 2026-10-12. Tests explicitly select the matching artifact release. Direct-mode tests use SDK storage and mocked web/LLM functions, including captured validator execution; they are not claims of real network consensus. See [DEPLOYMENT.md](DEPLOYMENT.md) and [live verification](docs/live-verification.md).

## Current official API references

Reviewed once before implementation, 2026-10-12:
- https://docs.genlayer.com/developers/intelligent-contracts/features/non-determinism
- https://docs.genlayer.com/developers/intelligent-contracts/equivalence-principle
- https://docs.genlayer.com/developers/intelligent-contracts/features/web-access
- https://docs.genlayer.com/developers/intelligent-contracts/features/transaction-context
- https://docs.genlayer.com/developers/intelligent-contracts/testing
- https://docs.genlayer.com/api-references/genlayer-linter

GenLayer is necessary because causal explanations, remediation relevance, contradictions and evidence quality cannot be checked solely by hashes or ordinary deterministic smart-contract rules. Consensus judges those interpretations while deterministic code controls the record lifecycle.
