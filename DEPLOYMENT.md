# Deployment

Use stable https://studio.genlayer.com (Studionet), not studio-dev or a release-candidate RPC. Stable Studio's pinned v0.2.16 template runner is used unchanged.

1. Install dev requirements; run `genvm-lint check contracts/incidentproof.py` and `pytest -q`.
2. Commit and push source and safe fixture. Build the manifest from the fixture's immutable 40-hex Git commit URL, exact UTF-8 bytes and SHA-256. See `fixtures/manifest.json` once published.
3. Import the exact canonical source into Studio. Select **Normal / Full Consensus**, deploy with no constructor arguments using a Studio-provided account.
4. Wait for finalized successful deployment. Read deployed source and compare exact bytes and SHA-256.
5. From the same account call `commit_incident` with fixture claims/manifest and a deadline inside the next 30 days. Wait for finalization.
6. Call `verify_incident` using Full Consensus. Wait for finalized success; read `get_incident`, `history_count` and `get_history`.
7. Recompute SHA-256 over canonical verdict JSON; compare with `decision_hash`. Record real transactions, source commit and exact final state in `docs/live-verification.md` and `docs/live-verification.json`.

Do not substitute leader-only execution, an accepted-but-unfinalized transaction, a mock result or an earlier contract source for live verification. If infrastructure fails, preserve the actual error and leave the deployment fields explicitly unverified.
