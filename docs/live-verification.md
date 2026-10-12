# Live verification

Final canonical deployment on stable Studionet, chain 61999, Normal (Full Consensus).

- Contract: `0x3AE46E93376edbfc3b9648641C8B8d93B1d101d3`
- Explorer: https://explorer-studio.genlayer.com/address/0x3AE46E93376edbfc3b9648641C8B8d93B1d101d3
- Deployment: https://explorer-studio.genlayer.com/tx/0x4c8d7256a58f8be8dcc4e503eb76b831f04f098b53d841fe5952799804a0cee4
- Commitment: https://explorer-studio.genlayer.com/tx/0xa85f569b6f7d84894997c281fc8519c05088adf1d00a092cbc098401e4eed778
- Verification: https://explorer-studio.genlayer.com/tx/0x8efa8fe373e78a69b6f5d3dac3b2ec772a87248c3a38ec385720247ea1163d33
- Deployed source commit: `3b30728e7b07bf42e80a9aa91d88253cb2e14d9a`
- Source SHA-256: `45eb63a0719b7750b9c2442060636d2ef10d7478acff67ed27395ead09eccf2f` (13,199 bytes), deployed readback byte-identical.
- Tests: 31 passed; GenVM lint (3 checks) and SDK validation passed; [CI passed](https://github.com/ANZA24k/IncidentProof/actions/runs/38221129672).
- All three transactions finalized successfully; verification consensus Accepted, with 3 agree, 1 disagree and 1 idle after quorum.
- History count: 2 (commitment and final verdict).
- Final state: FINAL; outcome INSUFFICIENT; timeline/root cause/remediation SUPPORTED; sufficient=true, trustworthy=false, contradictions=false; receipt AUTHENTICATED.
- Decision hash: `29195d15517bbe5848f0cc79f9e3223d8284228e086178426bf9613f57f86252`, recomputed from the observed verdict using sorted compact ASCII JSON.

[Exact final state](final-state.json), [machine-readable verification](live-verification.json), [immutable manifest](../fixtures/manifest.json), [submission text](submission.md).

The fixture explicitly discloses fabrication: internal consistency is not trustworthy production evidence. INSUFFICIENT is a successful substantive consensus verdict, distinct from network UNDETERMINED. Earlier failed attempts and their diagnosed fixes are recorded in the JSON. Final source remains unchanged after deployment.
