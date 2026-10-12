# Security model

No real credentials, personal logs, financial operations or funds are required. Public synthetic fixtures contain no secrets. Default nonpayable methods reject value in GenVM; there is no deposit, withdrawal or financial ledger.

Only the committing operator can initiate verification. Every successful verdict is immutable; permissionless expiry is allowed strictly after the committed deadline. ID reuse and identical claim/manifest replay are rejected. Decision hashes cover canonical verdict JSON, including policy, chain, contract, incident commitment, transaction time, authenticated receipts and findings. Canonical JSON uses ASCII escapes, sorted keys and compact separators; hashes are lowercase SHA-256.

Leader and validators fetch independently inside nondeterministic execution, then independently prompt without exposing the leader result to validator models. The validator checks exact decision-vector agreement, matching fetch receipts, response schemas and authenticated quotations. It rejects errors rather than agreeing on malformed output. Storage writes occur only after consensus. INSUFFICIENT is a terminal assessment; retry after a transient outage requires a new incident with different evidence/claims. Expiry is terminal and has no verdict hash.

Claims and fetched content are serialized as untrusted JSON beneath fixed instructions. Models must ignore embedded instructions and assess evidence; strict schemas and citation membership prevent invented quotations but cannot eliminate model manipulation or prove the semantic validity of a quotation. Consensus agreement does not make fabricated evidence true. Byte hashes prove identity, not authenticity, independence or trustworthy authorship. A Git commit can disappear if its public repository is removed; preserve snapshots externally for audit.

The host's HTTP response is already allocated before this contract checks its length. Contract limits bound accepted content, prompts and state, not network-level download memory. GenVM web policy controls HTTP execution/redirects; the contract never accepts bytes without the committed hash/length, even if the host follows a redirect. Only the fixed public raw-GitHub host is requestable. Arbitrary links within documents are ignored.

Three categorical axes plus flags intentionally favor precise, conservative agreement; ambiguous evidence may cause leader rotations or UNDETERMINED network results. Trust and sufficiency remain qualitative judgments. Self-published reports need corroboration appropriate to the scope; the synthetic fixture proves workflow and internal consistency only. No security audit, uptime certification or production reliability guarantee is implied.

To report a vulnerability, open a repository issue without publishing secrets or sensitive operational logs.
