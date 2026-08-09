# Neuruh Canary Evaluation Ledger

Public Commons Release 021. An append-only, tamper-evident ledger for canary evaluation evidence.

Each entry binds the exact proposal, Promotion Gate decision, candidate and baseline artifact digests, exposure, sample count, metrics, incidents and deterministic PASS / HOLD / ROLLBACK verdict.

**Critical boundary:** canary evidence never grants deployment authority. PASS means canary evidence met its declared observations; it does not deploy or promote anything.
