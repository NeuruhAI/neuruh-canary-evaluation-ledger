# Neuruh Canary Evaluation Ledger

[![ci](https://github.com/NeuruhAI/neuruh-canary-evaluation-ledger/actions/workflows/ci.yml/badge.svg)](https://github.com/NeuruhAI/neuruh-canary-evaluation-ledger/actions/workflows/ci.yml)

Public Commons Release 021. An append-only, tamper-evident ledger for canary evaluation evidence.

Each entry binds the exact proposal, Promotion Gate decision, candidate and baseline artifact digests, exposure, sample count, metrics, incidents and deterministic PASS / HOLD / ROLLBACK verdict.

**Critical boundary:** canary evidence never grants deployment authority. PASS means canary evidence met its declared observations; it does not deploy or promote anything.

## Install

```bash
git clone https://github.com/NeuruhAI/neuruh-canary-evaluation-ledger.git
cd neuruh-canary-evaluation-ledger
python -m venv .venv
source .venv/bin/activate
pip install .
```

Or install a pinned release directly:

```bash
pip install "neuruh-canary-evaluation-ledger @ git+https://github.com/NeuruhAI/neuruh-canary-evaluation-ledger.git@v0.1.1-alpha"
```

## Sixty-second example

The repository ships synthetic fixtures. Check one with the installed CLI:

```bash
neuruh-canary-evaluation-ledger verify examples/canary.synthetic.jsonl
neuruh-canary-evaluation-ledger digest examples/canary.synthetic.jsonl
```

Expected output:

```text
{"length": 1, "ok": true, "tip": "6d414621a81dae00153c3027180542264bfe22515a92142b8194e0853cc45308"}
sha256:c2c48a89190663e32ef76752ef2d96fe9485f70712e06ecc0ff3c048d0567c5a
```

`inspect` prints the full parsed object as indented JSON.

`examples/build_synthetic.py` regenerates the fixtures from scratch, so the construction path can be read end to end.

Bad input is reported, never raised as a traceback: a missing file, unreadable JSON, or a rejected object prints `error: ...` on stderr and exits `2`.

## API

| Name | Notes |
| --- | --- |
| `DIRECTIONS` | Declared vocabulary. |
| `SCHEMA_VERSION` | Declared vocabulary. |
| `VERDICTS` | Declared vocabulary. |
| `CanaryEvaluation` | Fields: `ledger_id`, `evaluation_id`, `sequence`, `proposal_digest`, `promotion_digest`, `candidate_artifact_digest`… |
| `CanaryLedger` | Fields: `entries` |
| `CanaryValidationError` | Raised for every rejection. |
| `MetricObservation` | Fields: `metric`, `baseline_value`, `canary_value`, `direction`, `tolerance`, `regressed` |
| `canonical_json(v)` |  |
| `evaluate_canary(**kwargs)` |  |
| `sha256_ref(v)` |  |
| `verify_ledger(entries, expected_tip)` |  |

The published schema is [`schema/canary-evaluation.v0.1.schema.json`](schema/canary-evaluation.v0.1.schema.json).

## Test

```bash
python -m unittest discover -s tests -v
```

## Safety boundary

This package validates, records, and reports. It holds no credentials, performs no network I/O,
and grants no authority. A valid object means the claims inside it are internally consistent and
content-bound — not that the underlying action was correct, permitted, or actually happened.
Digests and hash links are tamper evidence, not signatures: they detect modification, they do
not establish who wrote an entry.

Only synthetic fixtures ship here: no production data, endpoints, policies, or topology. See
[`ARCHITECTURE.md`](ARCHITECTURE.md), [`PUBLIC_PRIVATE_BOUNDARY.md`](PUBLIC_PRIVATE_BOUNDARY.md), [`SECURITY.md`](SECURITY.md), and the
[Neuruh Public Commons boundary](https://github.com/NeuruhAI/public-commons/blob/main/PUBLIC_PRIVATE_BOUNDARY.md).

## License

Apache License 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
