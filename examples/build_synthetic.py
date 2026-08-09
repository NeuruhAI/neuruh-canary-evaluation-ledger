from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"src"))
from neuruh_canary_evaluation_ledger import *
H=sha256_ref
e=evaluate_canary(
 ledger_id="canary-synthetic",evaluation_id="eval-1",sequence=0,
 proposal_digest=H("proposal"),promotion_digest=H("promotion"),
 candidate_artifact_digest=H("candidate"),baseline_artifact_digest=H("baseline"),
 stage="canary",exposure_fraction=0.1,sample_count=100,
 started_at="2026-08-09T20:10:00Z",ended_at="2026-08-09T20:20:00Z",
 metrics=(MetricObservation("latency_ms",100,105,"lower",10),MetricObservation("success_rate",0.95,0.96,"higher",0.01)),
 incident_ids=(),critical_incident_count=0)
ledger=CanaryLedger((e,))
Path(__file__).with_name("canary.synthetic.jsonl").write_text(ledger.to_jsonl())
print(ledger.tip)
