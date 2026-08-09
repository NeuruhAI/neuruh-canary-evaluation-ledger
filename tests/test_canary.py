import unittest
from neuruh_canary_evaluation_ledger import *
H=sha256_ref
def metric(**kw):
    d=dict(metric="latency",baseline_value=100,canary_value=105,direction="lower",tolerance=10,regressed=None);d.update(kw);return MetricObservation(**d)
def ev(**kw):
    d=dict(ledger_id="l1",evaluation_id="e1",sequence=0,proposal_digest=H("proposal"),promotion_digest=H("promotion"),
    candidate_artifact_digest=H("candidate"),baseline_artifact_digest=H("baseline"),stage="canary",exposure_fraction=.1,sample_count=100,
    started_at="2026-08-09T20:10:00Z",ended_at="2026-08-09T20:20:00Z",metrics=(metric(),),incident_ids=(),critical_incident_count=0)
    d.update(kw);return CanaryEvaluation(**d).seal()
class Tests(unittest.TestCase):
    def bad(self,fn):
        with self.assertRaises(CanaryValidationError):fn()
    def test_valid(self):ev().validate()
    def test_roundtrip(self):self.assertEqual(CanaryEvaluation.from_mapping(ev().to_dict()),ev())
    def test_hash_deterministic(self):self.assertEqual(ev().entry_hash,ev().entry_hash)
    def test_pass_verdict(self):self.assertEqual(ev().verdict,"pass")
    def test_hold_on_regression(self):self.assertEqual(ev(metrics=(metric(canary_value=120),)).verdict,"hold")
    def test_hold_on_incident(self):self.assertEqual(ev(incident_ids=("inc1",)).verdict,"hold")
    def test_rollback_on_critical(self):self.assertEqual(ev(incident_ids=("inc1",),critical_incident_count=1).verdict,"rollback")
    def test_critical_over_incidents(self):self.bad(lambda:ev(critical_incident_count=1))
    def test_deployment_authority_false(self):self.assertFalse(ev().deployment_authority)
    def test_deployment_authority_true_rejected(self):self.bad(lambda:ev(deployment_authority=True))
    def test_candidate_differs_baseline(self):self.bad(lambda:ev(candidate_artifact_digest=H("baseline")))
    def test_bad_proposal_hash(self):self.bad(lambda:ev(proposal_digest="bad"))
    def test_bad_promotion_hash(self):self.bad(lambda:ev(promotion_digest="bad"))
    def test_bad_candidate_hash(self):self.bad(lambda:ev(candidate_artifact_digest="bad"))
    def test_bad_baseline_hash(self):self.bad(lambda:ev(baseline_artifact_digest="bad"))
    def test_negative_sequence(self):self.bad(lambda:ev(sequence=-1))
    def test_bool_sequence(self):self.bad(lambda:ev(sequence=True))
    def test_zero_exposure(self):self.bad(lambda:ev(exposure_fraction=0))
    def test_over_exposure(self):self.bad(lambda:ev(exposure_fraction=1.1))
    def test_bool_exposure(self):self.bad(lambda:ev(exposure_fraction=True))
    def test_zero_sample(self):self.bad(lambda:ev(sample_count=0))
    def test_bool_sample(self):self.bad(lambda:ev(sample_count=True))
    def test_bad_start_time(self):self.bad(lambda:ev(started_at="wat"))
    def test_timezone_required(self):self.bad(lambda:ev(started_at="2026-08-09T20:10:00"))
    def test_end_after_start(self):self.bad(lambda:ev(ended_at="2026-08-09T20:09:59Z"))
    def test_equal_end_start(self):self.bad(lambda:ev(ended_at="2026-08-09T20:10:00Z"))
    def test_metrics_required(self):self.bad(lambda:ev(metrics=()))
    def test_duplicate_metric_name(self):self.bad(lambda:ev(metrics=(metric(),metric(canary_value=99))))
    def test_metric_lower_nonregressed(self):self.assertFalse(metric().seal().regressed)
    def test_metric_lower_regressed(self):self.assertTrue(metric(canary_value=111).seal().regressed)
    def test_metric_higher_nonregressed(self):self.assertFalse(metric(direction="higher",baseline_value=.9,canary_value=.91,tolerance=.01).seal().regressed)
    def test_metric_higher_regressed(self):self.assertTrue(metric(direction="higher",baseline_value=.9,canary_value=.88,tolerance=.01).seal().regressed)
    def test_metric_unknown_direction(self):self.bad(lambda:metric(direction="sideways").validate())
    def test_negative_tolerance(self):self.bad(lambda:metric(tolerance=-1).validate())
    def test_nonfinite_metric(self):self.bad(lambda:metric(canary_value=float("nan")).validate())
    def test_regressed_mismatch(self):self.bad(lambda:metric(canary_value=120,regressed=False).validate())
    def test_duplicate_incidents(self):self.bad(lambda:ev(incident_ids=("i","i")))
    def test_bad_critical_type(self):self.bad(lambda:ev(critical_incident_count=True))
    def test_verdict_tamper(self):self.bad(lambda:CanaryEvaluation(**{**ev().__dict__,"verdict":"rollback","entry_hash":None}).seal())
    def test_sequence_zero_prev_forbidden(self):self.bad(lambda:ev(previous_entry_hash="0"*64))
    def test_nonzero_prev_required(self):self.bad(lambda:ev(sequence=1,evaluation_id="e2"))
    def test_nonzero_prev_valid(self):
        a=ev();b=ev(sequence=1,evaluation_id="e2",previous_entry_hash=a.entry_hash);b.validate()
    def test_ledger_valid(self):
        a=ev();b=ev(sequence=1,evaluation_id="e2",previous_entry_hash=a.entry_hash);verify_ledger((a,b)).validate()
    def test_ledger_sequence_gap(self):
        a=ev();b=ev(sequence=2,evaluation_id="e2",previous_entry_hash=a.entry_hash);self.bad(lambda:verify_ledger((a,b)))
    def test_ledger_duplicate_id(self):
        a=ev();b=ev(sequence=1,previous_entry_hash=a.entry_hash);self.bad(lambda:verify_ledger((a,b)))
    def test_ledger_mixed_id(self):
        a=ev();b=ev(ledger_id="l2",sequence=1,evaluation_id="e2",previous_entry_hash=a.entry_hash);self.bad(lambda:verify_ledger((a,b)))
    def test_ledger_broken_prev(self):
        a=ev();b=ev(sequence=1,evaluation_id="e2",previous_entry_hash="0"*64);self.bad(lambda:verify_ledger((a,b)))
    def test_expected_tip(self):
        a=ev();verify_ledger((a,),expected_tip=a.entry_hash)
    def test_wrong_expected_tip(self):
        a=ev();self.bad(lambda:verify_ledger((a,),expected_tip="0"*64))
    def test_empty_ledger(self):verify_ledger(()).validate()
    def test_empty_tip_rejected(self):self.bad(lambda:verify_ledger((),expected_tip="0"*64))
    def test_jsonl_roundtrip(self):
        a=ev();l=CanaryLedger((a,));self.assertEqual(CanaryLedger.from_jsonl(l.to_jsonl()),l)
    def test_jsonl_bad_json(self):self.bad(lambda:CanaryLedger.from_jsonl("{bad}\n"))
    def test_unknown_top_field(self):
        x=ev().to_dict();x["deploy"]=True;self.bad(lambda:CanaryEvaluation.from_mapping(x))
    def test_bad_schema(self):
        x=ev().to_dict();x["schema_version"]="x";self.bad(lambda:CanaryEvaluation.from_mapping(x))
    def test_tamper_hash(self):
        x=ev().to_dict();x["sample_count"]=101;self.bad(lambda:CanaryEvaluation.from_mapping(x))
