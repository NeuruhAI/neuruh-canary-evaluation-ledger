from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json, math, re
from typing import Any, Mapping, Sequence

SCHEMA_VERSION="neuruh.canary-evaluation-ledger.v0.1"
VERDICTS={"pass","hold","rollback"}
DIRECTIONS={"lower","higher"}
HEX64=re.compile(r"^[0-9a-f]{64}$")

class CanaryValidationError(ValueError):
    """Fail-closed refusal for malformed, tampered, reordered, or authority-claiming canary evidence."""

def canonical_json(v:Any)->str:
    return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False)

def sha256_ref(v:str|bytes)->str:
    if isinstance(v,str): v=v.encode()
    return "sha256:"+sha256(v).hexdigest()

def _nonempty(v:Any,n:str)->str:
    if not isinstance(v,str) or not v.strip(): raise CanaryValidationError(f"{n} must be non-empty string")
    return v

def _sha(v:Any,n:str)->str:
    v=_nonempty(v,n)
    if not v.startswith("sha256:") or not HEX64.fullmatch(v[7:]): raise CanaryValidationError(f"{n} must be sha256:<64 lowercase hex>")
    return v

def _hash64(v:Any,n:str)->str:
    v=_nonempty(v,n)
    if not HEX64.fullmatch(v): raise CanaryValidationError(f"{n} must be 64 lowercase hex")
    return v

def _time(v:Any,n:str)->datetime:
    v=_nonempty(v,n)
    try:d=datetime.fromisoformat(v.replace("Z","+00:00"))
    except ValueError as e: raise CanaryValidationError(f"{n} must be RFC3339/ISO-8601") from e
    if d.tzinfo is None: raise CanaryValidationError(f"{n} must include timezone")
    return d.astimezone(timezone.utc)

def _num(v:Any,n:str)->float:
    if isinstance(v,bool) or not isinstance(v,(int,float)): raise CanaryValidationError(f"{n} must be numeric")
    x=float(v)
    if not math.isfinite(x): raise CanaryValidationError(f"{n} must be finite")
    return x

def _keys(raw:Mapping[str,Any],req:set[str],opt:set[str],ctx:str)->None:
    miss=sorted(req-set(raw)); unk=sorted(set(raw)-req-opt)
    if miss: raise CanaryValidationError(f"{ctx} missing: {', '.join(miss)}")
    if unk: raise CanaryValidationError(f"{ctx} unknown: {', '.join(unk)}")

def _strings(v:Any,n:str)->tuple[str,...]:
    if not isinstance(v,list): raise CanaryValidationError(f"{n} must be array")
    out=tuple(_nonempty(x,f"{n} item") for x in v)
    if len(out)!=len(set(out)): raise CanaryValidationError(f"{n} duplicates")
    return out

@dataclass(frozen=True)
class MetricObservation:
    metric:str
    baseline_value:float
    canary_value:float
    direction:str
    tolerance:float
    regressed:bool|None=None

    def calculated_regressed(self)->bool:
        b=_num(self.baseline_value,"baseline_value"); c=_num(self.canary_value,"canary_value"); t=_num(self.tolerance,"tolerance")
        if t<0: raise CanaryValidationError("tolerance must be non-negative")
        if self.direction=="lower": return c > b+t
        if self.direction=="higher": return c < b-t
        raise CanaryValidationError(f"unknown direction: {self.direction}")

    def validate(self)->None:
        _nonempty(self.metric,"metric")
        expected=self.calculated_regressed()
        if self.regressed is not None and self.regressed is not expected:
            raise CanaryValidationError("regressed mismatch")

    def seal(self)->"MetricObservation":
        self.validate()
        return MetricObservation(self.metric,float(self.baseline_value),float(self.canary_value),self.direction,float(self.tolerance),self.calculated_regressed())

    def to_dict(self)->dict[str,Any]:
        s=self.seal()
        return {"metric":s.metric,"baseline_value":s.baseline_value,"canary_value":s.canary_value,"direction":s.direction,"tolerance":s.tolerance,"regressed":s.regressed}

    @classmethod
    def from_mapping(cls,raw:Mapping[str,Any])->"MetricObservation":
        req={"metric","baseline_value","canary_value","direction","tolerance","regressed"}; _keys(raw,req,set(),"metric")
        o=cls(raw["metric"],raw["baseline_value"],raw["canary_value"],raw["direction"],raw["tolerance"],raw["regressed"]); o.validate(); return o

@dataclass(frozen=True)
class CanaryEvaluation:
    ledger_id:str
    evaluation_id:str
    sequence:int
    proposal_digest:str
    promotion_digest:str
    candidate_artifact_digest:str
    baseline_artifact_digest:str
    stage:str
    exposure_fraction:float
    sample_count:int
    started_at:str
    ended_at:str
    metrics:tuple[MetricObservation,...]
    incident_ids:tuple[str,...]
    critical_incident_count:int
    verdict:str|None=None
    previous_entry_hash:str|None=None
    entry_hash:str|None=None
    deployment_authority:bool=False

    def calculated_verdict(self)->str:
        regressions=sum(1 for m in self.metrics if m.seal().regressed)
        if self.critical_incident_count>0: return "rollback"
        if regressions>0 or self.incident_ids: return "hold"
        return "pass"

    def body_dict(self)->dict[str,Any]:
        sealed_metrics=[m.seal() for m in self.metrics]
        return {"schema_version":SCHEMA_VERSION,"ledger_id":self.ledger_id,"evaluation_id":self.evaluation_id,"sequence":self.sequence,
        "proposal_digest":self.proposal_digest,"promotion_digest":self.promotion_digest,"candidate_artifact_digest":self.candidate_artifact_digest,
        "baseline_artifact_digest":self.baseline_artifact_digest,"stage":self.stage,"exposure_fraction":self.exposure_fraction,"sample_count":self.sample_count,
        "started_at":self.started_at,"ended_at":self.ended_at,"metrics":[m.to_dict() for m in sealed_metrics],"incident_ids":list(self.incident_ids),
        "critical_incident_count":self.critical_incident_count,"verdict":self.calculated_verdict(),"previous_entry_hash":self.previous_entry_hash,
        "deployment_authority":False}

    def calculated_hash(self)->str:
        return sha256(canonical_json(self.body_dict()).encode()).hexdigest()

    def validate(self,*,check_hash=True)->None:
        for v,n in [(self.ledger_id,"ledger_id"),(self.evaluation_id,"evaluation_id"),(self.stage,"stage")]: _nonempty(v,n)
        for v,n in [(self.proposal_digest,"proposal_digest"),(self.promotion_digest,"promotion_digest"),(self.candidate_artifact_digest,"candidate_artifact_digest"),(self.baseline_artifact_digest,"baseline_artifact_digest")]: _sha(v,n)
        if self.candidate_artifact_digest==self.baseline_artifact_digest: raise CanaryValidationError("candidate and baseline digests must differ")
        if isinstance(self.sequence,bool) or not isinstance(self.sequence,int) or self.sequence<0: raise CanaryValidationError("sequence must be non-negative integer")
        x=_num(self.exposure_fraction,"exposure_fraction")
        if not 0 < x <= 1: raise CanaryValidationError("exposure_fraction must be >0 and <=1")
        if isinstance(self.sample_count,bool) or not isinstance(self.sample_count,int) or self.sample_count<=0: raise CanaryValidationError("sample_count must be positive integer")
        st=_time(self.started_at,"started_at"); en=_time(self.ended_at,"ended_at")
        if en<=st: raise CanaryValidationError("ended_at must be after started_at")
        if not self.metrics: raise CanaryValidationError("at least one metric required")
        names=[]
        for m in self.metrics: m.validate(); names.append(m.metric)
        if len(names)!=len(set(names)): raise CanaryValidationError("metric names must be unique")
        for x in self.incident_ids:_nonempty(x,"incident_id")
        if len(self.incident_ids)!=len(set(self.incident_ids)): raise CanaryValidationError("incident ids must be unique")
        if isinstance(self.critical_incident_count,bool) or not isinstance(self.critical_incident_count,int) or self.critical_incident_count<0: raise CanaryValidationError("critical_incident_count must be non-negative integer")
        if self.critical_incident_count>len(self.incident_ids): raise CanaryValidationError("critical incidents cannot exceed incident ids")
        expected=self.calculated_verdict()
        if self.verdict is not None and self.verdict!=expected: raise CanaryValidationError("verdict mismatch")
        if self.sequence==0:
            if self.previous_entry_hash is not None: raise CanaryValidationError("sequence zero cannot have previous hash")
        else:
            if self.previous_entry_hash is None: raise CanaryValidationError("nonzero sequence requires previous hash")
            _hash64(self.previous_entry_hash,"previous_entry_hash")
        if self.deployment_authority is not False: raise CanaryValidationError("canary evaluation never grants deployment authority")
        if check_hash:
            if self.entry_hash is None: raise CanaryValidationError("entry_hash required")
            _hash64(self.entry_hash,"entry_hash")
            if self.entry_hash!=self.calculated_hash(): raise CanaryValidationError("entry_hash mismatch")

    def seal(self)->"CanaryEvaluation":
        self.validate(check_hash=False)
        o=CanaryEvaluation(**{**self.__dict__,"metrics":tuple(m.seal() for m in self.metrics),"verdict":self.calculated_verdict(),"deployment_authority":False,"entry_hash":None})
        o=CanaryEvaluation(**{**o.__dict__,"entry_hash":o.calculated_hash()}); o.validate(); return o

    def to_dict(self)->dict[str,Any]:
        s=self.seal(); out=s.body_dict(); out["entry_hash"]=s.entry_hash; return out

    @classmethod
    def from_mapping(cls,raw:Mapping[str,Any])->"CanaryEvaluation":
        req={"schema_version","ledger_id","evaluation_id","sequence","proposal_digest","promotion_digest","candidate_artifact_digest","baseline_artifact_digest","stage","exposure_fraction","sample_count","started_at","ended_at","metrics","incident_ids","critical_incident_count","verdict","previous_entry_hash","entry_hash","deployment_authority"}
        _keys(raw,req,set(),"evaluation")
        if raw["schema_version"]!=SCHEMA_VERSION: raise CanaryValidationError("unsupported schema_version")
        if not isinstance(raw["metrics"],list): raise CanaryValidationError("metrics must be array")
        o=cls(raw["ledger_id"],raw["evaluation_id"],raw["sequence"],raw["proposal_digest"],raw["promotion_digest"],raw["candidate_artifact_digest"],raw["baseline_artifact_digest"],raw["stage"],raw["exposure_fraction"],raw["sample_count"],raw["started_at"],raw["ended_at"],tuple(MetricObservation.from_mapping(x) for x in raw["metrics"]),_strings(raw["incident_ids"],"incident_ids"),raw["critical_incident_count"],raw["verdict"],raw["previous_entry_hash"],_hash64(raw["entry_hash"],"entry_hash"),raw["deployment_authority"])
        o.validate(); return o

@dataclass(frozen=True)
class CanaryLedger:
    entries:tuple[CanaryEvaluation,...]
    def validate(self,*,expected_tip:str|None=None)->None:
        if not self.entries:
            if expected_tip is not None: raise CanaryValidationError("empty ledger cannot match expected tip")
            return
        if len({e.ledger_id for e in self.entries})!=1: raise CanaryValidationError("ledger_id must be constant")
        if [e.sequence for e in self.entries]!=list(range(len(self.entries))): raise CanaryValidationError("sequence must be contiguous from zero")
        ids=[e.evaluation_id for e in self.entries]
        if len(ids)!=len(set(ids)): raise CanaryValidationError("evaluation ids must be unique")
        for i,e in enumerate(self.entries):
            e.validate()
            exp=None if i==0 else self.entries[i-1].entry_hash
            if e.previous_entry_hash!=exp: raise CanaryValidationError("broken previous hash")
        if expected_tip is not None:
            _hash64(expected_tip,"expected_tip")
            if self.entries[-1].entry_hash!=expected_tip: raise CanaryValidationError("expected tip mismatch")
    @property
    def tip(self): return None if not self.entries else self.entries[-1].entry_hash
    def digest(self)->str:
        self.validate(); return sha256_ref(canonical_json([e.to_dict() for e in self.entries]))
    def to_jsonl(self)->str:
        self.validate(); return "".join(canonical_json(e.to_dict())+"\n" for e in self.entries)
    @classmethod
    def from_jsonl(cls,text:str)->"CanaryLedger":
        rows=[]
        for i,line in enumerate(text.splitlines(),1):
            if not line.strip(): continue
            try: raw=json.loads(line)
            except json.JSONDecodeError as e: raise CanaryValidationError(f"invalid JSON line {i}") from e
            rows.append(CanaryEvaluation.from_mapping(raw))
        o=cls(tuple(rows)); o.validate(); return o

def evaluate_canary(**kwargs)->CanaryEvaluation:
    return CanaryEvaluation(**kwargs).seal()

def verify_ledger(entries:Sequence[CanaryEvaluation],*,expected_tip:str|None=None)->CanaryLedger:
    o=CanaryLedger(tuple(entries)); o.validate(expected_tip=expected_tip); return o
