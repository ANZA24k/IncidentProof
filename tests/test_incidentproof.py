import hashlib
import json
from pathlib import Path
import pytest

SOURCE = "contracts/incidentproof.py"
BODY = Path("fixtures/incident.txt").read_text()
CLAIMS = Path("fixtures/claims.json").read_text()
URL = "https://raw.githubusercontent.com/ANZA24k/IncidentProof/" + "a" * 40 + "/fixtures/incident.txt"
MANIFEST = [{"url": URL, "sha256": hashlib.sha256(BODY.encode()).hexdigest(), "bytes": len(BODY.encode()), "role": "postmortem"}]
QUOTE = "configured queue_capacity=0"

def assessment(values=("SUPPORTED",)*3, sufficient=True, trustworthy=True):
    return {**{k: {"finding": v, "citations": [] if v == "UNKNOWN" else [{"index": 0, "quote": QUOTE}]} for k, v in zip(("timeline", "root_cause", "remediation"), values)}, "contradictions": "CONTRADICTED" in values, "sufficient": sufficient, "trustworthy": trustworthy}

@pytest.fixture
def setup(direct_vm, direct_deploy):
    direct_vm.warp("2026-10-12T00:00:00+00:00")
    c = direct_deploy(SOURCE, sdk_version="v0.2.16")
    direct_vm.mock_web("raw", {"status": 200, "body": BODY})
    direct_vm.mock_llm("independent incident", json.dumps(assessment()))
    return c

def commit(c, id="demo-incident", claims=CLAIMS, manifest=None, deadline=1791853200):
    return c.commit_incident(id, claims, json.dumps(MANIFEST if manifest is None else manifest), deadline)

@pytest.mark.parametrize("values,sufficient,trustworthy,expected", [
    (("SUPPORTED",)*3, True, True, "VERIFIED"),
    (("SUPPORTED","SUPPORTED","UNKNOWN"), True, True,"PARTIALLY_VERIFIED"),
    (("SUPPORTED","CONTRADICTED","UNKNOWN"),True,True,"DISPUTED"),
    (("UNKNOWN",)*3,False,False,"INSUFFICIENT"),
    (("SUPPORTED",)*3,False,True,"INSUFFICIENT"),
    (("SUPPORTED",)*3,True,False,"INSUFFICIENT")])
def test_outcomes(setup,direct_vm,values,sufficient,trustworthy,expected):
    commit(setup)
    direct_vm.clear_mocks()
    direct_vm.mock_web("raw", {"status":200,"body":BODY})
    direct_vm.mock_llm("independent incident",json.dumps(assessment(values,sufficient,trustworthy)))
    h=setup.verify_incident("demo-incident")
    state=json.loads(setup.get_incident("demo-incident"))
    assert state["verdict"]["outcome"]==expected
    canonical=json.dumps(state["verdict"],sort_keys=True,separators=(",",":"),ensure_ascii=True)
    assert h==hashlib.sha256(canonical.encode()).hexdigest()
    assert direct_vm.run_validator()
    assert setup.history_count()==2
    assert len(setup.get_history(0,50))==2
    with direct_vm.expect_revert("immutable"): setup.verify_incident("demo-incident")
    with direct_vm.expect_revert("immutable"): setup.expire_incident("demo-incident")

def test_independent_validator_rejects_disagreement(setup,direct_vm):
    commit(setup); setup.verify_incident("demo-incident")
    direct_vm.clear_mocks()
    direct_vm.mock_web("raw",{"status":200,"body":BODY})
    direct_vm.mock_llm("independent incident",json.dumps(assessment(("SUPPORTED","UNKNOWN","UNKNOWN"))))
    assert not direct_vm.run_validator()
    assert not direct_vm.run_validator(leader_error=ValueError("bad"))
    assert not direct_vm.run_validator(leader_result={"assessment":assessment(),"receipts":["MISMATCH"]})

def test_replay_and_authorization(setup,direct_vm,direct_bob):
    commit(setup)
    with direct_vm.expect_revert("duplicate incident"): commit(setup)
    with direct_vm.expect_revert("duplicate commitment"): commit(setup,"different-id")
    direct_vm.sender=direct_bob
    with direct_vm.expect_revert("operator only"): setup.verify_incident("demo-incident")
    assert setup.history_count()==1

@pytest.mark.parametrize("change",[
    {"url":"http://example.com/a.txt"}, {"url":"https://127.0.0.1/a.txt"},
    {"url":URL.replace("a"*40,"main")},{"url":URL+"?x=1"}, {"url":URL+"#x"},
    {"url":URL.replace("/fixtures/","/../")}, {"sha256":"0"*63},
    {"bytes":True},{"bytes":16001},{"role":"instructions"}])
def test_manifest_rejection(setup,direct_vm,change):
    m=[{**MANIFEST[0],**change}]
    with direct_vm.expect_revert(): commit(setup,manifest=m)
    assert setup.history_count()==0

@pytest.mark.parametrize("status,body,receipt",[(404,"","UNAVAILABLE"),(200,"changed","MISMATCH"),(200,"x"*17000,"MISMATCH")])
def test_inaccessible_or_tampered(setup,direct_vm,status,body,receipt):
    commit(setup); direct_vm.clear_mocks()
    direct_vm.mock_web("raw",{"status":status,"body":body})
    setup.verify_incident("demo-incident")
    s=json.loads(setup.get_incident("demo-incident"))
    assert s["verdict"]["outcome"]=="INSUFFICIENT"
    assert s["verdict"]["receipts"]==[receipt]
    assert direct_vm.run_validator()

@pytest.mark.parametrize("raw",["not json",json.dumps({}),json.dumps(assessment()).replace(QUOTE,"invented quotation"), "x"*10001])
def test_invalid_llm_does_not_finalize(setup,direct_vm,raw):
    commit(setup); direct_vm.clear_mocks()
    direct_vm.mock_web("raw",{"status":200,"body":BODY}); direct_vm.mock_llm("independent incident",raw)
    with direct_vm.expect_revert(): setup.verify_incident("demo-incident")
    assert json.loads(setup.get_incident("demo-incident"))["state"]=="COMMITTED"
    assert setup.history_count()==1

def test_deadline_and_expiry(setup,direct_vm):
    with direct_vm.expect_revert("deadline"): commit(setup,deadline=1)
    commit(setup)
    with direct_vm.expect_revert("not expired"): setup.expire_incident("demo-incident")
    direct_vm.warp("2026-11-13T00:00:00+00:00")
    with direct_vm.expect_revert("expired"): setup.verify_incident("demo-incident")
    setup.expire_incident("demo-incident")
    assert json.loads(setup.get_incident("demo-incident"))["state"]=="EXPIRED"
    with direct_vm.expect_revert("immutable"): setup.expire_incident("demo-incident")

def test_bounds(setup,direct_vm):
    with direct_vm.expect_revert(): commit(setup,manifest=MANIFEST*2)
    with direct_vm.expect_revert(): commit(setup,manifest=[])
    with direct_vm.expect_revert(): commit(setup,claims="x"*8001)
    with direct_vm.expect_revert(): commit(setup,id="BAD")
    with direct_vm.expect_revert(): setup.get_history(0,51)
    with direct_vm.expect_revert(): setup.get_incident("missing")

@pytest.mark.parametrize('bad_flag',[1,'true',{'value':True}])
def test_boolean_schema_rejects_coercion(setup,direct_vm,bad_flag):
    commit(setup);direct_vm.clear_mocks()
    result=assessment();result['trustworthy']=bad_flag
    direct_vm.mock_web('raw',{'status':200,'body':BODY})
    direct_vm.mock_llm('independent incident',json.dumps(result))
    with direct_vm.expect_revert('boolean required'):setup.verify_incident('demo-incident')
    assert json.loads(setup.get_incident('demo-incident'))['state']=='COMMITTED'

def test_authenticated_excerpt_whitespace(setup,direct_vm):
    commit(setup);direct_vm.clear_mocks();result=assessment()
    result['timeline']['citations']=[{'index':0,'quote':'capacity was zero. Reproducer: set capacity to zero'}]
    direct_vm.mock_web('raw',{'status':200,'body':BODY})
    direct_vm.mock_llm('independent incident',json.dumps(result))
    setup.verify_incident('demo-incident')
    assert direct_vm.run_validator()
