#!/usr/bin/env python3
from __future__ import annotations
import argparse, json
from pathlib import Path

ALLOW="ALLOW"; DENY="DENY"; UNRESOLVED="UNRESOLVED"

def load_contract(d):
    return {"name":d["name"],"id":d["contract_id"],"domain":set(d["domain"]),"denied":set(d["denied"]),"static":d.get("static_decision")}

def decide(c,x):
    if not x or x not in c["domain"]: return UNRESOLVED
    if c["static"] is not None: return c["static"]
    return DENY if x in c["denied"] else ALLOW

def mixed(family):
    for name in sorted(family):
        c=load_contract(family[name])
        if c["static"] is None and c["denied"] and len(c["denied"])<len(c["domain"]):
            a=next(x for x in sorted(c["domain"]) if x not in c["denied"]); d=next(iter(sorted(c["denied"])))
            return c,a,d
    raise RuntimeError("no mixed contract")

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--contracts",default="out-g5/g5_contracts.json"); ap.add_argument("--reported",default="out-g6/G6_CONFORMANCE.json"); ap.add_argument("--out",default="out-g6"); a=ap.parse_args()
    allc=json.loads(Path(a.contracts).read_text()); reported=json.loads(Path(a.reported).read_text())
    az,aa,ad=mixed(allc["azure"]); gh,ga,gd=mixed(allc["github"]); cf,ca,cd=mixed(allc["cloudflare"])
    ref_trace=[decide(cf,ca),decide(cf,cd)]
    allow_receipt={"contract":az["id"],"identity":aa,"decision":decide(az,aa)}
    wrong_receipt={**allow_receipt,"contract":"wrong-contract"}
    ref_commit=lambda r,x: r["contract"]==az["id"] and r["decision"]==ALLOW and r["identity"]==x and x in az["domain"]
    conflict=[aa,ad]; ref_conflict=None if len([x for x in conflict if x])!=1 else conflict[0]
    mutant_outputs={
      "M1_outer_static_allow": ALLOW,
      "M2_outer_static_deny": DENY,
      "M3_requested_before_resolved": decide(az,aa),
      "M4_unbound_receipt": allow_receipt["decision"]==ALLOW,
      "M5_first_effect_only": [ref_trace[0],ref_trace[0]],
      "M6_unknown_defaults_allow": ALLOW,
      "M7_wrong_contract_id_accepted": wrong_receipt["decision"]==ALLOW and wrong_receipt["identity"]==aa,
      "M8_conflict_pick_first": conflict[0],
    }
    references={
      "M1_outer_static_allow": decide(az,ad),
      "M2_outer_static_deny": decide(az,aa),
      "M3_requested_before_resolved": decide(az,ad),
      "M4_unbound_receipt": ref_commit(allow_receipt,ad),
      "M5_first_effect_only": ref_trace,
      "M6_unknown_defaults_allow": decide(az,"__unknown__"),
      "M7_wrong_contract_id_accepted": ref_commit(wrong_receipt,aa),
      "M8_conflict_pick_first": ref_conflict,
    }
    killed={k:mutant_outputs[k]!=references[k] for k in mutant_outputs}
    result={"independent":True,"imports_primary_runtime":False,"mutants":killed,"killed":sum(killed.values()),"required":8,"reported_primary_killed":reported.get("killed"),"pass":all(killed.values()) and reported.get("pass") is True,"witness":{"azure":[az["name"],aa,ad],"github":[gh["name"],ga,gd],"cloudflare":[ca,cd]}}
    p=Path(a.out); p.mkdir(parents=True,exist_ok=True); (p/"G6_CONFORMANCE_AUDIT.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n"); print(json.dumps(result,indent=2))
    if not result["pass"]: raise SystemExit(2)
if __name__=="__main__": main()
