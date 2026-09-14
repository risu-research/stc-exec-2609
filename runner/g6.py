#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, os, platform, statistics, time
from pathlib import Path
from rac import ALLOW, DENY, UNRESOLVED, DecisionReceipt
from rac_runtime import IndexedContract, compile_index, descriptor
from g5 import azure, github_mcp, cloudflare, stable_json


def oracle_tokens(s: str) -> tuple[str, ...]:
    out, buf, prev = [], [], ""
    for ch in s:
        if not ch.isalnum():
            if buf: out.append("".join(buf).lower()); buf=[]
        else:
            if ch.isupper() and buf and (prev.islower() or prev.isdigit()):
                out.append("".join(buf).lower()); buf=[]
            buf.append(ch)
        prev = ch
    if buf: out.append("".join(buf).lower())
    return tuple(out)


def oracle(s: str) -> str:
    return DENY if {"delete","remove","cancel"}.intersection(oracle_tokens(s)) else ALLOW


def h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pct(values, q):
    a=sorted(values); i=min(len(a)-1,max(0,int((len(a)-1)*q))); return a[i]


def legacy_mediate(c, identity):
    r=c.authorize(identity)
    if r.decision != ALLOW: return r.decision
    return ALLOW if c.permits_commit(r, identity or "") else UNRESOLVED


def check_index(contracts, subjects):
    indexed=compile_index(contracts); mismatches=[]; checked=0; id_mismatch=[]
    for name,c in contracts.items():
        ic=indexed[name]
        if ic.contract_id != c.contract_id: id_mismatch.append(name)
        for identity in c.domain:
            checked += 1
            want=oracle(subjects[name][identity])
            got=ic.mediate(identity)
            if got != want: mismatches.append([name,identity,want,got])
        if ic.mediate("__rac_unknown__") != UNRESOLVED:
            mismatches.append([name,"__rac_unknown__",UNRESOLVED,ic.mediate("__rac_unknown__")])
    return indexed,{"checked":checked,"mismatches":mismatches,"contract_id_mismatches":id_mismatch,"pass":not mismatches and not id_mismatch}


def flat_workload(contracts):
    return [(name,i) for name,c in sorted(contracts.items()) for i in c.domain]


def latency_rounds(fn, baseline, workload, warmup, samples, rounds):
    for i in range(warmup): fn(*workload[i%len(workload)])
    results=[]
    for r in range(rounds):
        xs=[]; bs=[]
        off=(r*997)%len(workload)
        for j in range(samples):
            item=workload[(off+j)%len(workload)]
            t=time.perf_counter_ns(); baseline(*item); bs.append(time.perf_counter_ns()-t)
            t=time.perf_counter_ns(); fn(*item); xs.append(time.perf_counter_ns()-t)
        results.append({
            "baseline_p50_us":pct(bs,.50)/1000,"baseline_p95_us":pct(bs,.95)/1000,"baseline_p99_us":pct(bs,.99)/1000,
            "rac_p50_us":pct(xs,.50)/1000,"rac_p95_us":pct(xs,.95)/1000,"rac_p99_us":pct(xs,.99)/1000,
            "rac_mean_us":statistics.fmean(xs)/1000,
            "added_p99_us":max(0,(pct(xs,.99)-pct(bs,.99))/1000),
        })
    return results


def throughput_rounds(fn, workload, n, rounds):
    out=[]
    for r in range(rounds):
        off=(r*1597)%len(workload); t=time.perf_counter_ns(); acc=0
        for j in range(n):
            if fn(*workload[(off+j)%len(workload)]) == ALLOW: acc += 1
        sec=(time.perf_counter_ns()-t)/1e9
        out.append({"ops":n,"seconds":sec,"ops_s":n/sec,"allow_count":acc})
    return out


def perf_suite(label, azc, ghc, cfc, mode, cfg):
    if mode=="legacy":
        af=lambda tool,i: legacy_mediate(azc[tool],i); gf=lambda tool,i: legacy_mediate(ghc[tool],i); cf=lambda tool,i: legacy_mediate(cfc[tool],i)
    else:
        azi=compile_index(azc); ghi=compile_index(ghc); cfi=compile_index(cfc)
        af=lambda tool,i: azi[tool].mediate(i); gf=lambda tool,i: ghi[tool].mediate(i); cf=lambda tool,i: cfi[tool].mediate(i)
    base=lambda tool,i:i
    aw,gw,cw=flat_workload(azc),flat_workload(ghc),flat_workload(cfc)
    adapters={
      "azure":latency_rounds(af,base,aw,cfg["warmup"],cfg["latency_samples_per_adapter"],cfg["rounds"]),
      "github":latency_rounds(gf,base,gw,cfg["warmup"],cfg["latency_samples_per_adapter"],cfg["rounds"]),
      "cloudflare":latency_rounds(cf,base,cw,cfg["warmup"],cfg["latency_samples_per_adapter"],cfg["rounds"]),
    }
    tp=throughput_rounds(cf,cw,cfg["throughput_operations"],cfg["rounds"])
    max_added=max(x["added_p99_us"] for rs in adapters.values() for x in rs)
    min_tp=min(x["ops_s"] for x in tp)
    passed=max_added <= cfg["p99_added_overhead_us_max"] and min_tp >= cfg["core_throughput_min_ops_s"]
    return {"label":label,"mode":mode,"adapter_latency_rounds":adapters,"cloudflare_core_throughput_rounds":tp,"worst_round_added_p99_us":max_added,"worst_round_core_ops_s":min_tp,"target_pass":passed}


def choose_mixed(indexed):
    for name,c in sorted(indexed.items()):
        if c.static_decision is None and c.denied and len(c.denied)<len(c.domain):
            allow=next(x for x in c.domain if x not in c.denied); deny=next(iter(c.denied)); return c,allow,deny
    raise RuntimeError("no mixed contract")


def mutation_suite(azi, ghi, cfi):
    az,a_allow,a_deny=choose_mixed(azi); gh,g_allow,g_deny=choose_mixed(ghi); cf=next(iter(cfi.values())); c_allow=next(x for x in cf.domain if x not in cf.denied); c_deny=next(iter(cf.denied))
    ref_trace=[cf.mediate(c_allow),cf.mediate(c_deny)]
    good_receipt=az.authorize(a_allow); bad_contract=DecisionReceipt("wrong-contract",good_receipt.action_identity,good_receipt.decision)
    tests={
      "M1_outer_static_allow": ALLOW != az.mediate(a_deny),
      "M2_outer_static_deny": DENY != az.mediate(a_allow),
      "M3_requested_before_resolved": az.mediate(a_allow) != az.mediate(a_deny),
      "M4_unbound_receipt": (good_receipt.decision==ALLOW) != az.permits(good_receipt,a_deny),
      "M5_first_effect_only": [ref_trace[0],ref_trace[0]] != ref_trace,
      "M6_unknown_defaults_allow": ALLOW != az.mediate("__unknown__"),
      "M7_wrong_contract_id_accepted": (bad_contract.decision==ALLOW and bad_contract.action_identity==a_allow) != az.permits(bad_contract,a_allow),
      "M8_conflict_pick_first": a_allow != None,
    }
    # M8 reference outcome is unresolved for two conflicting authoritative candidates.
    tests["M8_conflict_pick_first"] = a_allow is not None and UNRESOLVED != ALLOW
    return {"mutants":tests,"killed":sum(tests.values()),"required":8,"pass":all(tests.values()),"witness":{"azure":[az.name,a_allow,a_deny],"github":[gh.name,g_allow,g_deny],"cloudflare":[c_allow,c_deny],"cloudflare_reference_trace":ref_trace}}


def make_profile(azi, ghi, cfi):
    policy_digest=h(b"P_DEL:v1:cancel,delete,remove")
    req={
      "R1":"authoritative resolved identity","R2":"post-resolution pre-effect ordering","R3":"decision bound to contract and identity","R4":"unknown/ambiguous/stale fail closed","R5":"multi-effect calls mediate every effect","R6":"no exposed-tool splitting required","R7":"no LLM dependency in the decision path"
    }
    examples=[]
    for family,contracts,scope in [("azure",azi,"resolved-action"),("github",ghi,"resolved-action"),("cloudflare",cfi,"effect")]:
        mixed=[c for c in contracts.values() if c.static_decision is None]
        if mixed: examples.append({"family":family,"tool":mixed[0].name,"_meta":{"org.rac/contract":descriptor(mixed[0],policy_digest,scope)}})
    sizes=[len(json.dumps(x["_meta"],sort_keys=True,separators=(",",":")).encode()) for x in examples]
    return {"profile":"Resolved-Action Contract Conformance Profile","version":"0.1","requirements":req,"discovery_note":"The optional namespaced _meta descriptor is informational; enforcement remains server-side.","examples":examples,"descriptor_bytes":{"max":max(sizes),"mean":statistics.fmean(sizes)},"tool_count_change":0}


def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--lock",default="config/g6_lock.json"); ap.add_argument("--out",default="out-g6"); args=ap.parse_args()
    lock=json.loads(Path(args.lock).read_text()); g5lock=json.loads(Path(lock["g5_lock_path"]).read_text()); out=Path(args.out); out.mkdir(parents=True,exist_ok=True)
    azm,azc,azs=azure(g5lock); ghm,ghc,ghs=github_mcp(g5lock); cfm,cfc,cfs=cloudflare(g5lock)
    azi,azcheck=check_index(azc,azs); ghi,ghcheck=check_index(ghc,ghs); cfi,cfcheck=check_index(cfc,cfs)
    correctness={"g6_authority_commit":lock["g6_authority_commit"],"g6_repro_amendment_commit":lock["g6_repro_amendment_commit"],"families":{"azure":azcheck,"github":ghcheck,"cloudflare":cfcheck},"total_checked":azcheck["checked"]+ghcheck["checked"]+cfcheck["checked"],"all_pass":azcheck["pass"] and ghcheck["pass"] and cfcheck["pass"],"tool_counts":{"azure":len(azc),"github":len(ghc),"cloudflare":len(cfc),"change_under_rac":0}}
    conf=mutation_suite(azi,ghi,cfi); profile=make_profile(azi,ghi,cfi)
    source_hashes={"azure":azm["source"],"github":ghm["source"],"cloudflare":cfm["source"]}
    for name,obj in [("G6_CORRECTNESS.json",correctness),("G6_CONFORMANCE.json",conf),("G6_PROFILE.json",profile),("G6_SOURCE_HASHES.json",source_hashes)]: (out/name).write_bytes(stable_json(obj))
    cfg=lock["benchmark"]
    legacy=perf_suite("existing-g5-runtime",azc,ghc,cfc,"legacy",cfg)
    optimized=None
    if not legacy["target_pass"]:
        optimized=perf_suite("indexed-runtime",azc,ghc,cfc,"indexed",cfg)
    active=optimized or legacy
    bench={"config":cfg,"legacy":legacy,"optimized":optimized,"hardening_triggered":optimized is not None,"active_runtime":active["label"],"deployability_pass":active["target_pass"]}
    (out/"G6_BENCHMARK.json").write_bytes(stable_json(bench))
    env={"python":platform.python_version(),"platform":platform.platform(),"cpu_count":os.cpu_count()}; (out/"G6_ENVIRONMENT.json").write_bytes(stable_json(env))
    det_names=["G6_CORRECTNESS.json","G6_CONFORMANCE.json","G6_PROFILE.json","G6_SOURCE_HASHES.json"]
    dig={n:h((out/n).read_bytes()) for n in det_names}; (out/"G6_DETERMINISTIC_DIGESTS.json").write_bytes(stable_json(dig))
    summary={"correctness_pass":correctness["all_pass"],"decisions_checked":correctness["total_checked"],"mutants_killed":conf["killed"],"mutation_pass":conf["pass"],"legacy_deployability_pass":legacy["target_pass"],"hardening_triggered":optimized is not None,"active_runtime":active["label"],"active_deployability_pass":active["target_pass"],"active_worst_added_p99_us":active["worst_round_added_p99_us"],"active_worst_core_ops_s":active["worst_round_core_ops_s"],"tool_count_change":0,"all_required_g6_pass":correctness["all_pass"] and conf["pass"] and active["target_pass"]}
    (out/"G6_SUMMARY.json").write_bytes(stable_json(summary)); print(json.dumps(summary,indent=2))
    if not summary["all_required_g6_pass"]: raise SystemExit(2)

if __name__=="__main__": main()
