#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, os, platform, statistics
from pathlib import Path
from rac import Contract
from g6 import check_index, mutation_suite, make_profile, perf_suite, latency_rounds, throughput_rounds, flat_workload, legacy_mediate
from g5 import stable_json


def rebuild(raw):
    out={}
    for fam,tools in raw.items():
        out[fam]={}
        for name,d in tools.items():
            out[fam][name]=Contract(name=d["name"],form=d["form"],domain=tuple(d["domain"]),denied=tuple(d["denied"]),static_decision=d.get("static_decision"),contract_id=d["contract_id"])
    return out

def subjects(raw):
    out={}
    for fam,tools in raw.items():
        out[fam]={}
        for name,d in tools.items():
            m={}
            for x in d["domain"]:
                m[x]=x.split("=",1)[1] if fam=="github" and "=" in x else x
            out[fam][name]=m
    return out

def sha(b): return hashlib.sha256(b).hexdigest()

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--lock",default="config/g6_lock.json"); ap.add_argument("--contracts",required=True); ap.add_argument("--g5-results",required=True); ap.add_argument("--source-hashes",required=True); ap.add_argument("--out",default="out-g6"); a=ap.parse_args()
    lock=json.loads(Path(a.lock).read_text()); raw=json.loads(Path(a.contracts).read_text()); g5r=json.loads(Path(a.g5_results).read_text()); src=json.loads(Path(a.source_hashes).read_text()); cs=rebuild(raw); sub=subjects(raw); out=Path(a.out); out.mkdir(parents=True,exist_ok=True)
    idx={}; checks={}; total=0
    for fam in ("azure","github","cloudflare"):
        idx[fam],checks[fam]=check_index(cs[fam],sub[fam]); total+=checks[fam]["checked"]
    correctness={"families":checks,"total_checked":total,"g5_all_required_invariants_pass":g5r["all_required_invariants_pass"],"all_pass":g5r["all_required_invariants_pass"] and all(x["pass"] for x in checks.values()),"tool_counts":{"azure":len(cs["azure"]),"github":len(cs["github"]),"cloudflare":len(cs["cloudflare"]),"change_under_rac":0}}
    conf=mutation_suite(idx["azure"],idx["github"],idx["cloudflare"]); profile=make_profile(idx["azure"],idx["github"],idx["cloudflare"]); cfg=lock["benchmark"]
    cf=cs["cloudflare"]; w=flat_workload(cf); base=lambda n,x:x; fn=lambda n,x:legacy_mediate(cf[n],x)
    diag_lat=latency_rounds(fn,base,w,200,2000,1); diag_tp=throughput_rounds(fn,w,10000,1); diag_added=diag_lat[0]["added_p99_us"]; diag_ops=diag_tp[0]["ops_s"]; diag_pass=diag_added<=cfg["p99_added_overhead_us_max"] and diag_ops>=cfg["core_throughput_min_ops_s"]
    if diag_pass:
        legacy=perf_suite("legacy-full-replay",cs["azure"],cs["github"],cs["cloudflare"],"legacy",cfg)
    else:
        legacy={"mode":"legacy","target_pass":False,"replay":"bounded-diagnostic","diagnostic_added_p99_us":diag_added,"diagnostic_ops_s":diag_ops,"historical_full_gate":"TIMEOUT_900S"}
    indexed=perf_suite("indexed-runtime",cs["azure"],cs["github"],cs["cloudflare"],"indexed",cfg)
    bench={"config":cfg,"legacy":legacy,"indexed":indexed,"hardening_triggered":True,"active_runtime":"indexed-runtime","deployability_pass":indexed["target_pass"]}
    deterministic={"G6_CORRECTNESS.json":correctness,"G6_CONFORMANCE.json":conf,"G6_PROFILE.json":profile,"G6_SOURCE_HASHES.json":src}
    for n,o in deterministic.items(): (out/n).write_bytes(stable_json(o))
    (out/"G6_BENCHMARK.json").write_bytes(stable_json(bench)); (out/"G6_ENVIRONMENT.json").write_bytes(stable_json({"python":platform.python_version(),"platform":platform.platform(),"cpu_count":os.cpu_count()}))
    (out/"G6_DETERMINISTIC_DIGESTS.json").write_bytes(stable_json({n:sha((out/n).read_bytes()) for n in deterministic}))
    summary={"correctness_pass":correctness["all_pass"],"decisions_checked":total,"mutants_killed":conf["killed"],"mutation_pass":conf["pass"],"legacy_replay_pass":legacy["target_pass"],"active_runtime":"indexed-runtime","active_deployability_pass":indexed["target_pass"],"active_worst_added_p99_us":indexed["worst_round_added_p99_us"],"active_worst_core_ops_s":indexed["worst_round_core_ops_s"],"tool_count_change":0,"all_required_g6_pass":correctness["all_pass"] and conf["pass"] and indexed["target_pass"]}
    (out/"G6_SUMMARY.json").write_bytes(stable_json(summary)); print(json.dumps(summary,indent=2));
    if not summary["all_required_g6_pass"]: raise SystemExit(2)
if __name__=="__main__": main()
