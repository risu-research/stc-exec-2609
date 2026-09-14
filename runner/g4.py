#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, html, io, json, re, sys, urllib.request, zipfile
from collections import Counter, defaultdict
from pathlib import Path

UA = "stc-exec-2609-g4.1/1.0 (+https://github.com/risu-research/stc-exec-2609)"

def fetch(url: str, timeout: int = 180) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def tokenize(s: str) -> list[str]:
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", s)
    return [t for t in re.split(r"[^A-Za-z0-9]+", s.lower()) if t]

def is_restricted(s: str, tokens: set[str]) -> bool:
    return bool(set(tokenize(s)) & tokens)

def relation_metrics(groups: list[dict], tokens: set[str]) -> dict:
    memberships = sum(len(g["actions"]) for g in groups)
    tools = len(groups)
    all_ids = [a for g in groups for a in g["actions"]]
    unique_ids = set(all_ids)
    collisions = []
    collision_memberships = r_inside = n_inside = 0
    collision_unique_ids = set(); r_unique = set(); n_unique = set()
    homogeneous = []
    for g in groups:
        acts = list(g["actions"])
        flags = [is_restricted(a, tokens) for a in acts]
        if flags and any(flags) and not all(flags):
            r = [a for a, f in zip(acts, flags) if f]
            n = [a for a, f in zip(acts, flags) if not f]
            collisions.append({"tool": g["tool"], "restricted_actions": r, "nonrestricted_actions": n, "membership_count": len(acts)})
            collision_memberships += len(acts); r_inside += len(r); n_inside += len(n)
            collision_unique_ids.update(acts); r_unique.update(r); n_unique.update(n)
        elif len(acts) > 1:
            homogeneous.append({"tool": g["tool"], "membership_count": len(acts), "restricted": bool(flags and all(flags)), "actions": acts})
    return {
        "source_action_memberships": memberships,
        "unique_source_action_ids": len(unique_ids),
        "exposed_tools": tools,
        "membership_density": memberships/tools if tools else None,
        "unique_action_to_tool_ratio": len(unique_ids)/tools if tools else None,
        "tool_reduction_vs_memberships": 1-tools/memberships if memberships else None,
        "colliding_tools": len(collisions),
        "collision_tool_rate": len(collisions)/tools if tools else None,
        "memberships_inside_colliding_tools": collision_memberships,
        "collision_membership_exposure": collision_memberships/memberships if memberships else None,
        "restricted_memberships_inside_colliding_tools": r_inside,
        "permissive_exposure_membership_rate": r_inside/memberships if memberships else None,
        "nonrestricted_memberships_inside_colliding_tools": n_inside,
        "conservative_overhead_membership_rate": n_inside/memberships if memberships else None,
        "unique_action_ids_exposed_by_colliding_tools": len(collision_unique_ids),
        "unique_collision_action_exposure": len(collision_unique_ids)/len(unique_ids) if unique_ids else None,
        "unique_restricted_action_ids_in_collisions": len(r_unique),
        "unique_nonrestricted_action_ids_in_collisions": len(n_unique),
        "collision_certificates": collisions,
        "negative_control_groups_count": len(homogeneous),
        "largest_negative_controls": sorted(homogeneous, key=lambda x:(-x["membership_count"],x["tool"]))[:20],
    }

def azure(lock, tokens):
    c = lock["azure_commit"]
    url = f"https://raw.githubusercontent.com/microsoft/mcp/{c}/servers/Azure.Mcp.Server/src/Resources/consolidated-tools.json"
    raw = fetch(url); obj = json.loads(raw); entries = obj.get("consolidated_tools", [])
    groups=[]; action_to_tools=defaultdict(list); within_dups=[]; size_hist=Counter(); metadata=Counter()
    for e in entries:
        acts=list(e.get("mappedToolList") or [])
        if not acts: continue
        tool=e.get("name")
        if len(acts)!=len(set(acts)): within_dups.append(tool)
        groups.append({"tool":tool,"actions":acts}); size_hist[len(acts)]+=1
        for a in acts: action_to_tools[a].append(tool)
        md=e.get("toolMetadata") or {}
        for k in ("destructive","readOnly","idempotent","openWorld"):
            v=md.get(k)
            if isinstance(v,dict) and isinstance(v.get("value"),bool): metadata[f"{k}={str(v['value']).lower()}"]+=1
    r=relation_metrics(groups,tokens)
    duplicates={a:ts for a,ts in action_to_tools.items() if len(ts)>1}
    destruct_groups=[]; restricted_under_false=[]
    for e in entries:
        acts=list(e.get("mappedToolList") or [])
        if not acts: continue
        d=(((e.get("toolMetadata") or {}).get("destructive") or {}).get("value"))
        if d is True: destruct_groups.append({"tool":e.get("name"),"actions":acts})
        if d is False:
            rr=[a for a in acts if is_restricted(a,tokens)]
            if rr: restricted_under_false.append({"tool":e.get("name"),"actions":rr})
    d_members=sum(len(g["actions"]) for g in destruct_groups)
    d_non=sum(1 for g in destruct_groups for a in g["actions"] if not is_restricted(a,tokens))
    r.update({
        "source":{"url":url,"commit":c,"sha256":sha256(raw),"bytes":len(raw)},
        "raw_entries":len(entries),
        "duplicate_action_ids":duplicates,
        "duplicate_action_id_count":len(duplicates),
        "within_tool_duplicate_membership_tools":within_dups,
        "exposure_model":"relation E subseteq A x T",
        "group_size_histogram":dict(sorted(size_hist.items())),
        "metadata_counts":dict(metadata),
        "vendor_destructive_true":{
            "tools":len(destruct_groups),"source_action_memberships":d_members,
            "nonrestricted_pdel_action_memberships":d_non,
            "nonrestricted_share_within_destructive_tools":d_non/d_members if d_members else None,
            "pdel_restricted_under_destructive_false":restricted_under_false,
        }
    })
    return r

def github_mcp(lock,tokens,keys):
    c=lock["github_mcp_commit"]; url=f"https://codeload.github.com/github/github-mcp-server/zip/{c}"
    raw=fetch(url); dims=[]; tool_dims=defaultdict(list); errors=[]
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        names=[n for n in z.namelist() if "/pkg/github/__toolsnaps__/" in n and n.endswith(".snap")]
        for n in names:
            try:d=json.loads(z.read(n))
            except Exception as exc: errors.append({"path":n,"error":repr(exc)}); continue
            tool=d.get("name") or Path(n).stem; props=((d.get("inputSchema") or {}).get("properties") or {})
            for key in keys:
                p=props.get(key)
                if isinstance(p,dict):
                    vals=p.get("enum")
                    if isinstance(vals,list) and len(vals)>=2 and all(isinstance(v,str) for v in vals):
                        dim={"tool":tool,"key":key,"raw_values":vals,"path":n}; dims.append(dim); tool_dims[tool].append(dim)
    groups=[]; dimension_certs=[]; cohorts=[]
    for tool,ds in sorted(tool_dims.items()):
        alternatives=[]; mixed=[]
        for d in ds:
            alternatives.extend([f"{d['key']}={v}" for v in d["raw_values"]])
            flags=[is_restricted(v,tokens) for v in d["raw_values"]]
            if any(flags) and not all(flags): mixed.append(d)
        groups.append({"tool":tool,"actions":alternatives})
        cohorts.append({"tool":tool,"dimensions":[{"key":d["key"],"values":d["raw_values"]} for d in ds]})
        if mixed:
            dimension_certs.append({"tool":tool,"dimensions":[{"key":d["key"],"restricted_values":[v for v in d["raw_values"] if is_restricted(v,tokens)],"nonrestricted_values":[v for v in d["raw_values"] if not is_restricted(v,tokens)]} for d in mixed]})
    r=relation_metrics(groups,tokens); r["collision_certificates"]=dimension_certs
    r.update({"source":{"url":url,"commit":c,"sha256":sha256(raw),"bytes":len(raw)},
              "snapshots_scanned":len(names),"snapshot_parse_errors":errors,"qualifying_dispatcher_tools":len(groups),
              "qualifying_dispatcher_dimensions":len(dims),"explicit_dispatcher_alternatives":sum(len(d["raw_values"]) for d in dims),
              "dispatcher_keys":keys,"cohort":cohorts,
              "interpretation":"Memberships are explicit key=value enum alternatives; no Cartesian product is constructed."})
    return r

def cloudflare(lock,tokens):
    ac=lock["cloudflare_api_commit"]; mc=lock["cloudflare_mcp_commit"]
    spec_url=f"https://raw.githubusercontent.com/cloudflare/api-schemas/{ac}/openapi.json"
    readme_url=f"https://raw.githubusercontent.com/cloudflare/mcp/{mc}/README.md"
    proc_url=f"https://raw.githubusercontent.com/cloudflare/mcp/{mc}/src/spec-processor.ts"
    raw=fetch(spec_url,240); readme=fetch(readme_url); proc=fetch(proc_url)
    obj=json.loads(raw); methods={"get","post","put","patch","delete","head","options"}; actions=[]; counts=Counter(); opids=Counter()
    for path,item in (obj.get("paths") or {}).items():
        if not isinstance(item,dict):continue
        for meth,op in item.items():
            lm=meth.lower()
            if lm not in methods or not isinstance(op,dict):continue
            aid=f"{lm.upper()} {path}"; actions.append(aid); counts[lm.upper()]+=1
            if op.get("operationId"):opids[op["operationId"]]+=1
    r=relation_metrics([{"tool":"execute","actions":actions}],tokens)
    rr=readme.decode("utf-8",errors="replace"); pp=proc.decode("utf-8",errors="replace")
    architecture_ok=all(x in rr for x in ("`docs`","`search`","`execute`","individual tool for each")) and "cloudflare.request()" in rr
    processor_methods=set(re.findall(r"'(get|post|put|patch|delete|head|options)'",pp.split("HTTP_METHODS",1)[1].split("]",1)[0],re.I)) if "HTTP_METHODS" in pp else set()
    counted_methods=set(k.lower() for k,v in counts.items() if v)
    restricted=r["restricted_memberships_inside_colliding_tools"]
    delete_n=counts.get("DELETE",0)
    r.update({
        "source":{"url":spec_url,"commit":ac,"sha256":sha256(raw),"bytes":len(raw)},
        "mcp_architecture_source":{"url":readme_url,"commit":mc,"sha256":sha256(readme),"bytes":len(readme)},
        "mcp_processor_source":{"url":proc_url,"commit":mc,"sha256":sha256(proc),"bytes":len(proc)},
        "architecture_verified":architecture_ok,
        "processor_http_methods":sorted(processor_methods),"counted_http_methods":sorted(counted_methods),
        "counted_methods_supported_by_processor":counted_methods.issubset(processor_methods),
        "http_method_counts":dict(sorted(counts.items())),
        "pdel_restricted_memberships_total":restricted,
        "pdel_restricted_via_http_delete":delete_n,
        "pdel_restricted_via_nondelete_path_token":restricted-delete_n,
        "duplicate_operation_ids":{k:v for k,v in opids.items() if v>1},
        "code_mode_execution_tools":1,"full_code_mode_surface_tools":3,
        "full_surface_operation_to_tool_ratio":len(actions)/3 if actions else None,
        "execution_surface_operation_to_tool_ratio":len(actions),
        "scope_note":"Reconstructed census: pinned official api-schemas input evaluated against pinned Cloudflare MCP architecture that seeds spec.json from api-schemas/main and exposes execution through one execute tool. It is not asserted as a timestamped measurement of the live server's currently loaded R2 object."
    })
    return r

def stripe(lock,tokens,out):
    url=lock["stripe_source"]; raw=fetch(url); got=sha256(raw); expected=lock.get("stripe_expected_sha256")
    source_dir=out/"sources"; source_dir.mkdir(parents=True,exist_ok=True)
    hash_match=(expected is None or got==expected)
    if hash_match:(source_dir/"stripe_mcp_first_fetch.html").write_bytes(raw)
    text=raw.decode("utf-8",errors="replace")
    visible=re.sub(r"\s+"," ",html.unescape(re.sub(r"<[^>]+>"," ",text))).lower()
    routing=("stripe_api_read" in text and "stripe_api_write" in text and all(x in visible for x in ("post","patch","put","delete")))
    markers={k:text.lower().find(k) for k in ("supported api methods","confirm actions by agents")}
    raw_api_occurrences=len(re.findall(r"(?:https://docs\.stripe\.com)?/api/[A-Za-z0-9_?&=./%+-]+",text))
    witnesses={
        "cancel_subscription_text": "cancel a subscription" in visible,
        "delete_coupon_text": "delete a coupon" in visible,
        "create_customer_text": "create a customer" in visible,
        "human_confirmation_text": ("requires human confirmation" in visible and "refund" in visible and "outbound payments" in visible),
    }
    return {"source":{"url":url,"sha256":got,"bytes":len(raw),"expected_sha256":expected,"hash_matches_first_fetch":hash_match,"versioning":"unversioned; first-fetch hash locked"},
            "documented_read_write_routing_detected":routing,"marker_positions":markers,"raw_api_reference_occurrences":raw_api_occurrences,
            "text_witnesses":witnesses,"full_action_weighted_metrics_status":"UNRESOLVED",
            "reason":"G4 does not infer per-method HTTP verbs from titles. Stripe is retained as a frozen corroborative architecture/policy case unless an authoritative deterministic route mapping is added as a separately frozen extension."}

def stable(obj):return (json.dumps(obj,sort_keys=True,indent=2)+"\n").encode()

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--lock",default="config/g4_lock.json");ap.add_argument("--out",default="out");args=ap.parse_args()
    lock_bytes=Path(args.lock).read_bytes();lock=json.loads(lock_bytes);tokens=set(lock["restricted_tokens"]);keys=list(lock["github_dispatcher_keys"])
    out=Path(args.out);out.mkdir(parents=True,exist_ok=True)
    az=azure(lock,tokens);gh=github_mcp(lock,tokens,keys);cf=cloudflare(lock,tokens);st=stripe(lock,tokens,out)
    results={"g4":{"policy":"P_DEL","authority_commit":lock["authority_commit"],"runner_lock_sha256":sha256(lock_bytes),"zero_llm":True,"exposure_model":"relation"},"azure":az,"github_mcp":gh,"cloudflare":cf,"stripe":st}
    invariants={
        "azure_nonempty":az["exposed_tools"]>0 and az["source_action_memberships"]>0,
        "azure_no_within_tool_duplicate_memberships":len(az["within_tool_duplicate_membership_tools"])==0,
        "github_dispatchers_nonempty":gh["qualifying_dispatcher_tools"]>0,
        "github_parse_errors_zero":len(gh["snapshot_parse_errors"])==0,
        "cloudflare_nonempty":cf["source_action_memberships"]>0,
        "cloudflare_architecture_verified":cf["architecture_verified"],
        "cloudflare_processor_covers_counted_methods":cf["counted_methods_supported_by_processor"],
        "cloudflare_has_restricted_and_nonrestricted":cf["restricted_memberships_inside_colliding_tools"]>0 and cf["nonrestricted_memberships_inside_colliding_tools"]>0,
        "stripe_first_fetch_hash_reproduced":st["source"]["hash_matches_first_fetch"],
        "stripe_routing_detected":st["documented_read_write_routing_detected"],
    }
    results["invariants"]=invariants;results["all_required_invariants_pass"]=all(invariants.values())
    (out/"results.json").write_bytes(stable(results))
    (out/"source_hashes.json").write_bytes(stable({k:results[k]["source"] for k in ("azure","github_mcp","cloudflare","stripe")}))
    (out/"certificates.json").write_bytes(stable({"azure":az["collision_certificates"],"github_mcp":gh["collision_certificates"],"cloudflare":cf["collision_certificates"]}))
    lines=["# G4.1 deterministic census summary","",f"Authority commit: `{lock['authority_commit']}`",f"Policy: P_DEL = {sorted(tokens)}","Exposure model: relation E subseteq A x T",""]
    for key,label in (("azure","Azure full consolidated census"),("github_mcp","GitHub schema-dispatch census"),("cloudflare","Cloudflare reconstructed official-seed census")):
        r=results[key];lines += [f"## {label}",f"- source_action_memberships: {r['source_action_memberships']}",f"- unique_source_action_ids: {r['unique_source_action_ids']}",f"- exposed_tools: {r['exposed_tools']}",f"- membership_density: {r['membership_density']}",f"- colliding_tools: {r['colliding_tools']}",f"- collision_tool_rate: {r['collision_tool_rate']}",f"- collision_membership_exposure: {r['collision_membership_exposure']}",f"- permissive_exposure_membership_rate: {r['permissive_exposure_membership_rate']}",f"- conservative_overhead_membership_rate: {r['conservative_overhead_membership_rate']}",""]
    lines += ["## Stripe frozen corroborative case",f"- source_sha256: {st['source']['sha256']}",f"- hash_matches_first_fetch: {st['source']['hash_matches_first_fetch']}",f"- documented_read_write_routing_detected: {st['documented_read_write_routing_detected']}",f"- full_action_weighted_metrics_status: {st['full_action_weighted_metrics_status']}","","## Invariants"]
    lines += [f"- {k}: {v}" for k,v in invariants.items()];lines.append(f"- all_required_invariants_pass: {results['all_required_invariants_pass']}")
    (out/"SUMMARY.md").write_text("\n".join(lines)+"\n",encoding="utf-8")
    print((out/"SUMMARY.md").read_text())
    if not results["all_required_invariants_pass"]:sys.exit(2)

if __name__=="__main__":main()
