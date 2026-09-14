#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, html, io, json, re, sys, urllib.request, zipfile
from pathlib import Path
from html.parser import HTMLParser
from collections import Counter, defaultdict

UA = "stc-exec-2609-g4/1.0 (+https://github.com/risu-research/stc-exec-2609)"

def fetch(url: str, timeout: int = 120) -> bytes:
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

def group_metrics(groups: list[dict], tokens: set[str], action_field="actions") -> dict:
    source_n = sum(len(g[action_field]) for g in groups)
    exposed_n = len(groups)
    collisions = []
    restricted_inside = 0
    nonrestricted_inside = 0
    collision_actions = 0
    for g in groups:
        acts = g[action_field]
        flags = [is_restricted(a, tokens) for a in acts]
        mixed = bool(flags) and any(flags) and not all(flags)
        if mixed:
            r = [a for a, f in zip(acts, flags) if f]
            n = [a for a, f in zip(acts, flags) if not f]
            collisions.append({"tool": g["tool"], "restricted_actions": r, "nonrestricted_actions": n, "source_count": len(acts)})
            restricted_inside += len(r)
            nonrestricted_inside += len(n)
            collision_actions += len(acts)
    return {
        "source_actions": source_n,
        "exposed_tools": exposed_n,
        "compression_ratio": (source_n/exposed_n) if exposed_n else None,
        "tool_reduction": (1-exposed_n/source_n) if source_n else None,
        "colliding_tools": len(collisions),
        "collision_tool_rate": (len(collisions)/exposed_n) if exposed_n else None,
        "actions_inside_colliding_tools": collision_actions,
        "collision_action_exposure": (collision_actions/source_n) if source_n else None,
        "restricted_actions_inside_colliding_tools": restricted_inside,
        "permissive_exposure": (restricted_inside/source_n) if source_n else None,
        "nonrestricted_actions_inside_colliding_tools": nonrestricted_inside,
        "conservative_overhead": (nonrestricted_inside/source_n) if source_n else None,
        "collision_certificates": collisions,
    }

def azure(lock, tokens):
    commit = lock["azure_commit"]
    url = f"https://raw.githubusercontent.com/microsoft/mcp/{commit}/servers/Azure.Mcp.Server/src/Resources/consolidated-tools.json"
    raw = fetch(url)
    obj = json.loads(raw)
    entries = obj.get("consolidated_tools", [])
    groups = []
    action_to_tools = defaultdict(list)
    group_sizes = Counter()
    metadata_counts = Counter()
    homogeneous_examples = []
    for e in entries:
        acts = list(e.get("mappedToolList") or [])
        if not acts:
            continue
        name = e.get("name")
        groups.append({"tool": name, "actions": acts})
        group_sizes[len(acts)] += 1
        for a in acts:
            action_to_tools[a].append(name)
        md = e.get("toolMetadata") or {}
        for k in ("destructive", "readOnly", "idempotent", "openWorld"):
            v = md.get(k)
            if isinstance(v, dict) and isinstance(v.get("value"), bool):
                metadata_counts[f"{k}={str(v['value']).lower()}"] += 1
    duplicates = {a: ts for a, ts in action_to_tools.items() if len(ts) > 1}
    metrics = group_metrics(groups, tokens)
    for g in groups:
        if len(g["actions"]) <= 1:
            continue
        flags = [is_restricted(a, tokens) for a in g["actions"]]
        if all(flags) or not any(flags):
            homogeneous_examples.append({"tool": g["tool"], "source_count": len(g["actions"]), "restricted": bool(flags and all(flags)), "actions": g["actions"]})
    homogeneous_examples.sort(key=lambda x: (-x["source_count"], x["tool"]))
    destruct_groups = []
    for e in entries:
        acts = list(e.get("mappedToolList") or [])
        if not acts:
            continue
        d = (((e.get("toolMetadata") or {}).get("destructive") or {}).get("value"))
        if d is True:
            destruct_groups.append({"tool": e.get("name"), "actions": acts})
    destruct_source = sum(len(g["actions"]) for g in destruct_groups)
    destruct_nonrestricted = sum(1 for g in destruct_groups for a in g["actions"] if not is_restricted(a, tokens))
    restricted_under_nondestructive = []
    for e in entries:
        acts = list(e.get("mappedToolList") or [])
        if not acts:
            continue
        d = (((e.get("toolMetadata") or {}).get("destructive") or {}).get("value"))
        if d is False:
            rr = [a for a in acts if is_restricted(a, tokens)]
            if rr:
                restricted_under_nondestructive.append({"tool": e.get("name"), "actions": rr})
    metrics.update({
        "source": {"url": url, "commit": commit, "sha256": sha256(raw), "bytes": len(raw)},
        "raw_entries": len(entries),
        "duplicate_action_ids": duplicates,
        "projection_is_function": len(duplicates) == 0,
        "group_size_histogram": dict(sorted(group_sizes.items())),
        "metadata_counts": dict(metadata_counts),
        "negative_control_groups_count": len(homogeneous_examples),
        "largest_negative_controls": homogeneous_examples[:20],
        "vendor_destructive_true": {
            "tools": len(destruct_groups),
            "source_action_memberships": destruct_source,
            "nonrestricted_pdel_action_memberships": destruct_nonrestricted,
            "nonrestricted_share_within_destructive_tools": (destruct_nonrestricted/destruct_source if destruct_source else None),
            "pdel_restricted_under_destructive_false": restricted_under_nondestructive,
        }
    })
    return metrics, raw

def github_mcp(lock, tokens, dispatcher_keys):
    commit = lock["github_mcp_commit"]
    url = f"https://codeload.github.com/github/github-mcp-server/zip/{commit}"
    raw = fetch(url)
    dims = []
    tool_dims = defaultdict(list)
    parse_errors = []
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        names = [n for n in z.namelist() if "/pkg/github/__toolsnaps__/" in n and n.endswith(".snap")]
        snapshots = len(names)
        for n in names:
            try:
                d = json.loads(z.read(n))
            except Exception as exc:
                parse_errors.append({"path": n, "error": repr(exc)})
                continue
            tool = d.get("name") or Path(n).stem
            props = (((d.get("inputSchema") or {}).get("properties")) or {})
            for key in dispatcher_keys:
                p = props.get(key)
                if not isinstance(p, dict):
                    continue
                vals = p.get("enum")
                if isinstance(vals, list) and len(vals) >= 2 and all(isinstance(v, str) for v in vals):
                    dim = {"tool": tool, "key": key, "actions": [f"{key}={v}" for v in vals], "raw_values": vals, "path": n}
                    dims.append(dim)
                    tool_dims[tool].append(dim)
    tool_records = []
    certificates = []
    alternative_n = 0
    for tool, ds in sorted(tool_dims.items()):
        alts = []
        mixed_dims = []
        for d in ds:
            alternative_n += len(d["raw_values"])
            alts.extend([f"{d['key']}={v}" for v in d["raw_values"]])
            flags = [is_restricted(v, tokens) for v in d["raw_values"]]
            if any(flags) and not all(flags):
                mixed_dims.append(d)
        tool_records.append({"tool": tool, "actions": alts})
        if mixed_dims:
            cert_dims = []
            for d in mixed_dims:
                r = [v for v in d["raw_values"] if is_restricted(v, tokens)]
                nr = [v for v in d["raw_values"] if not is_restricted(v, tokens)]
                cert_dims.append({"key": d["key"], "restricted_values": r, "nonrestricted_values": nr})
            certificates.append({"tool": tool, "dimensions": cert_dims})
    base = group_metrics(tool_records, tokens)
    base["collision_certificates"] = certificates
    base.update({
        "source": {"url": url, "commit": commit, "sha256": sha256(raw), "bytes": len(raw)},
        "snapshots_scanned": snapshots,
        "snapshot_parse_errors": parse_errors,
        "qualifying_dispatcher_tools": len(tool_records),
        "qualifying_dispatcher_dimensions": len(dims),
        "explicit_dispatcher_alternatives": alternative_n,
        "dispatcher_keys": dispatcher_keys,
        "interpretation": "action-weighted metrics count explicit enum alternatives (key=value), not a Cartesian product of multiple selector dimensions"
    })
    return base, raw

def cloudflare(lock, tokens):
    commit = lock["cloudflare_api_commit"]
    url = f"https://raw.githubusercontent.com/cloudflare/api-schemas/{commit}/openapi.json"
    raw = fetch(url, timeout=240)
    obj = json.loads(raw)
    methods = {"get","post","put","patch","delete","head","options"}
    actions = []
    method_counts = Counter()
    opid_seen = Counter()
    for path, item in (obj.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for meth, op in item.items():
            lm = meth.lower()
            if lm not in methods or not isinstance(op, dict):
                continue
            aid = f"{lm.upper()} {path}"
            actions.append(aid)
            method_counts[lm.upper()] += 1
            oid = op.get("operationId")
            if oid:
                opid_seen[oid] += 1
    groups = [{"tool": "execute", "actions": actions}]
    metrics = group_metrics(groups, tokens)
    dup_opids = {k: v for k, v in opid_seen.items() if v > 1}
    metrics.update({
        "source": {"url": url, "commit": commit, "sha256": sha256(raw), "bytes": len(raw)},
        "http_method_counts": dict(sorted(method_counts.items())),
        "duplicate_operation_ids": dup_opids,
        "code_mode_execution_tools": 1,
        "full_code_mode_surface_tools": 3,
        "full_surface_compression_ratio": (len(actions)/3) if actions else None,
        "execution_surface_compression_ratio": len(actions),
        "note": "All official API operations are projected to Code Mode's single execute surface for the primary execution-policy analysis."
    })
    return metrics, raw

class StripeMethodsParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_heading = None
        self.heading_buf = []
        self.capture = False
        self.current_href = None
        self.link_buf = []
        self.links = []
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in ("h2","h3"):
            self.in_heading = tag
            self.heading_buf = []
        if tag == "a" and self.capture:
            self.current_href = attrs.get("href")
            self.link_buf = []
    def handle_data(self, data):
        if self.in_heading:
            self.heading_buf.append(data)
        if self.current_href is not None:
            self.link_buf.append(data)
    def handle_endtag(self, tag):
        if self.in_heading == tag:
            text = " ".join("".join(self.heading_buf).split()).lower()
            if "supported api methods" in text:
                self.capture = True
            elif self.capture and tag in ("h2","h3"):
                self.capture = False
            self.in_heading = None
        if tag == "a" and self.current_href is not None:
            title = " ".join("".join(self.link_buf).split())
            href = self.current_href
            if self.capture and href and "/api/" in href and title:
                self.links.append((title, href))
            self.current_href = None
            self.link_buf = []

def stripe(lock, tokens):
    url = lock["stripe_source"]
    raw = fetch(url)
    text = raw.decode("utf-8", errors="replace")
    p = StripeMethodsParser(); p.feed(text)
    seen = set(); methods = []
    for title, href in p.links:
        key = (title, href)
        if key not in seen:
            seen.add(key); methods.append({"title": title, "href": href})
    page_lower = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", text))).lower()
    routing_explicit = ("stripe_api_read" in text and "stripe_api_write" in text and all(x in page_lower for x in ("post","patch","put","delete")))
    restricted = [m for m in methods if is_restricted(m["title"] + " " + m["href"], tokens)]
    nonrestricted_write_witnesses = [m for m in methods if not is_restricted(m["title"] + " " + m["href"], tokens) and (set(tokenize(m["title"])) & {"create","update"})]
    collision_certified = bool(routing_explicit and restricted and nonrestricted_write_witnesses)
    return {
        "source": {"url": url, "sha256": sha256(raw), "bytes": len(raw), "versioning": "unversioned-web-page"},
        "supported_method_links_parsed": len(methods),
        "pdel_restricted_titles": restricted,
        "nonrestricted_write_witnesses": nonrestricted_write_witnesses[:20],
        "documented_read_write_routing_detected": routing_explicit,
        "write_surface_pdel_collision_certified": collision_certified,
        "full_action_weighted_metrics_status": "UNRESOLVED",
        "reason": "G4 forbids inferring each supported method's HTTP verb from title prose; exact action-weighted read/write metrics require authoritative per-method HTTP routing."
    }, raw

def stable_json(obj) -> bytes:
    return (json.dumps(obj, sort_keys=True, indent=2) + "\n").encode()

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--lock", default="config/g4_lock.json"); ap.add_argument("--out", default="out"); args = ap.parse_args()
    lock_bytes = Path(args.lock).read_bytes(); lock = json.loads(lock_bytes)
    tokens = set(lock["restricted_tokens"]); dispatcher_keys = list(lock["github_dispatcher_keys"])
    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
    results = {"g4": {"policy": "P_DEL", "authority_commit": lock["authority_commit"], "runner_lock_sha256": sha256(lock_bytes), "zero_llm": True}}
    source_hashes = {}
    az, _ = azure(lock, tokens); results["azure"] = az; source_hashes["azure"] = az["source"]
    gh, _ = github_mcp(lock, tokens, dispatcher_keys); results["github_mcp"] = gh; source_hashes["github_mcp"] = gh["source"]
    cf, _ = cloudflare(lock, tokens); results["cloudflare"] = cf; source_hashes["cloudflare"] = cf["source"]
    st, _ = stripe(lock, tokens); results["stripe"] = st; source_hashes["stripe"] = st["source"]
    invariants = {
        "azure_nonempty": az["exposed_tools"] > 0 and az["source_actions"] > 0,
        "azure_projection_is_function": az["projection_is_function"],
        "github_dispatchers_nonempty": gh["qualifying_dispatcher_tools"] > 0,
        "github_parse_errors_zero": len(gh["snapshot_parse_errors"]) == 0,
        "cloudflare_nonempty": cf["source_actions"] > 0,
        "cloudflare_has_delete_and_nondelete": (cf["http_method_counts"].get("DELETE", 0) > 0 and cf["source_actions"] > cf["http_method_counts"].get("DELETE", 0)),
        "stripe_snapshot_nonempty": st["source"]["bytes"] > 0,
    }
    results["invariants"] = invariants; results["all_required_invariants_pass"] = all(invariants.values())
    (out/"results.json").write_bytes(stable_json(results)); (out/"source_hashes.json").write_bytes(stable_json(source_hashes))
    certs = {"azure": az["collision_certificates"], "github_mcp": gh["collision_certificates"], "cloudflare": cf["collision_certificates"], "stripe": {"collision_certified": st["write_surface_pdel_collision_certified"], "restricted_witnesses": st["pdel_restricted_titles"][:20], "nonrestricted_write_witnesses": st["nonrestricted_write_witnesses"][:20]}}
    (out/"certificates.json").write_bytes(stable_json(certs))
    lines = ["# G4 deterministic full-census summary", "", f"Authority commit: `{lock['authority_commit']}`", f"Policy: P_DEL = {sorted(tokens)}", ""]
    for key, label in [("azure","Azure consolidated census"), ("github_mcp","GitHub schema-dispatch census"), ("cloudflare","Cloudflare OpenAPI -> execute")]:
        r = results[key]; lines.append(f"## {label}")
        for field in ("source_actions","exposed_tools","compression_ratio","colliding_tools","collision_tool_rate","collision_action_exposure","permissive_exposure","conservative_overhead"):
            if field in r: lines.append(f"- {field}: {r[field]}")
        lines.append("")
    lines += ["## Stripe", f"- supported_method_links_parsed: {st['supported_method_links_parsed']}", f"- documented_read_write_routing_detected: {st['documented_read_write_routing_detected']}", f"- write_surface_pdel_collision_certified: {st['write_surface_pdel_collision_certified']}", f"- full_action_weighted_metrics_status: {st['full_action_weighted_metrics_status']}", "", "## Invariants"]
    for k,v in invariants.items(): lines.append(f"- {k}: {v}")
    lines.append(f"- all_required_invariants_pass: {results['all_required_invariants_pass']}")
    (out/"SUMMARY.md").write_text("\n".join(lines)+"\n", encoding="utf-8")
    print((out/"SUMMARY.md").read_text())
    if not results["all_required_invariants_pass"]: sys.exit(2)

if __name__ == "__main__": main()
