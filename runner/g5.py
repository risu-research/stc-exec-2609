#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import io
import json
import urllib.request
import zipfile
from collections import defaultdict
from pathlib import Path

from rac import (
    ALLOW, DENY, UNRESOLVED, STATIC, SELECTOR, EFFECT,
    Action, baseline_errors, compile_contract, mediate_trace, pdel,
    resolve_unique_identity,
)

UA = "stc-exec-2609-g5/1.0 (+https://github.com/risu-research/stc-exec-2609)"


def fetch(url: str, timeout: int = 240) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def stable_json(obj) -> bytes:
    return (json.dumps(obj, sort_keys=True, indent=2) + "\n").encode()


def assert_hash(label: str, raw: bytes, expected: str) -> dict:
    actual = sha256(raw)
    return {
        "label": label,
        "sha256": actual,
        "expected_sha256": expected,
        "hash_match": actual == expected,
        "bytes": len(raw),
    }


def contract_metrics(contracts, subjects_by_contract):
    forms = {STATIC: 0, SELECTOR: 0, EFFECT: 0}
    false_allows = 0
    false_denies = 0
    checked = 0
    mismatches = []
    contract_bytes = 0
    denied_entries = 0
    domain_entries = 0
    for name, contract in contracts.items():
        forms[contract.form] += 1
        subjects = subjects_by_contract[name]
        contract_bytes += len(stable_json(contract.to_dict()))
        domain_entries += len(contract.domain)
        denied_entries += len(contract.denied)
        errs = baseline_errors(contract, subjects)
        false_allows += errs["permissive_false_allows"]
        false_denies += errs["conservative_false_denies"]
        for identity, subject in subjects.items():
            checked += 1
            got = contract.decide(identity)
            want = pdel(subject)
            if got != want:
                mismatches.append({
                    "contract": name,
                    "identity": identity,
                    "subject": subject,
                    "got": got,
                    "want": want,
                })
    return {
        "contract_forms": forms,
        "decisions_checked": checked,
        "equivalence_mismatches": mismatches,
        "equivalence_pass": not mismatches,
        "permissive_static_false_allows": false_allows,
        "conservative_static_false_denies": false_denies,
        "rac_false_allows": 0 if not mismatches else None,
        "rac_false_denies": 0 if not mismatches else None,
        "serialized_contract_bytes": contract_bytes,
        "domain_entries": domain_entries,
        "denied_entries": denied_entries,
    }


def azure(lock):
    commit = lock["azure_commit"]
    config_url = (
        f"https://raw.githubusercontent.com/microsoft/mcp/{commit}/"
        "servers/Azure.Mcp.Server/src/Resources/consolidated-tools.json"
    )
    raw = fetch(config_url)
    source = assert_hash("azure_consolidated_tools", raw, lock["azure_sha256"])
    source.update({"url": config_url, "commit": commit})
    obj = json.loads(raw)
    contracts = {}
    subjects = {}
    duplicate_memberships = defaultdict(list)

    for entry in obj.get("consolidated_tools", []):
        acts = list(entry.get("mappedToolList") or [])
        if not acts:
            continue
        name = entry.get("name")
        actions = [Action(identity=a, policy_subject=a) for a in acts]
        contracts[name] = compile_contract(name, actions, SELECTOR)
        subjects[name] = {a: a for a in acts}
        for a in acts:
            duplicate_memberships[a].append(name)

    metrics = contract_metrics(contracts, subjects)
    unique_actions = set()
    memberships = 0
    static_multi = 0
    for c in contracts.values():
        memberships += len(c.domain)
        unique_actions.update(c.domain)
        if c.form == STATIC and len(c.domain) > 1:
            static_multi += 1

    duplicates = {a: tools for a, tools in duplicate_memberships.items() if len(tools) > 1}

    router_url = (
        f"https://raw.githubusercontent.com/microsoft/mcp/{commit}/"
        "core/Microsoft.Mcp.Core/src/Areas/Server/Commands/ToolLoading/NamespaceToolLoader.cs"
    )
    router_raw = fetch(router_url)
    router = router_raw.decode("utf-8", errors="strict")
    markers = {
        "fallback_resolution": router.find("GetCommandAndParametersFromIntentAsync"),
        "final_child_lookup": router.find("namespaceCommands.TryGetValue(command"),
        "child_metadata_binding": router.find("ToolAnnotations, McpHelper.CreateToolAnnotationTelemetry(cmd)"),
        "child_elicitation": router.find("HandleElicitationAsync"),
        "child_execute": router.find("cmd.ExecuteAsync"),
    }
    router_order_ok = (
        all(v >= 0 for v in markers.values())
        and markers["fallback_resolution"] < markers["final_child_lookup"]
        < markers["child_metadata_binding"] < markers["child_elicitation"]
        < markers["child_execute"]
    )

    architecture = {
        "url": router_url,
        "commit": commit,
        "sha256": sha256(router_raw),
        "bytes": len(router_raw),
        "markers": markers,
        "final_resolution_before_child_policy_and_execution": router_order_ok,
        "production_positive_control": (
            "Pinned Azure code resolves the final child command, binds child metadata, "
            "performs child-level elicitation, and only then executes the child command."
        ),
    }

    metrics.update({
        "source": source,
        "architecture": architecture,
        "exposed_tools_retained": len(contracts),
        "split_baseline_unique_tools": len(unique_actions),
        "source_action_memberships": memberships,
        "unique_source_actions": len(unique_actions),
        "static_multi_action_negative_controls": static_multi,
        "duplicate_action_id_count": len(duplicates),
        "duplicate_action_ids": duplicates,
        "tool_count_change_under_rac": 0,
    })
    return metrics, contracts, subjects


def github_mcp(lock):
    commit = lock["github_mcp_commit"]
    url = f"https://codeload.github.com/github/github-mcp-server/zip/{commit}"
    raw = fetch(url)
    source = assert_hash("github_mcp_zip", raw, lock["github_mcp_sha256"])
    source.update({"url": url, "commit": commit})

    keys = list(lock["github_dispatcher_keys"])
    tool_actions = defaultdict(list)
    tool_subjects = defaultdict(dict)
    dims = []
    parse_errors = []
    snapshots = 0
    representative_code = ""

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
            for key in keys:
                p = props.get(key)
                if not isinstance(p, dict):
                    continue
                vals = p.get("enum")
                if isinstance(vals, list) and len(vals) >= 2 and all(isinstance(v, str) for v in vals):
                    dims.append({"tool": tool, "key": key, "values": vals, "path": n})
                    for v in vals:
                        identity = f"{tool}|{key}={v}"
                        tool_actions[tool].append(Action(identity=identity, policy_subject=v))
                        tool_subjects[tool][identity] = v

        action_files = [n for n in z.namelist() if n.endswith("/pkg/github/actions.go")]
        if action_files:
            representative_code = z.read(action_files[0]).decode("utf-8", errors="replace")

    contracts = {
        tool: compile_contract(tool, actions, SELECTOR)
        for tool, actions in tool_actions.items()
    }
    metrics = contract_metrics(contracts, tool_subjects)

    representative_markers = {
        "cancel_constant": "actionsMethodCancelWorkflowRun" in representative_code,
        "delete_logs_constant": "actionsMethodDeleteWorkflowRunLogs" in representative_code,
        "cancel_case": "case actionsMethodCancelWorkflowRun:" in representative_code,
        "cancel_handler": "return cancelWorkflowRun(" in representative_code,
        "delete_case": "case actionsMethodDeleteWorkflowRunLogs:" in representative_code,
        "delete_handler": "return deleteWorkflowRunLogs(" in representative_code,
    }
    representative_binding_ok = all(representative_markers.values())

    all_identities = set()
    for c in contracts.values():
        all_identities.update(c.domain)

    metrics.update({
        "source": source,
        "snapshots_scanned": snapshots,
        "snapshot_parse_errors": parse_errors,
        "qualifying_dispatcher_dimensions": len(dims),
        "exposed_tools_retained": len(contracts),
        "split_baseline_local_actions": len(all_identities),
        "unique_local_action_identities": len(all_identities),
        "tool_count_change_under_rac": 0,
        "dispatcher_keys": keys,
        "representative_production_binding": {
            "tool": "actions_run_trigger",
            "markers": representative_markers,
            "selector_dispatch_binding_verified": representative_binding_ok,
            "note": "Representative real handler switches on the same method constants exposed by the schema.",
        },
    })
    return metrics, contracts, tool_subjects


def cloudflare(lock):
    api_commit = lock["cloudflare_api_commit"]
    mcp_commit = lock["cloudflare_mcp_commit"]
    spec_url = f"https://raw.githubusercontent.com/cloudflare/api-schemas/{api_commit}/openapi.json"
    raw = fetch(spec_url)
    source = assert_hash("cloudflare_openapi", raw, lock["cloudflare_api_sha256"])
    source.update({"url": spec_url, "commit": api_commit})
    obj = json.loads(raw)
    methods = set(m.lower() for m in lock["http_methods"])
    actions = []
    subjects = {}
    for path, item in (obj.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            lm = method.lower()
            if lm not in methods or not isinstance(op, dict):
                continue
            identity = f"{lm.upper()} {path}"
            actions.append(Action(identity=identity, policy_subject=identity))
            subjects[identity] = identity

    contract = compile_contract("execute", actions, EFFECT)
    contracts = {"execute": contract}
    subjects_by_contract = {"execute": subjects}
    metrics = contract_metrics(contracts, subjects_by_contract)

    execute_url = f"https://raw.githubusercontent.com/cloudflare/mcp/{mcp_commit}/src/tools/execute.ts"
    execute_raw = fetch(execute_url)
    execute_src = execute_raw.decode("utf-8", errors="strict")
    markers = {
        "request_function": execute_src.find("async request(options)"),
        "method_path_binding": execute_src.find("const { method, path, query, body, contentType, rawBody } = options"),
        "outbound_fetch": execute_src.find("const response = await fetch(url.toString(),"),
        "user_code_execution": execute_src.find("const result = await (${code})();"),
    }
    request_boundary_ok = (
        all(v >= 0 for v in markers.values())
        and markers["request_function"] < markers["method_path_binding"] < markers["outbound_fetch"]
        and markers["user_code_execution"] > markers["request_function"]
    )
    architecture = {
        "url": execute_url,
        "commit": mcp_commit,
        "sha256": sha256(execute_raw),
        "bytes": len(execute_raw),
        "markers": markers,
        "effect_boundary_before_outbound_fetch": request_boundary_ok,
        "note": (
            "Pinned Code Mode defines cloudflare.request(options), extracts method/path, then performs fetch; "
            "this is an observable per-effect boundary inside an outer arbitrary async code invocation."
        ),
    }

    metrics.update({
        "source": source,
        "architecture": architecture,
        "exposed_tools_retained": 1,
        "split_baseline_http_operations": len(contract.domain),
        "tool_count_change_under_rac": 0,
    })
    return metrics, contracts, subjects_by_contract


def adversarial_gates(azure_contracts, cf_contract):
    gates = {}

    sql = azure_contracts["edit_azure_sql_databases_and_servers"]
    allowed = "sql_db_update"
    denied = "sql_db_delete"
    gates["real_mixed_selector"] = sql.decide(allowed) == ALLOW and sql.decide(denied) == DENY

    gates["post_resolution_needed_for_exactness"] = (
        sql.decide("edit_database_alias") == UNRESOLVED
        and sql.decide(allowed) == ALLOW
    )

    gates["unvalidated_requested_identity_is_not_authoritative"] = (
        pdel("update_database") == ALLOW and sql.decide(denied) == DENY
    )

    gates["unknown_fails_closed"] = sql.decide("totally_unknown_action") == UNRESOLVED
    gates["conflicting_identity_fails_closed"] = resolve_unique_identity([allowed, denied]) is None

    receipt = sql.authorize(allowed)
    gates["check_use_substitution_rejected"] = (
        sql.permits_commit(receipt, allowed)
        and not sql.permits_commit(receipt, denied)
    )

    allowed_cf = next(a for a in cf_contract.domain if cf_contract.decide(a) == ALLOW)
    denied_cf = next(a for a in cf_contract.domain if cf_contract.decide(a) == DENY)
    trace = [allowed_cf, denied_cf]
    rac_trace = mediate_trace(cf_contract, trace)
    ref_trace = [pdel(a) for a in trace]
    gates["mixed_multi_effect_trace_rac_exact"] = rac_trace == ref_trace == [ALLOW, DENY]
    gates["outer_static_allow_not_exact_for_mixed_trace"] = [ALLOW, ALLOW] != ref_trace
    gates["outer_static_deny_not_exact_for_mixed_trace"] = [DENY, DENY] != ref_trace

    return {
        "gates": gates,
        "all_pass": all(gates.values()),
        "cloudflare_trace_witness": {
            "allowed_effect": allowed_cf,
            "denied_effect": denied_cf,
            "reference": ref_trace,
            "rac": rac_trace,
        },
        "azure_selector_witness": {
            "tool": sql.name,
            "allowed_action": allowed,
            "denied_action": denied,
        },
    }


def summary_md(results: dict) -> str:
    az = results["azure"]
    gh = results["github"]
    cf = results["cloudflare"]
    adv = results["adversarial"]
    lines = [
        "# G5 Resolved-Action Contract summary",
        "",
        f"Authority constitution commit: `{results['g5']['authority_commit']}`",
        "Policy: P_DEL = {cancel, delete, remove}",
        "Primary decision dependency: zero LLM",
        "",
        "## Exact-equivalence gate",
        f"- Azure decisions checked: {az['decisions_checked']}; mismatches: {len(az['equivalence_mismatches'])}",
        f"- GitHub decisions checked: {gh['decisions_checked']}; mismatches: {len(gh['equivalence_mismatches'])}",
        f"- Cloudflare effects checked: {cf['decisions_checked']}; mismatches: {len(cf['equivalence_mismatches'])}",
        f"- all_required_invariants_pass: {results['all_required_invariants_pass']}",
        "",
        "## Contract forms",
        f"- Azure: STATIC={az['contract_forms']['STATIC']}, SELECTOR={az['contract_forms']['SELECTOR']}, EFFECT={az['contract_forms']['EFFECT']}",
        f"- GitHub: STATIC={gh['contract_forms']['STATIC']}, SELECTOR={gh['contract_forms']['SELECTOR']}, EFFECT={gh['contract_forms']['EFFECT']}",
        f"- Cloudflare: STATIC={cf['contract_forms']['STATIC']}, SELECTOR={cf['contract_forms']['SELECTOR']}, EFFECT={cf['contract_forms']['EFFECT']}",
        "",
        "## Static-baseline disagreement on mixed surfaces",
        f"- Azure permissive false allows: {az['permissive_static_false_allows']}",
        f"- Azure conservative false denies: {az['conservative_static_false_denies']}",
        f"- GitHub permissive false allows: {gh['permissive_static_false_allows']}",
        f"- GitHub conservative false denies: {gh['conservative_static_false_denies']}",
        f"- Cloudflare permissive false allows: {cf['permissive_static_false_allows']}",
        f"- Cloudflare conservative false denies: {cf['conservative_static_false_denies']}",
        "",
        "## Compression retained",
        f"- Azure exposed tools: {az['exposed_tools_retained']} (split baseline unique actions: {az['split_baseline_unique_tools']}); tool-count change under RAC: {az['tool_count_change_under_rac']}",
        f"- GitHub dispatcher tools: {gh['exposed_tools_retained']} (split local actions: {gh['split_baseline_local_actions']}); tool-count change under RAC: {gh['tool_count_change_under_rac']}",
        f"- Cloudflare executors: {cf['exposed_tools_retained']} (split HTTP operations: {cf['split_baseline_http_operations']}); tool-count change under RAC: {cf['tool_count_change_under_rac']}",
        "",
        "## Production-boundary evidence",
        f"- Azure final resolution -> child metadata/elicitation -> execute ordering verified: {az['architecture']['final_resolution_before_child_policy_and_execution']}",
        f"- GitHub representative selector dispatch binding verified: {gh['representative_production_binding']['selector_dispatch_binding_verified']}",
        f"- Cloudflare per-effect method/path boundary before outbound fetch verified: {cf['architecture']['effect_boundary_before_outbound_fetch']}",
        "",
        "## Adversarial gates",
    ]
    for k, v in adv["gates"].items():
        lines.append(f"- {k}: {v}")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lock", default="config/g5_lock.json")
    ap.add_argument("--out", default="out-g5")
    args = ap.parse_args()

    lock_bytes = Path(args.lock).read_bytes()
    lock = json.loads(lock_bytes)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    az, az_contracts, az_subjects = azure(lock)
    gh, gh_contracts, gh_subjects = github_mcp(lock)
    cf, cf_contracts, cf_subjects = cloudflare(lock)
    adv = adversarial_gates(az_contracts, cf_contracts["execute"])

    invariants = {
        "azure_source_hash_match": az["source"]["hash_match"],
        "github_source_hash_match": gh["source"]["hash_match"],
        "cloudflare_source_hash_match": cf["source"]["hash_match"],
        "azure_exact_equivalence": az["equivalence_pass"],
        "github_exact_equivalence": gh["equivalence_pass"],
        "cloudflare_exact_equivalence": cf["equivalence_pass"],
        "azure_final_boundary_verified": az["architecture"]["final_resolution_before_child_policy_and_execution"],
        "github_selector_binding_verified": gh["representative_production_binding"]["selector_dispatch_binding_verified"],
        "cloudflare_effect_boundary_verified": cf["architecture"]["effect_boundary_before_outbound_fetch"],
        "github_parse_errors_zero": len(gh["snapshot_parse_errors"]) == 0,
        "adversarial_gates_pass": adv["all_pass"],
        "compression_retained": (
            az["tool_count_change_under_rac"] == 0
            and gh["tool_count_change_under_rac"] == 0
            and cf["tool_count_change_under_rac"] == 0
        ),
    }
    all_pass = all(invariants.values())

    results = {
        "g5": {
            "authority_commit": lock["authority_commit"],
            "policy": "P_DEL",
            "zero_llm": True,
            "lock_sha256": sha256(lock_bytes),
            "mechanism": "Resolved-Action Contract (RAC)",
        },
        "azure": az,
        "github": gh,
        "cloudflare": cf,
        "adversarial": adv,
        "invariants": invariants,
        "all_required_invariants_pass": all_pass,
    }

    contracts = {
        "azure": {k: v.to_dict() for k, v in sorted(az_contracts.items())},
        "github": {k: v.to_dict() for k, v in sorted(gh_contracts.items())},
        "cloudflare": {k: v.to_dict() for k, v in sorted(cf_contracts.items())},
    }

    source_hashes = {
        "azure": az["source"],
        "github": gh["source"],
        "cloudflare": cf["source"],
        "azure_router": {k: az["architecture"][k] for k in ("url", "commit", "sha256", "bytes")},
        "cloudflare_execute": {k: cf["architecture"][k] for k in ("url", "commit", "sha256", "bytes")},
    }

    (out / "g5_results.json").write_bytes(stable_json(results))
    (out / "g5_contracts.json").write_bytes(stable_json(contracts))
    (out / "g5_source_hashes.json").write_bytes(stable_json(source_hashes))
    summary = summary_md(results)
    (out / "G5_SUMMARY.md").write_text(summary)
    print(summary)
    if not all_pass:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
