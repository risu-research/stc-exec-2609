#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import urllib.request
import zipfile
from pathlib import Path

UA = "stc-exec-2609-g5-binding/1.0 (+https://github.com/risu-research/stc-exec-2609)"


def fetch(url: str, timeout: int = 240) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def marker_report(text: str, markers: dict[str, str]) -> dict:
    positions = {name: text.find(value) for name, value in markers.items()}
    return {
        "positions": positions,
        "all_present": all(pos >= 0 for pos in positions.values()),
    }


def azure_binding(lock: dict) -> dict:
    commit = lock["azure_commit"]
    base = f"https://raw.githubusercontent.com/microsoft/mcp/{commit}/"
    paths = {
        "discovery": "core/Microsoft.Mcp.Core/src/Areas/Server/Commands/Discovery/ConsolidatedToolDiscoveryStrategy.cs",
        "command_group": "core/Microsoft.Mcp.Core/src/Commands/CommandGroup.cs",
        "loader": "core/Microsoft.Mcp.Core/src/Areas/Server/Commands/ToolLoading/NamespaceToolLoader.cs",
    }
    raws = {k: fetch(base + p) for k, p in paths.items()}
    texts = {k: raw.decode("utf-8", errors="strict") for k, raw in raws.items()}

    discovery = marker_report(texts["discovery"], {
        "membership_uses_dictionary_key": "consolidatedTool.MappedToolList.Contains(kvp.Key, StringComparer.OrdinalIgnoreCase)",
        "matching_dictionary_preserves_key": ".ToDictionary(kvp => kvp.Key, kvp => kvp.Value);",
        "consolidated_group_adds_same_key": "commandGroup.AddCommand(cmd.Key, cmd.Value);",
    })
    command_group = marker_report(texts["command_group"], {
        "direct_path_stored_as_key": "Commands[path] = command;",
    })
    loader = marker_report(texts["loader"], {
        "runtime_dictionary_from_namespace": "namespaceCommands = _commandFactory.GroupCommands([namespaceName]);",
        "final_command_lookup": "namespaceCommands.TryGetValue(command, out var cmd)",
        "fallback_resolution": "GetCommandAndParametersFromIntentAsync",
        "child_elicitation": "HandleElicitationAsync",
        "child_execute": "cmd.ExecuteAsync",
    })
    p = loader["positions"]
    ordering = (
        loader["all_present"]
        and p["fallback_resolution"] < p["final_command_lookup"]
        and p["final_command_lookup"] < p["child_elicitation"] < p["child_execute"]
    )
    all_pass = discovery["all_present"] and command_group["all_present"] and ordering

    return {
        "commit": commit,
        "files": {
            key: {"path": paths[key], "sha256": sha256(raws[key]), "bytes": len(raws[key])}
            for key in paths
        },
        "discovery_key_chain": discovery,
        "command_group_key_chain": command_group,
        "runtime_loader_chain": loader,
        "post_resolution_policy_before_execute_order": ordering,
        "all_azure_runtime_identity_links_pass": all_pass,
    }


def raw_selector_values(contract: dict) -> list[str]:
    values = []
    for identity in contract["domain"]:
        if "=" not in identity:
            raise ValueError(f"malformed GitHub identity: {identity}")
        values.append(identity.split("=", 1)[1])
    return values


def find_tool_source(go_files: dict[str, str], tool: str) -> list[str]:
    exact = re.compile(r'Name\s*:\s*"' + re.escape(tool) + r'"')
    return sorted(path for path, text in go_files.items() if exact.search(text))


def bind_value_in_source(text: str, value: str) -> dict:
    quoted = re.escape(json.dumps(value))
    # Find named constants whose literal value is exactly this selector value.
    const_names = re.findall(r'(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*' + quoted + r'\s*$', text)
    constant_evidence = []
    for const in const_names:
        uses = len(re.findall(r'\b' + re.escape(const) + r'\b', text))
        dispatch = bool(re.search(r'case\s+[^:\n]*\b' + re.escape(const) + r'\b[^:\n]*:', text))
        comparison = bool(re.search(r'(?:==|!=)\s*' + re.escape(const) + r'\b', text))
        constant_evidence.append({
            "constant": const,
            "uses": uses,
            "dispatch_case": dispatch,
            "comparison": comparison,
            "bound": uses >= 2 and (dispatch or comparison),
        })

    literal_count = len(re.findall(quoted, text))
    direct_case = bool(re.search(r'case\s+[^:\n]*' + quoted + r'[^:\n]*:', text))
    direct_comparison = bool(re.search(r'(?:==|!=)\s*' + quoted, text))
    direct_bound = literal_count >= 2 and (direct_case or direct_comparison)

    bound = direct_bound or any(e["bound"] for e in constant_evidence)
    return {
        "value": value,
        "literal_occurrences": literal_count,
        "direct_dispatch_case": direct_case,
        "direct_comparison": direct_comparison,
        "constants": constant_evidence,
        "bound": bound,
    }


def github_binding(lock: dict, contracts: dict) -> dict:
    commit = lock["github_mcp_commit"]
    url = f"https://codeload.github.com/github/github-mcp-server/zip/{commit}"
    raw = fetch(url)
    source_hash_match = sha256(raw) == lock["github_mcp_sha256"]
    go_files: dict[str, str] = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        for name in z.namelist():
            if "/pkg/github/" not in name or not name.endswith(".go"):
                continue
            if name.endswith("_test.go"):
                continue
            go_files[name] = z.read(name).decode("utf-8", errors="replace")

    mixed = {name: c for name, c in contracts.items() if c["form"] == "SELECTOR"}
    tool_reports = {}
    for tool, contract in sorted(mixed.items()):
        candidates = find_tool_source(go_files, tool)
        candidate_reports = []
        for path in candidates:
            text = go_files[path]
            value_reports = [bind_value_in_source(text, v) for v in raw_selector_values(contract)]
            candidate_reports.append({
                "path": path,
                "sha256": sha256(text.encode()),
                "all_values_bound": all(v["bound"] for v in value_reports),
                "values": value_reports,
            })
        passing = [r for r in candidate_reports if r["all_values_bound"]]
        tool_reports[tool] = {
            "source_candidates": candidate_reports,
            "passing_source_count": len(passing),
            "pass": len(passing) >= 1,
        }

    return {
        "commit": commit,
        "zip_sha256": sha256(raw),
        "zip_hash_matches_g5_lock": source_hash_match,
        "mixed_selector_tools": len(mixed),
        "tool_reports": tool_reports,
        "all_mixed_selector_tools_bound": source_hash_match and all(r["pass"] for r in tool_reports.values()),
    }


def cloudflare_binding(lock: dict) -> dict:
    commit = lock["cloudflare_mcp_commit"]
    url = f"https://raw.githubusercontent.com/cloudflare/mcp/{commit}/src/tools/execute.ts"
    raw = fetch(url)
    text = raw.decode("utf-8", errors="strict")
    markers = {
        "request_boundary": "async request(options)",
        "extract_method_path": "const { method, path, query, body, contentType, rawBody } = options;",
        "url_from_same_path": "const url = new URL(apiBase + path);",
        "outbound_fetch": "const response = await fetch(url.toString(), {",
    }
    report = marker_report(text, markers)
    p = report["positions"]
    ordered = (
        report["all_present"]
        and p["request_boundary"] < p["extract_method_path"] < p["url_from_same_path"] < p["outbound_fetch"]
    )
    fetch_start = p["outbound_fetch"] if p["outbound_fetch"] >= 0 else 0
    fetch_window = text[fetch_start:fetch_start + 500]
    method_forwarded = bool(re.search(r'\{\s*\n?\s*method\s*,', fetch_window)) or "method," in fetch_window
    all_pass = ordered and method_forwarded
    return {
        "commit": commit,
        "url": url,
        "sha256": sha256(raw),
        "bytes": len(raw),
        "markers": report,
        "ordered_method_path_to_fetch": ordered,
        "same_method_forwarded_to_fetch": method_forwarded,
        "all_cloudflare_effect_binding_links_pass": all_pass,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lock", default="config/g5_lock.json")
    ap.add_argument("--out", default="out-g5")
    ap.add_argument("--amendment", default="4c505ab73d14a0708dfdc0f8d80ac60011fd37a9")
    args = ap.parse_args()

    lock = json.loads(Path(args.lock).read_text())
    out = Path(args.out)
    contracts = json.loads((out / "g5_contracts.json").read_text())

    azure = azure_binding(lock)
    github = github_binding(lock, contracts["github"])
    cloudflare = cloudflare_binding(lock)
    all_pass = (
        azure["all_azure_runtime_identity_links_pass"]
        and github["all_mixed_selector_tools_bound"]
        and cloudflare["all_cloudflare_effect_binding_links_pass"]
    )
    report = {
        "g5_2_amendment_commit": args.amendment,
        "zero_llm": True,
        "azure": azure,
        "github": github,
        "cloudflare": cloudflare,
        "all_runtime_identity_binding_invariants_pass": all_pass,
    }
    (out / "G5_RUNTIME_BINDING_AUDIT.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    lines = [
        "# G5.2 runtime identity-binding audit",
        "",
        f"Amendment commit: `{args.amendment}`",
        f"Azure full key-preservation chain: {azure['all_azure_runtime_identity_links_pass']}",
        f"GitHub mixed selector tools bound: {sum(r['pass'] for r in github['tool_reports'].values())}/{github['mixed_selector_tools']}",
        f"Cloudflare method/path effect boundary bound: {cloudflare['all_cloudflare_effect_binding_links_pass']}",
        f"all_runtime_identity_binding_invariants_pass: {all_pass}",
    ]
    (out / "G5_RUNTIME_BINDING_AUDIT.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    if not all_pass:
        for tool, r in github["tool_reports"].items():
            if not r["pass"]:
                print(f"UNBOUND_GITHUB_TOOL: {tool}")
        raise SystemExit(2)


if __name__ == "__main__":
    main()
