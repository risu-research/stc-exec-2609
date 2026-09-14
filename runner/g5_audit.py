#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ALLOW = "ALLOW"
DENY = "DENY"
STATIC = "STATIC"
TOKENS = {"delete", "remove", "cancel"}


def independent_tokens(value: str) -> list[str]:
    """Independent character-state tokenizer; intentionally does not import rac.py."""
    out: list[str] = []
    buf: list[str] = []
    prev_alnum = ""

    def flush() -> None:
        if buf:
            out.append("".join(buf).lower())
            buf.clear()

    for ch in value:
        if ch.isalnum():
            if (
                buf
                and ch.isupper()
                and prev_alnum
                and (prev_alnum.islower() or prev_alnum.isdigit())
            ):
                flush()
            buf.append(ch)
            prev_alnum = ch
        else:
            flush()
            prev_alnum = ""
    flush()
    return out


def oracle(subject: str) -> str:
    return DENY if TOKENS.intersection(independent_tokens(subject)) else ALLOW


def serialized_decision(contract: dict, identity: str) -> str:
    domain = contract["domain"]
    denied = set(contract["denied"])
    if identity not in domain:
        raise ValueError(f"identity outside serialized domain: {identity}")
    if contract["form"] == STATIC:
        return contract["static_decision"]
    return DENY if identity in denied else ALLOW


def github_subject(identity: str) -> str:
    if "=" not in identity:
        raise ValueError(f"malformed GitHub local identity: {identity}")
    return identity.split("=", 1)[1]


def contract_id(contract: dict) -> str:
    unsigned = {
        "name": contract["name"],
        "form": contract["form"],
        "domain": contract["domain"],
        "denied": contract["denied"],
        "static_decision": contract["static_decision"],
    }
    raw = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def audit_corpus(name: str, corpus_contracts: dict) -> dict:
    checked = 0
    mismatches = []
    malformed = []
    id_mismatches = []

    for tool, contract in sorted(corpus_contracts.items()):
        domain = contract.get("domain") or []
        denied = set(contract.get("denied") or [])
        if len(domain) != len(set(domain)):
            malformed.append({"tool": tool, "reason": "duplicate-domain-identity"})
        if not denied.issubset(set(domain)):
            malformed.append({"tool": tool, "reason": "denied-not-subset-of-domain"})
        if contract_id(contract) != contract.get("contract_id"):
            id_mismatches.append(tool)

        for identity in domain:
            subject = github_subject(identity) if name == "github" else identity
            expected = oracle(subject)
            actual = serialized_decision(contract, identity)
            checked += 1
            if expected != actual:
                mismatches.append({
                    "tool": tool,
                    "identity": identity,
                    "subject": subject,
                    "expected": expected,
                    "actual": actual,
                })

    return {
        "decisions_checked": checked,
        "mismatches": mismatches,
        "malformed_contracts": malformed,
        "contract_id_mismatches": id_mismatches,
        "pass": not mismatches and not malformed and not id_mismatches,
    }


def check_anchors(results: dict) -> dict:
    anchors = {
        "azure": {
            "decisions_checked": 414,
            "exposed_tools_retained": 159,
            "selector_tools": 9,
            "permissive_false_allows": 21,
            "conservative_false_denies": 34,
        },
        "github": {
            "decisions_checked": 87,
            "exposed_tools_retained": 18,
            "selector_tools": 8,
            "permissive_false_allows": 10,
            "conservative_false_denies": 27,
        },
        "cloudflare": {
            "decisions_checked": 3466,
            "exposed_tools_retained": 1,
            "effect_tools": 1,
            "permissive_false_allows": 450,
            "conservative_false_denies": 3016,
        },
    }

    observed = {
        "azure": {
            "decisions_checked": results["azure"]["decisions_checked"],
            "exposed_tools_retained": results["azure"]["exposed_tools_retained"],
            "selector_tools": results["azure"]["contract_forms"]["SELECTOR"],
            "permissive_false_allows": results["azure"]["permissive_static_false_allows"],
            "conservative_false_denies": results["azure"]["conservative_static_false_denies"],
        },
        "github": {
            "decisions_checked": results["github"]["decisions_checked"],
            "exposed_tools_retained": results["github"]["exposed_tools_retained"],
            "selector_tools": results["github"]["contract_forms"]["SELECTOR"],
            "permissive_false_allows": results["github"]["permissive_static_false_allows"],
            "conservative_false_denies": results["github"]["conservative_static_false_denies"],
        },
        "cloudflare": {
            "decisions_checked": results["cloudflare"]["decisions_checked"],
            "exposed_tools_retained": results["cloudflare"]["exposed_tools_retained"],
            "effect_tools": results["cloudflare"]["contract_forms"]["EFFECT"],
            "permissive_false_allows": results["cloudflare"]["permissive_static_false_allows"],
            "conservative_false_denies": results["cloudflare"]["conservative_static_false_denies"],
        },
    }
    return {
        "expected": anchors,
        "observed": observed,
        "pass": observed == anchors,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="out-g5")
    ap.add_argument("--amendment", default="e2eba9dd8be6cbf196ac470c04d0844f2c5ab6ca")
    args = ap.parse_args()

    out = Path(args.out)
    results = json.loads((out / "g5_results.json").read_text())
    contracts = json.loads((out / "g5_contracts.json").read_text())

    audits = {
        name: audit_corpus(name, contracts[name])
        for name in ("azure", "github", "cloudflare")
    }
    anchors = check_anchors(results)
    total_checked = sum(a["decisions_checked"] for a in audits.values())
    all_pass = all(a["pass"] for a in audits.values()) and anchors["pass"]

    report = {
        "g5_1_amendment_commit": args.amendment,
        "oracle_implementation": "independent-character-state-tokenizer",
        "imports_rac_policy_code": False,
        "total_decisions_checked": total_checked,
        "corpus_audits": audits,
        "g4_frozen_anchor_check": anchors,
        "all_independent_audit_invariants_pass": all_pass,
    }

    (out / "G5_INDEPENDENT_AUDIT.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    summary = [
        "# G5.1 independent oracle audit",
        "",
        f"Amendment commit: `{args.amendment}`",
        f"Total independently checked decisions: {total_checked}",
        f"Azure mismatches: {len(audits['azure']['mismatches'])}",
        f"GitHub mismatches: {len(audits['github']['mismatches'])}",
        f"Cloudflare mismatches: {len(audits['cloudflare']['mismatches'])}",
        f"Frozen G4 aggregate anchors match: {anchors['pass']}",
        f"all_independent_audit_invariants_pass: {all_pass}",
    ]
    (out / "G5_INDEPENDENT_AUDIT.md").write_text("\n".join(summary) + "\n")
    print("\n".join(summary))
    if not all_pass:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
