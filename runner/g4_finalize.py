#!/usr/bin/env python3
"""Identity-only G4.3 postprocessor.

The primary extractor intentionally retains raw, auditable enum strings. This
postprocessor applies the pre-frozen GitHub tool-local identity clarification
without changing P_DEL classification, population, collisions, or membership
metrics.
"""
import json
from pathlib import Path

OUT = Path("out")
p = OUT / "results.json"
r = json.loads(p.read_text())
gh = r["github_mcp"]

# Each qualifying dispatcher alternative is local to exactly one tool/dimension.
# Therefore canonical alternative identities are the explicit alternatives,
# even when bare enum strings repeat in different tools.
explicit = gh["explicit_dispatcher_alternatives"]
coll_members = gh["memberships_inside_colliding_tools"]
restricted = gh["restricted_memberships_inside_colliding_tools"]
nonrestricted = gh["nonrestricted_memberships_inside_colliding_tools"]

gh["raw_unqualified_unique_enum_strings"] = gh["unique_source_action_ids"]
gh["unique_source_action_ids"] = explicit
gh["unique_action_to_tool_ratio"] = explicit / gh["exposed_tools"] if gh["exposed_tools"] else None
gh["unique_action_ids_exposed_by_colliding_tools"] = coll_members
gh["unique_collision_action_exposure"] = coll_members / explicit if explicit else None
gh["unique_restricted_action_ids_in_collisions"] = restricted
gh["unique_nonrestricted_action_ids_in_collisions"] = nonrestricted
gh["action_identity"] = "tool-local triple (tool_name, dispatcher_property, enum_value)"
gh["pdel_classification_basis"] = "enum_value only; unchanged from G4 constitution"

p.write_text(json.dumps(r, indent=2, sort_keys=True) + "\n")

lines = [
    "# G4 FINAL deterministic census summary",
    "",
    f"Authority commit: `{r['g4']['authority_commit']}`",
    "Policy: P_DEL = ['cancel', 'delete', 'remove']",
    "Exposure model: relation E subseteq A x T",
    "Zero LLM: true",
    "",
]
for key, label in (
    ("azure", "Azure full consolidated census"),
    ("github_mcp", "GitHub schema-dispatch census"),
    ("cloudflare", "Cloudflare reconstructed official-seed census"),
):
    x = r[key]
    lines += [
        f"## {label}",
        f"- source_action_memberships: {x['source_action_memberships']}",
        f"- unique_source_action_ids: {x['unique_source_action_ids']}",
        f"- exposed_tools: {x['exposed_tools']}",
        f"- membership_density: {x['membership_density']}",
        f"- colliding_tools: {x['colliding_tools']}",
        f"- collision_tool_rate: {x['collision_tool_rate']}",
        f"- collision_membership_exposure: {x['collision_membership_exposure']}",
        f"- permissive_exposure_membership_rate: {x['permissive_exposure_membership_rate']}",
        f"- conservative_overhead_membership_rate: {x['conservative_overhead_membership_rate']}",
        "",
    ]
lines += [
    "## Stripe contemporaneous corroborative case",
    f"- current_dynamic_source_sha256: {r['stripe']['source']['sha256']}",
    f"- matches_first_raw_fetch: {r['stripe']['source']['hash_matches_first_fetch']}",
    f"- documented_read_write_routing_detected: {r['stripe']['documented_read_write_routing_detected']}",
    "- full_action_weighted_metrics_status: UNRESOLVED",
    "- role: excluded from primary quantitative invariants due dynamic raw HTML representation",
    "",
    "## Required invariants",
]
for k, v in r["invariants"].items():
    lines.append(f"- {k}: {v}")
lines.append(f"- all_required_invariants_pass: {r['all_required_invariants_pass']}")
(OUT / "FINAL_SUMMARY.md").write_text("\n".join(lines) + "\n")
print((OUT / "FINAL_SUMMARY.md").read_text())
