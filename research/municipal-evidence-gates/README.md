# Decision-to-Performance Evidence Gates (HSP, v1)

A reproducible, offline research audit of public selection records and what subsequent performance claims are justified by the available evidence. No model APIs, no network requests, no raw tenant addresses, no third-party participant validation.

## Run

```bash
python src/claim_gate.py
python -m unittest discover -s tests -v
```

Requires Python 3.10+ standard library only. All materialized inputs live in `evidence/`, anchored by SHA-256 checksums in `evidence/manifest.json`. Output `outputs/claim_ledger.json` contains status, specific evidence, and unmet proof requirements for 20 machine-audited claims.

**Provenance:** This package is a *frozen replay of prior successful public-data audit results*, not a new independent scrape of NYC historical candidate-side records. Source runs and original files are identified in the manifest and `papers/RESEARCH_SYNTHESIS_KO.md`.

**What is not claimed:** no attribution of statutory illegality; no complete 2024 or 2025 as-of-decision candidate reconstruction; no causal impact estimate; no proven distributional inequity. HSP treatment is a package of sensor installation, monitoring, and reporting obligations rather than a sensor-only effect.

The `tests/` suite deliberately tries to promote invalid administrative observations into stronger legal/causal claims; tests pass only when these promotions are rejected.

## Key findings

- 2024: 35 buildings with a higher proxy score than nine, 16 tied at nine. This produces 51 candidates for 50 slots and activates the tie-priority condition in the observed reconstruction.
- 2025: 36 strictly higher, 14 tied. Exactly 50 candidates are at/above nine, so tie priority is not the primary discrepancy. A selected eight-citation case replaces an unselected nine-citation candidate in observed records.
- At the exact-score boundary, the total-score comparisons produce 15 / 13 candidate pairs in 2024/25, respectively. When both seasons' violation counts also must match after location, size, and complaint-fraction restrictions, neither year yields a pair.
- Missing apartment-label bound (conditional on current denominator): one selected 2025 building has at most 19/96 complainant units; its unselected nine-citation counterpart has at least 2/8. These are not statutory as-of-decision shares.
- Public reports: attempted monitoring visits are an effort indicator; tenant complaints and legally found violations are distinct administrative measures. Earlier complaints reductions should not be read as a newly identified causal treatment effect.

## Core files

- `evidence/*.json`: immutable data files from prior audited pipelines plus dated official report measurements.
- `src/claim_gate.py`: evidence provenance, legal tie-rule conditions, missingness-bound comparisons, control overlap, claim-admissibility gates.
- `tests/test_claim_gate.py`: adversarial and mutation regression tests.
- `outputs/claim_ledger.json`: machine-generated claims and unresolved proof dependencies.
- `papers/RESEARCH_SYNTHESIS_KO.md`: manuscript strategy, formal limits, methods and official sources.
- `papers/PPMR_ABSTRACT_EN.md`: practical EOI draft, not submitted.
