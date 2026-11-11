"""Counterexample-oriented gates: refuse an unsupported inference even on plausible inputs."""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from claim_gate import (load, audit_evidence, complaint_fraction_bounds,
                        tie_boundary_status, metric_compatibility, slope_equivalence,
                        SUPPORT, CONDITIONAL, PENDING, BLOCKED)

class EvidenceGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest,cls.e=load(ROOT)
        cls.out=audit_evidence(cls.e,cls.manifest)
        cls.claims={x['claim_id']:x for x in cls.out['claim_ledger']}

    def test_source_manifest_cryptographic_integrity(self):
        self.assertEqual(len(self.manifest['inputs']), 5)
        self.assertTrue(all(len(x['sha256'])==64 for x in self.manifest['inputs'].values()))

    def test_corrupted_input_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            dst=Path(temp)/'evidence'; dst.mkdir()
            for p in (ROOT/'evidence').iterdir():
                (dst/p.name).write_bytes(p.read_bytes())
            path=dst/'boundary_support.json';path.write_bytes(path.read_bytes()+b'\n')
            with self.assertRaisesRegex(ValueError,'hash mismatch'):
                load(Path(temp))

    def test_2024_overflow_invokes_tie_rule(self):
        v=self.out['audited_years']['2024']['tie_rule_on_current_proxy']
        self.assertEqual(v['candidates_at_or_above'],51)
        self.assertTrue(v['tie_break_required_on_observed_candidate_set'])

    def test_2025_no_overflow_does_not_invoke_tie_rule(self):
        v=self.out['audited_years']['2025']['tie_rule_on_current_proxy']
        self.assertEqual(v['candidates_at_or_above'],50)
        self.assertFalse(v['tie_break_required_on_observed_candidate_set'])

    def test_2025_rank_order_exception_preserved(self):
        self.assertEqual(self.out['audited_years']['2025']['below_boundary']['selected'],1)
        self.assertEqual(self.out['audited_years']['2025']['tied_boundary']['unselected'],1)

    def test_2024_no_selected_below_cutoff(self):
        self.assertEqual(self.out['audited_years']['2024']['below_boundary']['selected'],0)

    def test_equal_score_pairs_are_observed_but_no_full_same_season_support(self):
        self.assertEqual(self.out['audited_years']['2024']['tie_support']['exact_total_score_pairs'],15)
        self.assertEqual(self.out['audited_years']['2025']['tie_support']['exact_total_score_pairs'],13)
        for y in ('2024','2025'):
            self.assertEqual(self.out['audited_years'][y]['tie_support']['selected_buildings_after_same_season_split'],0)

    def test_2025_96_units_missingness_robust_proxy_gap(self):
        cases=self.out['audited_years']['2025']['missingness_robust_proxy_counterexamples']
        self.assertEqual(len(cases),1)
        selected=cases[0]['selected_current_fraction_bounds']
        unselected=cases[0]['unselected_current_fraction_bounds']
        self.assertLess(selected[1],unselected[0])
        self.assertAlmostEqual(selected[1],19/96,places=5)
        self.assertAlmostEqual(unselected[0],2/8,places=5)

    def test_fraction_bounds_invalid_values_fail(self):
        with self.assertRaises(ValueError):
            complaint_fraction_bounds({'current_legal_class_a':0,'two_season_distinct_unit_proxy':1,'unknown_apartment_rows':1})
        with self.assertRaises(ValueError):
            complaint_fraction_bounds({'current_legal_class_a':8,'two_season_distinct_unit_proxy':9,'unknown_apartment_rows':1})

    def test_fraction_bounds_are_not_categorical_legal_violations(self):
        self.assertEqual(self.claims['2025_order_residual']['status'],CONDITIONAL)
        self.assertIn('time-frozen citation register',self.claims['2025_order_residual']['unmet_requirements'])

    def test_earlier_season_equivalence_not_established(self):
        for yr in ('2024','2025'):
            for metric in ('complaints','violations'):
                self.assertFalse(self.out['audited_years'][yr]['matched_pretrend_analysis']['pretrend_equivalence'][metric]['passed'])

    def test_risk_score_balance_rejected(self):
        for yr in ('2024','2025'):
            q=self.out['audited_years'][yr]['matched_pretrend_analysis']
            self.assertFalse(q['risk_balance_passed'])
            self.assertGreater(abs(q['risk_score_smd']),2)

    def test_pretrend_nonrejection_is_not_equivalence(self):
        p={'matched_paired_slope_difference':{'ci95':[-.30,.30]}}
        self.assertFalse(slope_equivalence(p,.15)['passed'])

    def test_equivalence_alone_cannot_unlock_causality(self):
        corrupted=copy.deepcopy(self.e)
        for yr in ('2024','2025'):
            for metric in ('complaints','violations'):
                corrupted['control_pretrends']['years'][yr]['pretrends'][metric]['matched_paired_slope_difference']['ci95']=[-.01,.01]
            corrupted['control_pretrends']['years'][yr]['balance']['log_legal_violation_score']['standardized_difference']=0
        claims={x['claim_id']:x for x in audit_evidence(corrupted,self.manifest)['claim_ledger']}
        self.assertEqual(claims['causal_heat_effect_2024']['status'],BLOCKED)
        self.assertEqual(claims['causal_heat_effect_2025']['status'],BLOCKED)

    def test_attempts_not_completed_inspections(self):
        self.assertFalse(metric_compatibility('attempted_building_visits','completed_inspections'))
        self.assertEqual(self.claims['visits_as_completed_inspections']['status'],BLOCKED)
        self.assertEqual(self.claims['mayor_effort_growth']['status'],SUPPORT)

    def test_complaints_not_indoor_temperature_or_causal_effect(self):
        self.assertFalse(metric_compatibility('reported_complaints','indoor_temperature'))
        self.assertFalse(metric_compatibility('reported_complaints','causal_impact_on_complaints'))
        self.assertEqual(self.claims['comptroller_causal_2025']['status'],BLOCKED)

    def test_all_category_violations_not_heat_citations(self):
        self.assertFalse(metric_compatibility('all_category_violations','confirmed_heat_violations'))

    def test_pluto_taxlot_not_historic_building_unit_denominator(self):
        self.assertEqual(self.claims['pluto_units_historical_truth']['status'],BLOCKED)

    def test_both_years_official_notices_real(self):
        for yr in ('2024','2025'):
            self.assertEqual(self.claims[f'official_cohort_{yr}']['status'],SUPPORT)
            self.assertEqual(self.claims[f'full_historical_decision_reproduced_{yr}']['status'],PENDING)

    def test_2025_three_date_fields_do_not_fix_counterexample(self):
        self.assertEqual(self.claims['case_2025_issue_date_switch']['status'],BLOCKED)
        self.assertEqual(self.e['official_reconciliation']['case_date_test']['cross_season_case_count'],0)

    def test_hist_official_unit_mismatch_not_conflated_with_current(self):
        anomalies=[x for x in self.out['unexplained_residuals'] if x['class']=='official_notice_vs_current_unit_difference']
        self.assertEqual(len(anomalies),1)
        self.assertEqual(anomalies[0]['year'],'2024')

    def test_2025_address_alias_requires_crosswalk(self):
        anomalies=[x for x in self.out['unexplained_residuals'] if x['class']=='official_notice_vs_current_address_nonmatch']
        self.assertEqual(len(anomalies),1)
        self.assertEqual(anomalies[0]['count'],2)

    def test_2025_observed_robust_controversy_not_actually_activated_tie_rule(self):
        self.assertFalse(self.out['audited_years']['2025']['tie_rule_on_current_proxy']['tie_break_required_on_observed_candidate_set'])
        self.assertEqual(len(self.out['audited_years']['2025']['missingness_robust_proxy_counterexamples']),1)

    def test_no_fairness_or_causal_discovery_claim(self):
        self.assertEqual(self.claims['equity_distribution']['status'],BLOCKED)
        self.assertEqual(self.claims['causal_heat_effect_2025']['status'],BLOCKED)

if __name__=='__main__':unittest.main()
