#!/usr/bin/env python3
"""HSP decision-to-performance evidence gate, v1.0.

This is an AUDIT OF ALLOWED INFERENCES, not a causal estimator.
Works offline on prior independently executed, hashed NYC public-data audits.
Never reaches external websites, never modifies source evidence.
"""
import argparse
import hashlib
import json
from pathlib import Path

SUPPORT = 'supported_at_declared_scope'
CONDITIONAL = 'supported_as_current_proxy_only'
PENDING = 'requires_additional_historical_evidence'
BLOCKED = 'not_identified_from_supplied_evidence'


def load(root: Path, strict_hash: bool = True):
    evidence = root / 'evidence'
    manifest = json.loads((evidence / 'manifest.json').read_text(encoding='utf-8'))
    data = {}
    for filename, spec in manifest['inputs'].items():
        blob = (evidence / filename).read_bytes()
        if strict_hash and hashlib.sha256(blob).hexdigest() != spec['sha256']:
            raise ValueError('Evidence hash mismatch: ' + filename)
        data[filename.removesuffix('.json')] = json.loads(blob)
    return manifest, data


def complaint_fraction_bounds(item):
    """Under *current* units and at most one new distinct unit per unknown row.

    This bound assumes each unknown row can at most add one dwelling unit;
    known distinct apartment labels are treated as valid and distinct.
    Not a bound on the actual historical official selection percentage.
    """
    n = int(item['current_legal_class_a'])
    k = int(item['two_season_distinct_unit_proxy'])
    missing = int(item['unknown_apartment_rows'])
    if n <= 0 or k < 0 or missing < 0 or k > n:
        raise ValueError('Invalid apartment-count bounds input')
    return (k/n, min(n, k+missing)/n)


def tie_boundary_status(cutoff, above, tied):
    """A legal tie-break is potentially triggered if more than 50 are at/above boundary."""
    n = int(above) + int(tied)
    return {'candidates_at_or_above':n, 'slots_open_to_ties':50-int(above),
            'tie_break_required_on_observed_candidate_set':n>50}


def slope_equivalence(pretrend, margin):
    ci = pretrend.get('matched_paired_slope_difference', {}).get('ci95')
    if ci is None:
        return {'passed':False, 'reason':'No interval'}
    lo, hi = ci
    return {'passed':(-margin < lo and hi < margin), 'ci95':ci,
            'note':'Exploratory normal CI may be optimistic due to control reuse; never sufficient for causal proof.'}


def metric_compatibility(metric, claim):
    types = {
        'attempted_building_visits':{'attempted_building_visits'},
        'completed_inspections':{'completed_inspections'},
        'reported_complaints':{'reported_complaints'},
        'confirmed_heat_violations':{'confirmed_heat_violations'},
        'all_category_violations':{'all_category_violations'},
        'indoor_temperature':{'indoor_temperature'},
        'causal_impact_on_temperature':set(),
        'causal_impact_on_complaints':set(),
    }
    if claim not in types:
        raise ValueError('Unknown claim type: ' + claim)
    return metric in types[claim]


def audit_evidence(data, manifest):
    rec = data['official_reconciliation']
    boundary = data['boundary_support']
    control = data['control_pretrends']
    ext = data['external_claims']
    reg = data['registry_crosscheck']
    assert set(boundary['years']) == {'2024','2025'}
    claim_rows=[]
    anomalies=[]
    annual={}
    def claim(id, tier, statement, status, inputs, needed=None, rationale=None):
        claim_rows.append({'claim_id':id,'tier':tier,'statement':statement,
            'status':status, 'supporting_evidence':inputs,
            'unmet_requirements':needed or [], 'rationale':rationale})
    for year in ['2024','2025']:
        r=rec['official_pdfs'][year]
        b=boundary['years'][year]
        p=control['years'][year]
        primary=b['source_eligible_primary']
        sel=b['selected_in_eligible_primary']
        cut=b['rank50_score_primary']
        above=b['above_cutoff']
        tied=b['at_cutoff']
        below=b['below_cutoff']
        assert r['rows']==50, f'Official published {year} row count unexpected'
        assert rec['selected_cohort_rows'][year] == 50
        assert above['total']+tied['total']+below['total']==primary
        assert above['selected']+tied['selected']+below['selected']==sel
        assert cut == 9, f'{year} frozen observed threshold changed; verify provenance'
        q=tie_boundary_status(cut,above['total'],tied['total'])
        support=b['matched_tie_support']
        pairs=support['pair_gate_counts']
        exact = pairs['exact_risk_score']
        all_gates=support['distinct_selected_after_all_gates']
        strict=support['all_gates_with_same_season_counts_selected']
        assert strict<=all_gates<=exact
        assert exact==tied['selected']*tied['unselected']
        assert len([v for v in b['tie_cases_pseudonymous'] if v['selected']]) == tied['selected']
        unknown_unit_labels=0
        strict_order={'selected_certainly_outscores_unselected':0,
                      'unselected_certainly_outscores_selected':0,
                      'order_undetermined_under_missing_label_bounds':0}
        robust_cases=[]
        unselected=[v for v in b['tie_cases_pseudonymous'] if not v['selected']]
        for a in (t for t in b['tie_cases_pseudonymous'] if t['selected']):
            al,ah=complaint_fraction_bounds(a)
            unknown_unit_labels += a['unknown_apartment_rows']
            for u in unselected:
                ul,uh=complaint_fraction_bounds(u)
                if al>uh:
                    strict_order['selected_certainly_outscores_unselected']+=1
                elif ah<ul:
                    strict_order['unselected_certainly_outscores_selected']+=1
                    robust_cases.append({'selected_alias':a['case'],'unselected_alias':u['case'],
                        'selected_current_fraction_bounds':[round(al,6),round(ah,6)],
                        'unselected_current_fraction_bounds':[round(ul,6),round(uh,6)]})
                else:
                    strict_order['order_undetermined_under_missing_label_bounds']+=1
        assert sum(strict_order.values())==exact
        margin=control['prespecified_matching_calipers']['heldout_slope_equivalence_tolerance_log_rate_per_season']
        pretrend={lab:slope_equivalence(p['pretrends'][lab],margin) for lab in ('complaints','violations')}
        risk_smd=p['balance']['log_legal_violation_score']['standardized_difference']
        standard=control['prespecified_matching_calipers']['max_baseline_absolute_standardized_mean_difference']
        assert isinstance(risk_smd,(int,float))
        annual[year]={
            'official_published_list_rows':r['rows'],'source_eligible_current_proxy':primary,
            'selected_current_proxy':sel,'selected_share_of_proxy_pool':round(sel/primary,5),
            'address_matches_to_current_api':r['address_matches'],
            'current_notice_unit_discrepancy_count':len(r['current_HSP_unit_mismatches']),
            'official_address_unmatched_count':len(r['official_unmatched']),
            'rank50_proxy':cut,'above_boundary':above,'tied_boundary':tied,'below_boundary':below,
            'tie_rule_on_current_proxy':q,
            'tie_support':{'exact_total_score_pairs':exact,'same_borough_pairs':pairs.get('plus_same_borough',0),
                'same_borough_and_size_pairs':pairs.get('plus_unit_factor_two',0),
                'with_tie_fraction_nearness_pairs':pairs.get('plus_complaint_fraction_10pp',0),
                'selected_buildings_after_all_nearness_gates':all_gates,
                'selected_buildings_after_same_season_split':strict,
                'different_season_vector_count_after_all_gates':sum(not v['same_season_counts'] for v in support['complete_pair_aliases'])},
            'tie_fraction_partial_order_current_denominator':strict_order,
            'missingness_robust_proxy_counterexamples':robust_cases,
            'matched_pretrend_analysis':{'selected_eligible':p['selected_eligible_with_borough'],
                'matched':p['treated_matched'],'distinct_controls':p['distinct_matched_control_buildings'],
                'risk_score_smd':risk_smd,'risk_balance_passed':abs(risk_smd)<=standard,
                'pretrend_equivalence':pretrend}
        }
        if r['current_HSP_unit_mismatches']:
            anomalies.append({'year':year,'class':'official_notice_vs_current_unit_difference',
                'count':len(r['current_HSP_unit_mismatches']),
                'label':'The historical notice and current HSP unit totals differ, without evidence yet of which records changed or when',
                'additional_proofs':['historical building registration snapshot', 'document-as-of census crosswalk']})
        if r['official_unmatched']:
            anomalies.append({'year':year,'class':'official_notice_vs_current_address_nonmatch',
                'count':len(r['official_unmatched']),
                'label':'Conservative address key mismatch; may be alias/typo and does not imply different physical building',
                'additional_proofs':['historic BIN/BBL/building identification and address alias verification']})
        if below['selected']:
            anomalies.append({'year':year,'class':'selected_below_observed_cutoff',
                'count':below['selected'],'label':'observed selection-order residual, not verified statutory violation',
                'additional_proofs':['time-frozen legal violation register','historical eligibility/exemption register',
                                     'administrative scoring ledger','other selection criteria under 56-02(a)']})
        if robust_cases:
            anomalies.append({'year':year,'class':'robust_under_unknown_apartment_rows_only',
                'count':len(robust_cases),'cases':robust_cases,
                'label':'sensitivity bound conditional on CURRENT Class A denominator and current apartment labels; statutory tie-break only if overflow',
                'additional_proofs':['historical legal Class A unit denominator','time-frozen unit-level complaint coding','administrative tie-breaking applicability']})
        claim(f'official_cohort_{year}','decision','Official HPD published list contains 50 selected entries',SUPPORT,
            ['official_reconciliation'],rationale='Published list identifies decisions, not scored candidate universe')
        claim(f'current_boundary_{year}','decision',f'Current-public-data proxy threshold is {cut} citations',CONDITIONAL,
            ['boundary_support'],needed=['historical frozen all-candidate inputs','formal exclusions recorded as of decision'],
            rationale='Legal score code from free-text description, does not verify historical administrative ranking')
        claim(f'full_historical_decision_reproduced_{year}','decision',
            'Full as-of-year administrative selection independently reproduced',PENDING,
            ['official_reconciliation','boundary_support'],
            needed=['decision-time candidate universe','original scoring ledger','all 7A and in-rem statuses','unit-level numerator and denominator versions'])
        claim(f'nearby_equal_risk_controls_{year}','comparability','Exact-score and seasonal vector matched control group with full proximity',BLOCKED,
            ['boundary_support'], needed=['same-season-vector comparison pairs under predeclared proximity conditions'],
            rationale=f'Only {strict} selected buildings have such a pair; requires positive overlap')
        claim(f'causal_heat_effect_{year}','causal','Heat Sensor Program causal effect on heat hardship or tenant complaints',BLOCKED,
            ['control_pretrends','boundary_support','external_claims'],
            needed=['defensible counterfactual and overlap','historical treatment assignment','supported pretrend/sensitivity analysis',
                    'separation of inspection detection, complaint reporting and indoor temperature'])
    assert annual['2025']['below_boundary']['selected'] == 1, '2025 selected-below-9 residual changed; review the frozen baseline'
    assert rec['case_date_test']['qualifying_legal_code_proxy_total'] == 8, '2025 8-citation case changed; re-audit the official API'
    dates=rec['case_date_test']['counts_by_heating_season_and_field']
    date_equal=all(len(set(dates[y].values()))==1 for y in dates)
    assert date_equal
    assert rec['case_date_test']['cross_season_case_count']==0
    claim('case_2025_issue_date_switch','exception',
        '2025 8-citation selected case can be reconciled by substituting notice, inspection or approval date',BLOCKED,
        ['official_reconciliation'], needed=['alternative documented admissible citation set or frozen registration history'],
        rationale='Each of the three date columns yields 3+5 relevant citations within the same two seasons')
    claim('2025_order_residual','exception','One 2025 published selected building falls below observed proxy threshold 9',CONDITIONAL,
        ['boundary_support','official_reconciliation'],needed=['time-frozen citation register','documented inclusion/exclusion decisions'],
        rationale='Observed ranking mismatch is not proof of legal misconduct; 56-02(a) permits additional criteria')
    assert ext['mayor_pmmr_2026']['visits_attempted_prior']==181
    assert ext['mayor_pmmr_2026']['visits_attempted_current']==251
    diff=(251-181)/181
    claim('mayor_effort_growth','performance',
        'HSP proactive attempted building visits rose from 181 to 251 for the first four fiscal months',SUPPORT,
        ['external_claims'],rationale=f'Administrative effort change {diff:.2%}; explicitly attempted visits, not completed inspections')
    claim('visits_as_completed_inspections','performance',
        'Attempted visits prove that 251 inspections were completed',BLOCKED,
        ['external_claims'],needed=['completed visit outcomes or documented attempt-to-completion rate'])
    claim('comptroller_descriptive_2025','performance',
        'Comptroller reported a 46% average reduction in complaints after earlier-program activation',SUPPORT,
        ['external_claims'],rationale='This reports another office’s descriptive finding, not independent replication by the present audit')
    claim('comptroller_causal_2025','causal',
        'Reported 46% fewer complaints identifies the counterfactual causal effect of HSP',BLOCKED,
        ['external_claims','control_pretrends'],needed=['credible comparison/assignment design','population and time alignment',
            'response to reporting selection and mean reversion','sampling uncertainty'])
    claim('observed_changes_indoor_heat','performance',
        'A decline in complaints and/or a rise in recorded violations proves true indoor temperatures improved',BLOCKED,
        ['external_claims'],needed=['quality-controlled physical temperature panel or defensible thermal outcome proxy',
            'tenant reporting and inspection/ascertainment adjustments'])
    claim('equity_distribution','equity',
        'Equal protection or equitable distribution of enhanced heat enforcement across vulnerability groups established',BLOCKED,
        ['boundary_support'],needed=['complete legally eligible denominator by subgroup','stable vulnerability measure',
        'historical subgroup population and treatment assignment','distribution of implementation burden and remedy'])
    claim('pluto_units_historical_truth','history',
        'Current PLUTO tax-lot UnitsRes proves historical building-level legal unit count',BLOCKED,
        ['official_reconciliation','registry_crosscheck'],needed=['actual 2024/25 building-specific registration records','historical parcel-to-building crosswalk'])
    claim('historical_notices_current_diff','history',
        'Official historic notices differ from present public records on some addresses/unit totals',SUPPORT,
        ['official_reconciliation','registry_crosscheck'],rationale='Observed document-vs-current snapshot variation, not proven as-of-year original administrative error')
    return {'framework_name':'Decision-to-Performance Evidence Gates',
            'version':'1.0','observations':'Prior successful recorded public-data audits plus current official reporting; static replay',
            'source_manifest':manifest['anchors'],'audited_years':annual,
            'unexplained_residuals':anomalies,'metric_claim_checks':{
                'attempted_visits_can_prove_completed_inspections':metric_compatibility('attempted_building_visits','completed_inspections'),
                'reported_complaints_can_prove_indoor_temperature':metric_compatibility('reported_complaints','indoor_temperature'),
                'all_category_violations_can_prove_heat_specific_violations':metric_compatibility('all_category_violations','confirmed_heat_violations'),
                'reported_complaints_can_prove_causal_effect':metric_compatibility('reported_complaints','causal_impact_on_complaints')},
            'official_attempted_visits_change_percent':round(100*diff,2),
            'claim_ledger':claim_rows,
            'limitations':['Point-in-time CURRENT API reconstruction, not an archival 2024/25 legal classification',
                'Selection tie priority is triggered by an excess of eligible candidates at the threshold, not every numerical tie',
                'Intervals for missing apartment labels are conditional on the current denominator, source-proxy validity, and maximum one newly identified unit per unknown complaint row',
                'Public snapshots do not identify individual agency discretion or establish erroneous selection',
                'No estimate of treatment impact is generated; unsupported claims are machine-blocked']}


def main(argv=None):
    p=argparse.ArgumentParser()
    p.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1])
    p.add_argument('--out',type=Path)
    a=p.parse_args(argv)
    manifest,data=load(a.root)
    result=audit_evidence(data,manifest)
    out=a.out or a.root/'outputs'/'claim_ledger.json'
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2,ensure_ascii=False,sort_keys=True)+'\n',encoding='utf-8')
    print('RUN_SUCCESS',len(result['claim_ledger']),'claims',len(result['unexplained_residuals']),'exception classes')
    for y,x in result['audited_years'].items():
        print(y,'cutoff=',x['rank50_proxy'],'tie_needed=',x['tie_rule_on_current_proxy']['tie_break_required_on_observed_candidate_set'],
              'exact_pairs=',x['tie_support']['exact_total_score_pairs'],
              'all_gates_pairs=',x['tie_support']['selected_buildings_after_all_nearness_gates'],
              'same_season_pairs=',x['tie_support']['selected_buildings_after_same_season_split'],
              'conditional_missed=',x['below_boundary']['selected'])
    print('ARTIFACT',out)
    return result


if __name__=='__main__':
    main()
