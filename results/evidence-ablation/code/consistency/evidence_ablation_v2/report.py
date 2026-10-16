"""Public, standard-library-only statistics and final-release report."""
import argparse
from collections import Counter
from copy import deepcopy
import csv
import importlib.util
import json
from pathlib import Path

PROFILES=('full','E1_contract','E1_field','E2_binding','E3_effect','E3_delivery','E4_closure')
path=Path(__file__).resolve().parents[1]/'evidence_ablation_v1/report.py'
spec=importlib.util.spec_from_file_location('legacy_statistics',path)
legacy=importlib.util.module_from_spec(spec);spec.loader.exec_module(legacy)
legacy.PROFILES=PROFILES
read,write,metrics,summarize=legacy.read,legacy.write,legacy.metrics,legacy.summarize


def linked_summary(rows):
    parents={r['cluster']:r['cluster'] for r in rows}
    def find(x):
        while parents[x]!=x:
            parents[x]=parents[parents[x]];x=parents[x]
        return x
    groups={}
    for r in rows:
        group=r['response_group']
        if group is not None:
            if group in groups:
                a,b=find(groups[group]),find(r['cluster'])
                if a!=b:parents[max(a,b)]=min(a,b)
            else:groups[group]=r['cluster']
    linked=deepcopy(rows)
    for r in linked:r['cluster']=find(r['cluster'])
    s=summarize(linked)
    return {'original_parent_clusters':len(parents),
            'linked_clusters':len({find(x) for x in parents}),
            'method':'Join parent seeds sharing an actually reused response in the final collection; 5000 paired bootstrap draws, seed 20260920. Conditional on recorded outputs.',
            'profiles':{p:{k:v for k,v in v.items() if k.endswith('_ci95')} for p,v in s['profiles'].items()}}


def generate(root):
    summary,usage=legacy.export(root)
    public=root/'public';rows=read(public/'outcomes.json')
    reference=read(root/'private/retained-outcomes-reference.json')
    retained={ (r['case'],r['profile']):r for r in rows if r['profile'] not in ('E1_contract','E1_field')}
    assert retained=={(r['case'],r['profile']):r for r in reference}, 'Retained predictions or diagnostics changed'
    origins={legacy.token(k):'retained' for k in {r['packet_hash'] for r in read(root/'private/retained-manifest.json') if r['rule']=='Uncertain' and r['input_status']=='ready'}}
    requests=read(public/'request-metrics.json')
    for r in requests:r['origin']=origins.get(r['response_group'],'new_E1')
    write(public/'request-metrics.json',requests)
    usage['by_origin']={}
    for origin in ('retained','new_E1'):
        subset=[r for r in requests if r['origin']==origin]
        usage['by_origin'][origin]={
            'unique_requests':len(subset),'physical_attempts':sum(r['attempts'] for r in subset),
            'tokens':{k:sum(r['usage'][k] for r in subset) for k in ('total_tokens','prompt_tokens','completion_tokens','prompt_cache_hit_tokens')},
            'statuses':dict(Counter(r['api_status'] for r in subset)),
            'rejected_requests':sum(bool(r['screen_errors']) for r in subset)}
    write(public/'usage.json',usage)
    intervals=linked_summary(rows);write(public/'linked-cluster-intervals.json',intervals)
    diagnostics=read(public/'semantic-check-diagnostics.json')
    diagnostic_summary={}
    for profile in ('E1_contract','E1_field'):
        subset=[x for x in diagnostics if x['profile']==profile]
        kinds=Counter();transitions=Counter()
        for x in subset:kinds.update(x['disabled_kinds']);transitions.update(x['disabled_transitions'])
        diagnostic_summary[profile]={'applicable_views':len(subset),
            'views_with_disabled_checks':sum(x['disabled_checks']>0 for x in subset),
            'disabled_checks':sum(x['disabled_checks'] for x in subset),
            'kinds':dict(kinds),'claim_transitions':dict(transitions),
            'case_rule_transitions':dict(Counter(x['full_rule']+' -> '+x['ablated_rule'] for x in subset))}
    write(public/'semantic-check-summary.json',diagnostic_summary)
    collision_groups={}
    manifest=read(root/'private/manifest.json')
    for row in manifest:
        if row['rule']=='Uncertain':
            collision_groups.setdefault(row['packet_hash'],[]).append(row)
    collisions=[{'response_group':legacy.token(key),'views':len(rs),
                 'truth_counts':dict(Counter(r['truth'] for r in rs)),
                 'profiles':dict(Counter(r['profile'] for r in rs))}
                for key,rs in collision_groups.items() if len({r['truth'] for r in rs})>1]
    write(public/'packet-collision-audit.json',{'groups':collisions,'group_count':len(collisions),
          'fallback_views':sum(x['views'] for x in collisions),
          'scope':'Actual model-visible packet collisions, not identity of complete raw execution evidence.'})
    write(public/'experiment.json',{'cases':477,'profiles':list(PROFILES),
          'views':len(rows),'design_entries':477*len(PROFILES),'preflight':read(root/'preflight.json'),
          'reuse':'Full/E2/E3/E4 predictions and original responses retained; only E1 Contract/Field newly inferred',
          'model':'deepseek-v4-flash','temperature':0,'thinking':'disabled','max_tokens':3200,
          'U_counts_as_incorrect':True,'no_new_VM_execution':True})
    lines=['# Final evidence ablation: 477 OpenCode cases','',
           'E1 Contract and E1 Field independently remove semantic information from the same captured executions. Full, E2 Association, E3 State, E3 Delivery, and E4 Closure retain their validated inputs and predictions. Only the two E1 profiles add model requests. This is a retrospective paired study, not a new blind benchmark.','',
           '| Profile | n | Matched Full | Hybrid | Change (pp) | 95% linked-cluster CI (pp) | False C / I | False I / C | U |',
           '|---|---:|---:|---:|---:|---|---:|---:|---:|']
    for profile in PROFILES:
        s=summary['profiles'][profile];m=s['hybrid'];b=s['paired_full_hybrid']
        interval=intervals['profiles'][profile].get('hybrid_paired_accuracy_change_ci95')
        interval_text=f"[{100*interval['lower']:.2f}, {100*interval['upper']:.2f}]" if interval else '—'
        lines.append(f"| {profile} | {m['n']} | {100*b['accuracy']:.2f}% | {100*m['accuracy']:.2f}% | {100*(m['accuracy']-b['accuracy']):+.2f} | {interval_text} | {m['false_C']}/{m['true_I']} | {m['false_I']}/{m['true_C']} | {m['uncertain']} |")
    lines += ['', '## Interpretation boundaries', '',
              '- E1 jointly withdraws supplied semantic metadata and dependent compiled rule checks. It is not merely an LLM-only text deletion. Independent rule violations still determine I; only rule U uses accepted LLM inference.',
              '- Contract and Field overlap in compiled effect checks, which require both operational postconditions and argument/state field roles. They are not orthogonal or exhaustive decompositions of semantic context.',
              '- Field removes schemas and representation/equivalence policies. Tool names, raw field names/values, operational descriptions, program syntax and other surviving clues remain; models may infer semantics from them.',
              '- Semantic-check transitions measure rule dependence, not claim-level truth accuracy. Whole-case judgments can remain unchanged when another independent violation is decisive.',
              '- Cohorts differ. Compare each profile with Full on exactly its applicable cases. A retains historical selection bias; source/observer strata and common-applicability comparisons are included in summary.json.',
              '- Confidence intervals condition on collected responses. They do not model backend drift or repeated LLM sampling. Final linked clusters are recomputed after adding the new actual response-sharing relations; retained point predictions do not change.',
              '- Every failed or rejected model output remains U and is counted as incorrect. There is no answer-dependent retry or sample exclusion.',
              '- Original execution truth, tool calls, raw observations and clocks are unchanged. No VM rerun or new behavior intervention was performed.',
              '', '## Semantic-check coverage', '', '```json', json.dumps(diagnostic_summary,indent=2), '```',
              '', '## Recorded usage', '', '```json', json.dumps(usage,indent=2), '```',
              '', '## Reproduce', '', '`python code/consistency/evidence_ablation_v2/report.py --public .`',
              '', 'This recomputes summary.json and linked-cluster-intervals.json from the public outcomes using only the Python standard library. Raw detector replay additionally needs the lawful original evidence and pinned private dependencies.']
    (public/'RESULTS.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    validation={'passed':True,'retained_views_exact':len(reference),'views':len(rows),
                'profiles':list(PROFILES),'retained_predictions_unchanged':True,
                'parent_clusters':intervals['original_parent_clusters'],'linked_clusters':intervals['linked_clusters']}
    write(root/'statistics-validation.json',validation)
    print(json.dumps(validation),flush=True)


def main():
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path);p.add_argument('--public',type=Path);a=p.parse_args()
    if a.public:
        rows=read(a.public/'outcomes.json')
        assert summarize(rows)==read(a.public/'summary.json')
        assert linked_summary(rows)==read(a.public/'linked-cluster-intervals.json')
        print(json.dumps({'statistics_reproduced':True,'views':len(rows),'profiles':len(PROFILES)}))
    else:generate(a.root)

if __name__=='__main__':main()
