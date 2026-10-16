"""Export deidentified outcomes and reproducible paired/clustered statistics."""
import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import itertools
import json
from pathlib import Path
import random

PROFILES=('full','E1_context','E2_binding','E3_effect','E3_delivery','E4_closure')

def read(p):return json.loads(Path(p).read_text(encoding='utf-8-sig'))
def write(p,v):
    p=Path(p);p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(json.dumps(v,ensure_ascii=False,sort_keys=True,indent=2)+'\n')
def token(s):return hashlib.sha256(('public-ablation/'+s).encode()).hexdigest()[:16]
def divide(a,b):return a/b if b else None

def metrics(rows,key):
    n=len(rows);ti=sum(x['truth']=='Inconsistent' for x in rows);tc=n-ti
    correct=sum(x[key]==x['truth'] for x in rows);u=sum(x[key]=='Uncertain' for x in rows)
    fc=sum(x['truth']=='Inconsistent' and x[key]=='Consistent' for x in rows)
    fi=sum(x['truth']=='Consistent' and x[key]=='Inconsistent' for x in rows)
    return dict(n=n,true_I=ti,true_C=tc,correct=correct,accuracy=divide(correct,n),uncertain=u,
                false_C=fc,false_C_rate=divide(fc,ti),false_I=fi,false_I_rate=divide(fi,tc),
                I_recall=divide(sum(x['truth']=='Inconsistent' and x[key]=='Inconsistent' for x in rows),ti),
                determinate_coverage=divide(n-u,n),conditional_accuracy=divide(correct,n-u),
                fallback=sum(x['rule']=='Uncertain' for x in rows))

def ci(values,seed=20260920,iterations=5000):
    # Each cluster holds case-level changes; resample clusters, retaining all
    # dependent configurations and their paired Full/ablated observations.
    groups=list(values.values())
    if not groups:return None
    totals=[(sum(v),len(v)) for v in groups];rng=random.Random(seed);samples=[]
    for _ in range(iterations):
        choices=[totals[rng.randrange(len(totals))] for _ in totals]
        samples.append(sum(v for v,n in choices)/sum(n for v,n in choices))
    samples.sort()
    return {'estimate':sum(v for v,n in totals)/sum(n for v,n in totals),
            'lower':samples[int(.025*(iterations-1))],'upper':samples[int(.975*(iterations-1))],
            'clusters':len(groups),'iterations':iterations,'seed':seed}

def summarize(rows):
    full={x['case']:x for x in rows if x['profile']=='full'}
    assert len(full)==477
    out={'profiles':{},'strata':{},'pairwise_common_applicability':{}}
    for profile in PROFILES:
        subset=[x for x in rows if x['profile']==profile];base=[full[x['case']] for x in subset]
        item={'rules':metrics(subset,'rule'),'hybrid':metrics(subset,'hybrid'),
              'paired_full_rules':metrics(base,'rule'),'paired_full_hybrid':metrics(base,'hybrid')}
        if profile!='full':
            for method in ('rule','hybrid'):
                differences=defaultdict(list);false_changes=defaultdict(list)
                for x in subset:
                    b=full[x['case']]
                    differences[x['cluster']].append(int(x[method]==x['truth'])-int(b[method]==x['truth']))
                    if x['truth']=='Inconsistent':false_changes[x['cluster']].append(int(x[method]=='Consistent')-int(b[method]=='Consistent'))
                item[method+'_paired_accuracy_change_ci95']=ci(differences)
                item[method+'_paired_false_C_change_ci95']=ci(false_changes)
                item[method+'_transitions']=dict(Counter(full[x['case']][method]+' -> '+x[method] for x in subset))
        out['profiles'][profile]=item
        out['strata'][profile]={field:{v:{'rules':metrics([x for x in subset if x[field]==v],'rule'),
                                                'hybrid':metrics([x for x in subset if x[field]==v],'hybrid')}
                                        for v in sorted({x[field] for x in subset})}
                                for field in ('group','source','observation_profile','truth')}
    for a,b in itertools.combinations(PROFILES[1:],2):
        ar={x['case']:x for x in rows if x['profile']==a};br={x['case']:x for x in rows if x['profile']==b};common=sorted(set(ar)&set(br))
        out['pairwise_common_applicability'][a+' vs '+b]={'n':len(common),'full':metrics([full[c] for c in common],'hybrid'),
                                                       a:metrics([ar[c] for c in common],'hybrid'),b:metrics([br[c] for c in common],'hybrid')}
    return out

def export(out):
    manifest=read(out/'private/manifest.json');rows=[];responses={}
    for p in (out/'private/responses').glob('*/response.json'):responses[p.parent.name]=read(p)
    for x in manifest:
        if x['rule']!='Uncertain':response=None;hybrid=x['rule'];status='not_needed'
        elif x['input_status']=='oversize':response=None;hybrid='Uncertain';status='input_budget_exceeded'
        else:
            response=responses[x['packet_hash']];hybrid=response['verdict'];status=response['api_status']
        rows.append({'case':x['case_token'],'cluster':token(x['cluster']),'profile':x['profile'],'group':x['group'],
                     'source':x['source'],'observation_profile':x['observation_profile'],'truth':x['truth'],
                     'rule':x['rule'],'hybrid':hybrid,'llm_evidence':response['evidence_verdict'] if response else None,
                     'api_status':status,'screen_errors':response['screen_errors'] if response else [],
                     'removed_count':x['removed_count'],'packet_chars':x['packet_chars'],
                     'response_group':token(x['packet_hash']) if response else None,
                     'claims_C':x['claims'].get('Consistent',0),'claims_I':x['claims'].get('Inconsistent',0),'claims_U':x['claims'].get('Uncertain',0)})
    write(out/'public/outcomes.json',rows)
    with (out/'public/outcomes.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader()
        for row in rows:w.writerow({**row,'screen_errors':';'.join(row['screen_errors'])})
    app=[]
    for case in read(out/'private/applicability.json'):
        for a in case['audit']:app.append({'case':case['case_token'],'profile':a['profile'],'status':a['status'],'reason':a.get('reason')})
    write(out/'public/applicability.json',app)
    usage={'physical_requests':sum(x['attempts'] for x in responses.values()),'unique_packets':len(responses),
           'logical_fallbacks':sum(x['rule']=='Uncertain' for x in rows),'logical_api_views':sum(x['response_group'] is not None for x in rows),
           'retries':sum(x['attempts']-1 for x in responses.values()),'statuses':dict(Counter(x['api_status'] for x in responses.values())),
           'screen_rejected_responses':sum(bool(x['screen_errors']) for x in responses.values()),
           'screen_rejected_views':sum(bool(x['screen_errors']) for x in rows),
           'reported_models':dict(Counter(x['model'] for x in responses.values())),
           'tokens':{k:sum(x['usage'][k] for x in responses.values()) for k in ('total_tokens','prompt_tokens','completion_tokens','prompt_cache_hit_tokens')},
           'summed_request_seconds':sum(x['seconds'] for x in responses.values())}
    write(out/'public/usage.json',usage)
    write(out/'public/request-metrics.json',[{'response_group':token(h),**{k:v for k,v in x.items() if k in ('api_status','screen_errors','attempts','seconds','usage','model')}} for h,x in sorted(responses.items())])
    summary=summarize(rows);write(out/'public/summary.json',summary)
    with (out/'public/summary.csv').open('w',newline='') as f:
        keys=['profile','method','n','true_I','true_C','correct','accuracy','false_C','false_C_rate','false_I','false_I_rate','uncertain','determinate_coverage','conditional_accuracy','fallback']
        w=csv.DictWriter(f,fieldnames=keys,extrasaction='ignore');w.writeheader()
        for p,v in summary['profiles'].items():
            for method in ('rules','hybrid','paired_full_rules','paired_full_hybrid'):w.writerow({'profile':p,'method':method,**v[method]})
    return summary,usage

def render_report(out,summary,usage):
    lines=['# All-applicable evidence ablation on 477 OpenCode configurations','',
           'Every variant starts from the same captured Full execution. Hybrid preserves rule C/I; only rule U uses accepted DeepSeek V4 Flash inference. U and rejected/failed responses count as incorrect. Full is freshly evaluated in this experiment; frozen accuracy results remain untouched.','',
           '| Evidence | n | Full on same cases | Ablated Hybrid | Rule accuracy | False C / true I | False I / true C | U |',
           '|---|---:|---:|---:|---:|---:|---:|---:|']
    for p,v in summary['profiles'].items():
        h=v['hybrid'];r=v['rules'];b=v['paired_full_hybrid']
        lines.append(f"| {p} | {h['n']} | {b['accuracy']:.2%} | {h['accuracy']:.2%} | {r['accuracy']:.2%} | {h['false_C']}/{h['true_I']} | {h['false_I']}/{h['true_C']} | {h['uncertain']} |")
    lines+=['','## Interpretation and limitations','',
            '- Profile denominators differ. Use within-case Full contrasts and the common-applicability comparisons, not a naive ranking of marginal accuracies.',
            '- E1 removes the observed environment clock, not every possible semantic context. E2 removes explicit instruction bindings while preserving event contents, order, and time as partial clues.',
            '- E3-effect removes all independent before/after state snapshots; E3-delivery removes delivery/recipient copies, retaining native returns. These are stronger source-level removals than the previous single-record projections.',
            '- A remains a historically selected legal-variation subset. This is retrospective paired analysis of an exposed benchmark, not a new external blind test.',
            '- Historical actual-state projections and live observer records are stratified. Full does not imply all business effects are observed.',
            '- Rule missing-ID integrity checks can return global U; E2 results do not establish a general exhaustive-candidate correlation capability.',
            '- Confidence intervals use 5,000 parent-seed cluster bootstrap resamples. They describe this clustered benchmark and do not remove selection bias.',
            '- Shared identical packets reuse one response within this experiment only. Physical requests, unique packets, and logical fallback views are reported separately.',
            '- LLM evidence verdict is a model judgment, not independent evidence sufficiency ground truth. Successful JSON/reference checks do not certify semantic truth.',
            '- No new VM execution or perturbation of the original oracle. API billed dollar cost is not estimated without a supplied bill.','',
            '## API usage','',json.dumps(usage,indent=2),'',
            '## Reproduce statistics','',
            'Run `python code/consistency/evidence_ablation_v1/report.py --public .` from this public directory. The output must equal summary.json. Full detector reruns require the original evidence under its upstream permissions and the pinned repository dependencies. Raw evidence is intentionally absent from this package.']
    (out/'public/RESULTS.md').write_text('\n'.join(lines)+'\n')

def main():
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path);p.add_argument('--public',type=Path);a=p.parse_args()
    if a.public:
        result=summarize(read(a.public/'outcomes.json'))
        assert result==read(a.public/'summary.json'),'summary drift'
        print(json.dumps({'statistics_reproduced':True,'views':len(read(a.public/'outcomes.json')),'profiles':len(result['profiles'])}))
    else:
        out=a.root or Path(__file__).resolve().parents[2]/'artifacts/behavior-consistency-v5-evidence-ablation-r1-20260920'
        summary,usage=export(out);render_report(out,summary,usage);print(json.dumps(usage))

if __name__=='__main__':main()
