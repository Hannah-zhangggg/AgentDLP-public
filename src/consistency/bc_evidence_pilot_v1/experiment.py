import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re

from consistency.evidence_pilot_v1.experiment import ROOT, PROMPTS, read, write, file_hash
from consistency.evidence_pilot_v1.postflight import verify
from consistency.evidence_pilot_v1.projection import PROFILES, project, make_packet
from consistency.evidence_pilot_v1.routing import select_prompt
from consistency.evidence_baseline_v1.loader import live_view, historical_view
from consistency.evidence_baseline_v1.detector import detect
from consistency.llm_review_v1.experiment import request

OUT=ROOT/'artifacts/reports/bc-evidence-pilot-v1-20260913'
PREVIOUS=ROOT/'artifacts/reports/evidence-loss-pilot-v1-20260913'
LEGACY=ROOT/'datasets/behavior-consistency-v5/intervention-execution-r1/manifest.json'
LIVE=ROOT/'artifacts/reports/evidence-baseline-v1-live-final-r1/manifest.json'


def opaque(value):return hashlib.sha256(value.encode()).hexdigest()[:16]


def legacy_record_adapter(view):
    """Address existing result fields, not synthesized observations.

    Legacy loader used a shared invocation/return ID and omitted child result
    IDs. The frozen packet deduplicates IDs. Give field-level addresses to the
    actually present fields so native returns are not accidentally suppressed.
    No timestamps, state, bindings or missing results are inferred here.
    """
    v=deepcopy(view)
    for event in v['events']+v.get('children',[]):
        if 'result' in event:event['return_evidence_id']=event['evidence_id']+':result'
        if 'delivered' in event:event['delivery_evidence_id']=event['evidence_id']+':delivered'
    return v


def redact_run_identifiers(value):
    """Extend the existing A-only run-ID masking to B/C without changing facts."""
    if isinstance(value,dict):return {redact_run_identifiers(k):redact_run_identifiers(v) for k,v in value.items()}
    if isinstance(value,list):return [redact_run_identifiers(v) for v in value]
    if not isinstance(value,str):return value
    value=re.sub(r'p433-evidencev1-v5d-\d+-[abc]\d+','RUN',value,flags=re.I)
    value=re.sub(r'\bV5D-\d+-[ABC]\d+\b','CASE',value,flags=re.I)
    return re.sub(r'\bp433-[a-f0-9]{8}-\d+\b','RUN',value,flags=re.I)


def selection():
    rows=[]
    for r in read(LIVE)['rows']:
        if r['oracle_valid'] and r['truth']=='Inconsistent' and '-B' in r['case_id']:
            rows.append({'case_id':r['case_id'],'group':'B','source':r['source'],
                'stratum':'live_independent_observers','run_ref':r['run'],
                'truth':r['truth'],'taxonomy':r['oracle_taxonomy'],'oracle_ref':str(LIVE.relative_to(ROOT))})
    candidates=[r for r in read(LEGACY)['cases'] if r['group'] in ('B','C') and
        r['status']=='executed_oracle_valid' and r['truth']['consistency']=='Inconsistent']
    selected=[];seen_tags=set();seen_mechanisms=set();per_source=Counter();per_seed=Counter()
    # Coverage-oriented sample, independent of current or historical predictions.
    for group,quota in (('B',3),('C',1)):
        for _ in range(3*quota):
            pool=[r for r in candidates if r['group']==group and r not in selected and per_source[group,r['source']]<quota]
            def rank(r):
                return (-len(set(r['truth']['violation_tags'])-seen_tags),
                    -len(set(r['mechanism_ids'])-seen_mechanisms),per_seed[r['seed_id']],opaque('bc-pilot-20260913/'+r['case_id']))
            r=min(pool,key=rank);selected.append(r)
            seen_tags.update(r['truth']['violation_tags']);seen_mechanisms.update(r['mechanism_ids'])
            per_source[group,r['source']]+=1;per_seed[r['seed_id']]+=1
    for r in selected:
        run='artifacts/reports/'+r['selected_attempt'].replace('--','/')
        rows.append({'case_id':r['case_id'],'seed_id':r['seed_id'],'group':r['group'],'source':r['source'],
            'stratum':'historical_actual_fact_projection','run_ref':run,'truth':'Inconsistent',
            'taxonomy':r['truth']['violation_tags'],'mechanism_ids':r['mechanism_ids'],
            'oracle_ref':str(LEGACY.relative_to(ROOT))})
    assert len(rows)==16
    return rows


def prepare():
    OUT.mkdir(exist_ok=True)
    verify(ROOT,read(PREVIOUS/'freeze.json')['files'])
    verify(ROOT,read(PREVIOUS/'postflight-freeze.json')['files'])
    selected=selection()
    write(OUT/'plan.json',{'base_runs':16,'nominal_views':80,'profiles':list(PROFILES),
        'sampling':'All four existing oracle-I live-observer B runs; nine B and three C legacy oracle-I runs, source quotas and taxonomy/mechanism diversity with deterministic hash tie-breaking. Never selected on detector predictions.',
        'primary_metric':'True I predicted C / all true-I views; U remains in denominator. Also report detection rate, U, I-to-C overrides, and missing-evidence subsets.',
        'policy':'Frozen rules, matrix selector, v3/v4 prompts and output checker; no prompt tuning or semantic repair after seeing results. Rule C bypasses API; all rule I/U receive selected review.',
        'evidence_boundary':'Live and historical strata are separate. Historical states are archived actual facts expanded offline, not proof that new independent observers were installed. No new VM execution.',
        'adaptation':'Legacy field-level evidence IDs prevent invocation/return ID collisions. Run-ID redaction covers B/C. Frozen comparison, projection and prompt logic unchanged.',
        'limitations':['No E1 context condition or T6 sample in this initial probe.','Coverage-oriented sample, not a prevalence estimate.','Selected actual truth is I; B/C design labels alone do not determine truth.','No tuning on this probe; all outputs including failures retained.'],
        'api':{'request_model':'deepseek-v4-flash','temperature':0,'max_tokens':3200,'thinking':'disabled','max_transport_attempts':2}})
    write(OUT/'private/base-runs.json',selected)
    records=[];sources={str(p.relative_to(ROOT)):file_hash(p) for p in (LEGACY,LIVE)}
    compatibility=[]
    for base in selected:
        run=ROOT/base['run_ref'];legacy=base['stratum'].startswith('historical')
        v=historical_view(run) if legacy else live_view(run)
        if v['issues']:raise ValueError('source_integrity:'+base['case_id']+':'+str(v['issues']))
        if legacy:v=legacy_record_adapter(v)
        sources[str((run/'retrieval.json').relative_to(ROOT))]=file_hash(run/'retrieval.json')
        contracts={};pins=read(run/'retrieval.json')['files']
        for name in ('public-contract.json','legal-public-contract.json'):
            path=run/'external'/name
            if not path.exists():continue
            if file_hash(path)!=pins.get('external/'+name):raise ValueError('contract_hash')
            contracts[name]={k:x for k,x in read(path).items() if k not in ('task_id','source')}
        if not contracts:raise ValueError('public_contract_missing:'+base['case_id'])
        compatibility.append({**base,'instructions':len(v['instructions']),'native_calls':len(v['events']),
            'child_calls':len(v.get('children',[])),'observer_profile':v['profile'],
            'state_witnesses':sum(bool(e.get(k)) for e in v['events']+v.get('children',[]) for k in ('state_before','state_after')),
            'runtime_events':len(v.get('runtime_events',[]))})
        for profile in PROFILES:
            rid='probe-'+opaque(base['stratum']+'/'+base['case_id']+'/'+profile)
            if not v['events'] and profile!='full':
                records.append({**base,'id':rid,'profile':profile,'status':'projection_not_applicable_no_native_target'})
                continue
            view,removed=project(v,profile);result=detect(view)
            packet=redact_run_identifiers(make_packet(view,result,contracts))
            # A result field must not disappear solely through ID deduplication.
            expected=sum('result' in e for e in view['events']+view.get('children',[]))
            actual=sum(e['kind']=='native_return' for e in packet['evidence'])
            if expected!=actual:raise ValueError('packet_return_coverage:'+rid)
            route=select_prompt(packet)
            rec={**base,'id':rid,'profile':profile,'status':'prepared','rule_verdict':result['verdict'],
                'rule_taxonomy':result['taxonomy'],'route':route,'api_needed':result['verdict']!='Consistent',
                'packet':'packets/'+rid+'.json'}
            write(OUT/rec['packet'],packet);write(OUT/'rules'/(rid+'.json'),result)
            write(OUT/'private/projections'/(rid+'.json'),{'source_run':base['run_ref'],'removed_observations':removed})
            records.append(rec)
            print(json.dumps({'prepared':base['case_id'],'stratum':base['stratum'],'profile':profile,
                'rule':result['verdict'],'prompt':route['version'],'characters':len(json.dumps(packet))}),flush=True)
    write(OUT/'private/selection.json',records);write(OUT/'compatibility.json',compatibility)
    write(OUT/'packet-freeze.json',{r['packet']:file_hash(OUT/r['packet']) for r in records if r['status']=='prepared'})
    paths=list((ROOT/'consistency/evidence_baseline_v1').glob('*.py'))
    paths+=list((ROOT/'consistency/bc_evidence_pilot_v1').glob('*.py'))
    paths += [ROOT/'consistency/evidence_pilot_v1/projection.py',ROOT/'consistency/evidence_pilot_v1/routing.py',
        ROOT/'consistency/llm_review_v1/packet.py',ROOT/'consistency/llm_review_v1/experiment.py',
        ROOT/'consistency/dataset_v5_formal/public433_rules.py',ROOT/'consistency/semantic_adapters.py',
        ROOT/'consistency/semantic_model.py',PROMPTS/'v3.txt',PROMPTS/'v4.txt']
    sources.update({str(p.relative_to(ROOT)):file_hash(p) for p in paths})
    write(OUT/'source-freeze.json',sources)
    print(json.dumps({'prepared_views':sum(r['status']=='prepared' for r in records),
        'api_needed':sum(r.get('api_needed',False) for r in records),'route_counts':dict(Counter(r['route']['version'] for r in records if r['status']=='prepared'))}))


def run():
    print(json.dumps({'DEEPSEEK_API_KEY_present':bool(os.environ.get('DEEPSEEK_API_KEY')),
        'WSLENV_present':bool(os.environ.get('WSLENV'))}),flush=True)
    if not os.environ.get('DEEPSEEK_API_KEY'):raise ValueError('missing_key')
    verify(ROOT,read(OUT/'source-freeze.json'));verify(OUT,read(OUT/'packet-freeze.json'))
    rows=[r for r in read(OUT/'private/selection.json') if r['status']=='prepared']
    def one(r):
        path=OUT/'responses'/(r['id']+'.json')
        if path.exists():return r['id'],'cached'
        if not r['api_needed']:
            write(path,{'status':'rule_bypass','api_calls':0});return r['id'],'rule_bypass'
        prompt=(PROMPTS/(r['route']['version']+'.txt')).read_text()
        packet=read(OUT/r['packet']);attempts=[]
        for n in range(2):
            result=request(packet,prompt);attempts.append(result)
            write(OUT/'attempts'/(r['id']+f'.attempt-{n+1}.json'),result)
            if result['status'] in ('ok','invalid_response') or result.get('http_status') in (400,401,403):break
        write(path,{'id':r['id'],'prompt_version':r['route']['version'],
            'system_sha256':file_hash(PROMPTS/(r['route']['version']+'.txt')),
            'packet_sha256':file_hash(OUT/r['packet']),'api_calls':len(attempts),**result})
        return r['id'],result['status']
    # Connectivity check; preserve a validly received but rejected response.
    first=rows[0];rid,status=one(first);print(json.dumps({'review':rid,'status':status}),flush=True)
    if status in ('http_error','transport_error'):raise RuntimeError('first_API_transport_failure')
    with ThreadPoolExecutor(max_workers=2) as pool:
        for future in as_completed([pool.submit(one,r) for r in rows[1:]]):
            rid,status=future.result();print(json.dumps({'review':rid,'status':status}),flush=True)


def metrics(rows):
    n=len(rows)
    def counts(key):return dict(Counter(r[key] for r in rows))
    return {'n':n,'rules':counts('rule_verdict'),'hybrid':counts('hybrid_verdict'),
        'evidence_assessment':counts('evidence_verdict'),
        'rule_false_C':sum(r['rule_verdict']=='Consistent' for r in rows),
        'hybrid_false_C':sum(r['hybrid_verdict']=='Consistent' for r in rows),
        'hybrid_false_C_rate':sum(r['hybrid_verdict']=='Consistent' for r in rows)/n if n else None,
        'hybrid_I_recall':sum(r['hybrid_verdict']=='Inconsistent' for r in rows)/n if n else None,
        'rule_I_to_hybrid_C':sum(r['rule_verdict']=='Inconsistent' and r['hybrid_verdict']=='Consistent' for r in rows),
        'rejected_outputs':sum(r['api_status'] not in ('ok','rule_bypass') or bool(r['screen_errors']) for r in rows)}


def score():
    verify(ROOT,read(OUT/'source-freeze.json'));verify(OUT,read(OUT/'packet-freeze.json'))
    rows=[]
    for r in read(OUT/'private/selection.json'):
        if r['status']!='prepared':continue
        saved=read(OUT/'responses'/(r['id']+'.json'));response=saved.get('response') or {}
        accepted=saved['status']=='ok' and not saved.get('screen_errors')
        bypass=saved['status']=='rule_bypass'
        rows.append({**r,'api_status':saved['status'],'screen_errors':saved.get('screen_errors',[]),
            'hybrid_verdict':'Consistent' if bypass else response.get('inferred_verdict') if accepted else 'Uncertain',
            'evidence_verdict':r['rule_verdict'] if bypass else response.get('evidence_verdict') if accepted else 'Uncertain',
            'reason':response.get('reason'),'assumptions':response.get('assumptions'),
            'raw_inferred_verdict':response.get('inferred_verdict'),'raw_evidence_verdict':response.get('evidence_verdict')})
    attempts=[read(p) for p in (OUT/'attempts').glob('*.json')];usage=Counter()
    for a in attempts:
        for k,v in (a.get('usage') or {}).items():
            if isinstance(v,int):usage[k]+=v
    summary={'all_truth':'Inconsistent','base_runs':16,'views':len(rows),'overall':metrics(rows),
        'by_profile':{p:metrics([r for r in rows if r['profile']==p]) for p in PROFILES},
        'by_stratum':{s:{'all':metrics([r for r in rows if r['stratum']==s]),
            'full':metrics([r for r in rows if r['stratum']==s and r['profile']=='full']),
            'degraded':metrics([r for r in rows if r['stratum']==s and r['profile']!='full'])} for s in sorted({r['stratum'] for r in rows})},
        'by_group':{g:metrics([r for r in rows if r['group']==g]) for g in ('B','C')},
        'degraded_rule_U':metrics([r for r in rows if r['profile']!='full' and r['rule_verdict']=='Uncertain']),
        'api_calls':len(attempts),'usage':dict(usage),'returned_models':dict(Counter(r.get('model') for r in attempts)),
        'rows':rows,'scope':'Applicability probe on selected real I runs; separate live and historical observation strata, no A-rate pooling, no prompt tuning.'}
    write(OUT/'summary.json',summary)
    write(OUT/'freeze.json',{'files':{str(p.relative_to(ROOT)):file_hash(p) for p in OUT.rglob('*') if p.is_file()},
        'source_files':read(OUT/'source-freeze.json')})
    print(json.dumps({k:v for k,v in summary.items() if k!='rows'},indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=('prepare','run','score'))
    {'prepare':prepare,'run':run,'score':score}[parser.parse_args().action]()
