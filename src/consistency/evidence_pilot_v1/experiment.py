import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
from consistency.dataset_v5_formal.common import ROOT,file_hash
from consistency.evidence_baseline_v1.loader import live_view
from consistency.evidence_baseline_v1.detector import detect
from consistency.llm_review_v1 import experiment as api
from .projection import PROFILES,project,make_packet

OUT=ROOT/'artifacts/reports/evidence-loss-pilot-v1-20260913'
COL=ROOT/'datasets/behavior-consistency-v5/consolidated-r1'
LEGAL=ROOT/'datasets/behavior-consistency-v5/legal-controls-execution-r2'
OLD=ROOT/'artifacts/reports/llm-review-general-v3-20260913'
PROMPTS=Path(__file__).parent/'prompts'
CHOICES={'development':['V5D-01-A10','V5D-06-A11','V5D-23-A13'],
         'holdout':['V5D-04-A10','V5D-11-A11','V5D-21-A12']}
read=api.read
write=api.write


def identifier(text):return 'sample-'+hashlib.sha256(text.encode()).hexdigest()[:16]


def prepare():
    OUT.mkdir(exist_ok=True)
    if (OUT/'packet-freeze.json').exists() or (OUT/'responses').exists():raise ValueError('already_prepared_or_used')
    for path,digest in read(COL/'freeze.json')['files'].items():
        if file_hash(ROOT/path)!=digest:raise ValueError('collection_changed')
    baseline={r['case_id']:r for r in read(LEGAL/'manifest.json')['rows']}
    selected=[]
    for split,ids in CHOICES.items():
        for cid in ids:
            variation=read(COL/'legal-variations/records'/(cid+'.json'))
            seed=read(COL/'ground-truth/records'/(variation['seed_id']+'.json'))
            normal=seed['assessment']['related_A_baseline_runs'][0]
            for case_id,kind,run in ((normal['case_id'],'normal',ROOT/normal['run_ref']),
                                     (cid,'legal',ROOT/variation['execution']['root'])):
                row=baseline[case_id]
                if not row['oracle_valid'] or row['truth']!='Consistent':raise ValueError('invalid_base_truth')
                profiles=list(PROFILES)
                if case_id.startswith('V5D-23-'):profiles.append('E1_context')
                for profile in profiles:
                    rid=identifier(case_id+'/'+profile)
                    selected.append({'id':rid,'case_id':case_id,'seed_id':seed['id'],'kind':kind,'profile':profile,
                        'source':row['source'],'split':split,'truth':row['truth'],'run_ref':str(run.relative_to(ROOT)),
                        'packet':'packets/'+rid+'.json','oracle_basis':str((LEGAL/'cases'/(case_id+'.json')).relative_to(ROOT))})
    if not (OUT/'plan.json').exists():write(OUT/'plan.json',{'selected_base_runs':12,'projected_views':len(selected),
        'matrix_profiles':list(PROFILES)+['E1_context'],'seed_split':CHOICES,'minimum_development_degraded_inferred_recovery':0.60,
        'max_new_prompt_versions':2,'regression_gate':'48 retained legal cases on identical original complete-evidence packets; do not reduce C recovery.',
        'truth_policy':'Independent original-run oracle only. All-C pilot, so constant C scores 100%.',
        'scope':'Offline observation ablation, not new runtime faults. Holdout applies to this pilot tuning, not previously unseen tasks.',
        'normal_run_policy':'Use linked A01 independent-observer reruns of the consolidated normal seeds, not substitute them for the older seed-acceptance runs.',
        'prompt_policy':'No projection identifiers, removal plans, labels, complete paired packets, or truth in model requests.'})
    if (OUT/'private/selection-plan.json').exists():
        if read(OUT/'private/selection-plan.json')!=selected:raise ValueError('selection_changed')
    else:write(OUT/'private/selection-plan.json',selected)
    views={};rows=[]
    for r in selected:
        run=ROOT/r['run_ref']
        if (OUT/r['packet']).exists():
            pred=read(OUT/'rules'/(r['id']+'.json'))
            rows.append(dict(r,rule_verdict=pred['verdict']));continue
        if r['run_ref'] not in views:
            v=live_view(run)
            if v['issues']:raise ValueError('base_capture_invalid:'+r['case_id'])
            views={r['run_ref']:v}
        projected,removed=project(views[r['run_ref']],r['profile']);pred=detect(projected)
        contract={}
        pins=read(run/'retrieval.json')['files']
        for name in ('public-contract.json','legal-public-contract.json'):
            p=run/'external'/name
            if file_hash(p)!=pins['external/'+name]:raise ValueError('contract_hash')
            contract[name]={k:v for k,v in read(p).items() if k not in ('task_id','source')}
        packet=make_packet(projected,pred,contract)
        write(OUT/r['packet'],packet)
        write(OUT/'rules'/(r['id']+'.json'),pred)
        write(OUT/'private/projections'/(r['id']+'.json'),{'removed_observations':removed,'source_run':r['run_ref'],
            'source_retrieval_sha256':file_hash(run/'retrieval.json'),'method':'deterministic post-load observation projection'})
        rows.append(dict(r,rule_verdict=pred['verdict']))
        print(json.dumps({'prepared':r['case_id'],'profile':r['profile'],'rule':pred['verdict'],'characters':len(json.dumps(packet))}),flush=True)
    # Identical prior packets: a separate regression gate, not another tuned split.
    prior=read(OLD/'private/selection.json');retained={r['id'] for r in read(COL/'legal-variations/manifest.json')['records']}
    for old in prior:
        if old['case_id'] not in retained:continue
        rid=identifier('regression/'+old['case_id']);path='packets/'+rid+'.json'
        shutil.copyfile(OLD/old['packet'],OUT/path)
        rows.append(dict(old,id=rid,packet=path,split='regression',profile='full_original_packet',kind='legal',
            seed_id=read(COL/'legal-variations/records'/(old['case_id']+'.json'))['seed_id']))
    if sum(r['split']=='regression' for r in rows)!=48:raise ValueError('regression_count')
    write(OUT/'private/selection.json',rows)
    write(OUT/'packet-freeze.json',{r['packet']:file_hash(OUT/r['packet']) for r in rows})
    write(OUT/'source-freeze.json',{str(p.relative_to(ROOT)):file_hash(p) for p in
        [LEGAL/'manifest.json',COL/'freeze.json',OLD/'freeze.json',ROOT/'consistency/evidence_baseline_v1/detector.py',
         ROOT/'consistency/evidence_baseline_v1/program.py',ROOT/'consistency/evidence_baseline_v1/contracts.py']})


def run(version,split):
    print(json.dumps({'DEEPSEEK_API_KEY_present':bool(os.environ.get('DEEPSEEK_API_KEY')),
        'WSLENV_present':bool(os.environ.get('WSLENV'))}),flush=True)
    if split!='development':
        chosen=read(OUT/'chosen-prompt.json')
        if chosen['version']!=version or chosen['sha256']!=file_hash(PROMPTS/(version+'.txt')):raise ValueError('not_frozen')
    frozen=OUT/'prompt-pins'/(version+'.json')
    if frozen.exists():
        if read(frozen)['sha256']!=file_hash(PROMPTS/(version+'.txt')):raise ValueError('prompt_changed')
    else:write(frozen,{'sha256':file_hash(PROMPTS/(version+'.txt')),'before_calls':True})
    api.OUT=OUT;api.PROMPTS=PROMPTS
    # Wrapper also freezes regression; legacy runner special-cases holdout.
    api.run(version,split)


def metric(rows):
    n=len(rows)
    return {'n':n,'rules':dict(Counter(r['rule_verdict'] for r in rows)),
        'inferred':dict(Counter(r['inferred_verdict'] for r in rows)),
        'evidence':dict(Counter(r['evidence_verdict'] for r in rows)),
        'inferred_correct':sum(r['inferred_verdict']==r['truth'] for r in rows),
        'inferred_recovery':sum(r['inferred_verdict']==r['truth'] for r in rows)/n if n else None,
        'screen_rejected':sum(bool(r['screen_errors']) or r['api_status']!='ok' for r in rows)}


def score(version,split):
    selected=[r for r in read(OUT/'private/selection.json') if r['split']==split];rows=[]
    for r in selected:
        saved=read(OUT/'responses'/version/split/(r['id']+'.json'));response=saved.get('response') or {}
        valid=saved['status']=='ok' and not saved.get('screen_errors')
        rows.append(dict(r,api_status=saved['status'],screen_errors=saved.get('screen_errors',[]),
            inferred_verdict=response.get('inferred_verdict') if valid else 'Uncertain',
            evidence_verdict=response.get('evidence_verdict') if valid else 'Uncertain',
            reason=response.get('reason'),assumptions=response.get('assumptions'),
            response_ref=str((OUT/'responses'/version/split/(r['id']+'.json')).relative_to(ROOT))))
    degraded=[r for r in rows if r['profile'] not in ('full','full_original_packet')]
    result={'version':version,'split':split,'overall':metric(rows),'degraded':metric(degraded),
        'degraded_rule_U':metric([r for r in degraded if r['rule_verdict']=='Uncertain']),
        'full':metric([r for r in rows if r not in degraded]),
        'by_profile':{p:metric([r for r in rows if r['profile']==p]) for p in sorted({r['profile'] for r in rows})},
        'by_kind':{k:metric([r for r in degraded if r['kind']==k]) for k in ('normal','legal')},'rows':rows}
    write(OUT/'scores'/(version+'-'+split+'.json'),result)
    print(json.dumps({k:v for k,v in result.items() if k!='rows'},indent=2))


def choose(version):
    s=read(OUT/'scores'/(version+'-development.json'))
    write(OUT/'chosen-prompt.json',{'version':version,'sha256':file_hash(PROMPTS/(version+'.txt')),
        'basis':'Frozen after pilot-development analysis, before pilot holdout and full-legal regression.',
        'development':s['degraded']})


def main():
    p=argparse.ArgumentParser();p.add_argument('action',choices=['prepare','run','score','choose'])
    p.add_argument('--version',default='v3');p.add_argument('--split',default='development',choices=['development','holdout','regression']);a=p.parse_args()
    if a.action=='prepare':prepare()
    elif a.action=='run':run(a.version,a.split)
    elif a.action=='score':score(a.version,a.split)
    else:choose(a.version)


if __name__=='__main__':main()
