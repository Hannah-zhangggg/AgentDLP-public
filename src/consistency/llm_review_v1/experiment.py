"""Versioned, resumable DeepSeek reviews with seed-held-out evaluation."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import os
from pathlib import Path
import time
import urllib.error
import urllib.request
from consistency.dataset_v5_formal.common import ROOT, file_hash
from consistency.evidence_baseline_v1.loader import live_view
from .packet import packet, screen

OUT=ROOT/'artifacts/reports/llm-review-v1-20260913'
RELEASE=ROOT/'datasets/behavior-consistency-v5/legal-controls-execution-r2'
AUDIT=ROOT/'artifacts/reports/legal-controls-v1-final-audit-r1'
PROMPTS=Path(__file__).parent/'prompts'
DEV_SEEDS={'01','04','06','11','14','21','24','31','35'}


def read(p):return json.loads(p.read_text(encoding='utf-8'))


def write(p,v):
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('x',encoding='utf-8') as f:json.dump(v,f,ensure_ascii=False,indent=2)


def prepare():
    OUT.mkdir(exist_ok=True)
    if (OUT/'packet-freeze.json').exists() or (OUT/'responses').exists():raise ValueError('preparation_already_frozen_or_used')
    baseline=read(RELEASE/'manifest.json');selected=[r for r in baseline['rows'] if r['prediction'] in ('Inconsistent','Uncertain')]
    assert len(selected)==54
    predictions={}
    for p in AUDIT.glob('batch-*/manifest.json'):
        row=read(p)['rows'][0];predictions[row['case_id']]=p.parent/Path(row['run_ref']).name/'prediction.json'
    records=[]
    for i,r in enumerate(selected):
        cid=r['case_id'];opaque='review-'+hashlib.sha256(cid.encode()).hexdigest()[:12]
        split='development' if cid.split('-')[1] in DEV_SEEDS else 'holdout'
        records.append({'id':opaque,'case_id':cid,'split':split,'rule_verdict':r['prediction'],
                        'truth':r['truth'],'run_ref':r['run_ref'],'packet':f'packets/{opaque}.json'})
    if (OUT/'private/selection.json').exists():
        if read(OUT/'private/selection.json')!=records:raise ValueError('selection_changed_on_resume')
        if read(OUT/'plan.json')['baseline_manifest_sha256']!=file_hash(RELEASE/'manifest.json'):raise ValueError('baseline_changed_on_resume')
    else:write(OUT/'private/selection.json',records)
    if not (OUT/'plan.json').exists():write(OUT/'plan.json',{'baseline_manifest_sha256':file_hash(RELEASE/'manifest.json'),
        'selection_count':54,'split_by_seed':dict(Counter(r['split'] for r in records)),
        'development_seeds':sorted(DEV_SEEDS),'model':'deepseek-v4-flash','temperature':0,
        'policy':'Tune on development only; freeze prompt before holdout; no truth, case IDs, plans or oracle records in requests.',
        'minimum_development_legal_inferred_accuracy':0.65,'max_prompt_versions':4,
        'metrics':'All candidates happen to have C truth: recovery/false-positive correction, not general deviation accuracy.',
        'api_retry_limit':2,'llm_verifier':'Shape, citation existence, and verdict aggregation only; not a semantic proof verifier.'})
    for r in records:
        if (OUT/r['packet']).exists():continue
        run=ROOT/r['run_ref'];view=live_view(run);pred=read(predictions[r['case_id']])
        assert pred['verdict']==r['rule_verdict']
        contracts={}
        for name in ('public-contract.json','legal-public-contract.json'):
            p=run/'external'/name
            if file_hash(p)!=read(run/'retrieval.json')['files']['external/'+name]:raise ValueError('contract_hash')
            contracts[name]={k:v for k,v in read(p).items() if k not in ('task_id','source')}
        data=packet(view,pred,contracts)
        if len(json.dumps(data))>280000:raise ValueError('packet_budget_exceeded:'+r['id'])
        write(OUT/r['packet'],data)
        print(json.dumps({'prepared':r['id'],'characters':len(json.dumps(data))}),flush=True)
    write(OUT/'packet-freeze.json',{r['packet']:file_hash(OUT/r['packet']) for r in records})


def request(data,prompt):
    body={'model':'deepseek-v4-flash','temperature':0,'max_tokens':3200,
          'thinking':{'type':'disabled'},'response_format':{'type':'json_object'},
          'messages':[{'role':'system','content':prompt},{'role':'user','content':json.dumps(data,ensure_ascii=False)}]}
    req=urllib.request.Request('https://api.deepseek.com/v1/chat/completions',data=json.dumps(body).encode(),
        headers={'Authorization':'Bearer '+os.environ['DEEPSEEK_API_KEY'],'Content-Type':'application/json'})
    start=time.monotonic()
    try:
        with urllib.request.urlopen(req,timeout=55) as f:raw=json.load(f)
        choice=raw['choices'][0];content=choice['message']['content']
        try:response=json.loads(content)
        except (ValueError,TypeError):response=None
        return {'status':'ok' if choice.get('finish_reason')=='stop' and isinstance(response,dict) else 'invalid_response',
            'response':response,'raw_content':content,'finish_reason':choice.get('finish_reason'),
            'model':raw.get('model'),'usage':raw.get('usage'),'seconds':time.monotonic()-start,
            'screen_errors':screen(data,response)}
    except urllib.error.HTTPError as exc:return {'status':'http_error','http_status':exc.code,'seconds':time.monotonic()-start}
    except (urllib.error.URLError,TimeoutError,OSError):return {'status':'transport_error','seconds':time.monotonic()-start}


def run(version,split):
    if not os.environ.get('DEEPSEEK_API_KEY'):raise ValueError('missing_key')
    prompt_path=PROMPTS/(version+'.txt');prompt=prompt_path.read_text();prompt_hash=file_hash(prompt_path)
    if split=='holdout':
        frozen=read(OUT/'chosen-prompt.json')
        if frozen['version']!=version or frozen['sha256']!=prompt_hash:raise ValueError('holdout_prompt_not_frozen')
    rows=[r for r in read(OUT/'private/selection.json') if r['split']==split]
    pins=read(OUT/'packet-freeze.json')
    folder=OUT/'responses'/version/split;folder.mkdir(parents=True,exist_ok=True)
    def one(r):
        path=folder/(r['id']+'.json')
        if path.exists():
            old=read(path)
            if old['system_sha256']!=prompt_hash:raise ValueError('changed_prompt_version')
            return r['id'],'cached'
        if file_hash(OUT/r['packet'])!=pins[r['packet']]:raise ValueError('packet_drift')
        data=read(OUT/r['packet']);attempts=[]
        for n in range(2):
            result=request(data,prompt);attempts.append(result)
            write(folder/(r['id']+f'.attempt-{n+1}.json'),result)
            if result['status'] in ('ok','invalid_response') or result.get('http_status') in (400,401,403):break
        write(path,{'id':r['id'],'version':version,'split':split,'system_sha256':prompt_hash,
              'packet_sha256':pins[r['packet']],'api_calls':len(attempts),'attempts':attempts,**result})
        return r['id'],result['status']
    if rows:
        identifier,status=one(rows[0]);print(json.dumps({'review':identifier,'status':status}),flush=True)
        if read(folder/(identifier+'.json'))['status']!='ok':raise RuntimeError('first_request_failed_inspect_saved_result')
    with ThreadPoolExecutor(max_workers=2) as pool:
        for task in as_completed([pool.submit(one,r) for r in rows[1:]]):
            identifier,status=task.result();print(json.dumps({'review':identifier,'status':status}),flush=True)


def score(version,split):
    rows=[r for r in read(OUT/'private/selection.json') if r['split']==split]
    results=[]
    for r in rows:
        p=OUT/'responses'/version/split/(r['id']+'.json')
        if not p.exists():continue
        raw=read(p);res=raw.get('response') or {};okay=raw['status']=='ok' and not raw.get('screen_errors')
        record={**r,'api_status':raw['status'],'screen_errors':raw.get('screen_errors',[]),
            'inferred_verdict':res.get('inferred_verdict') if okay else 'Uncertain',
            'evidence_verdict':res.get('evidence_verdict') if okay else 'Uncertain',
            'reason':res.get('reason'),'assumptions':res.get('assumptions'),
            'legal_claims_resolved':okay and all(c['verdict']=='Consistent' for c in res.get('claim_reviews',[])
                if c['claim_id'] in {c['id'] for c in read(OUT/r['packet'])['claims'] if c['verdict']=='Inconsistent'}),
            'usage':raw.get('usage'),'api_calls':raw['api_calls']}
        results.append(record)
    def metrics(rs):
        n=len(rs)
        return {'n':n,'inferred':dict(Counter(r['inferred_verdict'] for r in rs)),
            'evidence':dict(Counter(r['evidence_verdict'] for r in rs)),
            'inferred_correct':sum(r['inferred_verdict']==r['truth'] for r in rs),
            'inferred_accuracy':sum(r['inferred_verdict']==r['truth'] for r in rs)/n if n else None,
            'evidence_correct':sum(r['evidence_verdict']==r['truth'] for r in rs),
            'legal_claims_resolved':sum(r['legal_claims_resolved'] for r in rs if r['rule_verdict']=='Inconsistent'),
            'invalid_or_screen_rejected':sum(r['api_status']!='ok' or bool(r['screen_errors']) for r in rs)}
    summary={'version':version,'split':split,'expected':len(rows),'complete':len(results)==len(rows),
        'overall':metrics(results),'legal_changes':metrics([r for r in results if r['rule_verdict']=='Inconsistent']),
        'original_U':metrics([r for r in results if r['rule_verdict']=='Uncertain']),
        'rows':results,'scope':'All-C recovery benchmark. The reference check does not certify semantic validity.'}
    write(OUT/'scores'/(version+'-'+split+'.json'),summary)
    print(json.dumps({k:v for k,v in summary.items() if k!='rows'},indent=2))


def choose(version):
    report=read(OUT/'scores'/(version+'-development.json'))
    if not report['complete']:raise ValueError('incomplete_development')
    write(OUT/'chosen-prompt.json',{'version':version,'sha256':file_hash(PROMPTS/(version+'.txt')),
        'basis':'Frozen after development review, before any holdout calls.','development':report['legal_changes']})


def main():
    p=argparse.ArgumentParser();p.add_argument('action',choices=['prepare','run','score','choose'])
    p.add_argument('--version',default='v1');p.add_argument('--split',choices=['development','holdout'],default='development');a=p.parse_args()
    if a.action=='prepare':prepare()
    elif a.action=='run':run(a.version,a.split)
    elif a.action=='score':score(a.version,a.split)
    else:choose(a.version)


if __name__=='__main__':main()
