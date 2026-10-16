"""Unify accepted seeds and executed legal variants without altering raw evidence."""
from collections import Counter
from copy import deepcopy
import json
from pathlib import Path
import jsonschema
from .common import ROOT, file_hash

BASE=ROOT/'datasets/behavior-consistency-v5'
OUT=BASE/'consolidated-r1'
FORMAL=BASE/'formal-ground-truth-r3'
LEGAL=BASE/'legal-controls-execution-r2'
DESIGN=BASE/'intervention-design-r3'
REVIEW=ROOT/'artifacts/reports/llm-review-general-v3-20260913'
EXPECTED_EXCLUDED={'V5D-24-A02','V5D-24-A04','V5D-24-A12','V5D-24-A13','V5D-38-A02'}
FIELDS=('schema_version','id','kind','seed_id','source','definition','ground_truth','execution','assessment','provenance')
SCHEMA={'$schema':'https://json-schema.org/draft/2020-12/schema','title':'AgentDLP consolidated record v1',
    'type':'object','additionalProperties':False,'required':list(FIELDS),
    'properties':{k:{'type':'object'} for k in FIELDS}}
SCHEMA['properties'].update({'schema_version':{'const':'agentdlp-consolidated-v1'},
    'id':{'type':'string','minLength':1},'kind':{'enum':['ground_truth_seed','legal_variation']},
    'seed_id':{'type':'string','minLength':1},'provenance':{'type':'array','items':{'type':'object'}},
    'ground_truth':{'type':'object','required':['verdict','oracle_valid','taxonomy','scope','task_outcome','basis'],
        'properties':{'verdict':{'const':'Consistent'},'oracle_valid':{'const':True},'taxonomy':{'type':'array','maxItems':0}}},
    'execution':{'type':'object','required':['run_id','root','retrieval','evidence_index']},
    'assessment':{'type':'object','required':['rules','llm','used_verdict','selection_basis']}})


def read(path):return json.loads(path.read_text(encoding='utf-8'))


def write(path,data):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x',encoding='utf-8') as f:json.dump(data,f,ensure_ascii=False,indent=2)


def relative(path):return str(path.relative_to(ROOT))


def safe_path(root,name):
    name=name.replace('\\','/')
    path=(root/name).resolve()
    if not path.is_relative_to(root.resolve()):raise ValueError('escaping_evidence_path')
    if not path.is_file():raise ValueError('missing_evidence:'+relative(path))
    return path


def select_legal(rows,designs,reviews):
    if len({r['case_id'] for r in rows})!=len(rows):raise ValueError('duplicate_case')
    kept=[];excluded=[];baselines=[]
    for row in rows:
        cid=row['case_id'];design=designs[cid]
        if design['group']!='A':raise ValueError('non_A_case')
        if cid.endswith('-A01'):
            baselines.append(row);continue
        if not row['oracle_valid'] or row['truth']!='Consistent':raise ValueError('invalid_legal_truth')
        review=reviews.get(cid)
        if row['prediction']!='Consistent' and review is None:raise ValueError('missing_review')
        verdict=review['inferred_verdict'] if review else row['prediction']
        if verdict=='Uncertain':excluded.append(row)
        elif verdict=='Consistent':kept.append(row)
        else:raise ValueError('unresolved_inconsistency')
    return kept,excluded,baselines


def validate(record):
    jsonschema.validate(record,SCHEMA)
    if record['kind']=='legal_variation':
        if record['assessment']['used_verdict']!='Consistent':raise ValueError('non_C_in_legal_set')
        if not record['definition']['changes']:raise ValueError('baseline_is_not_variation')


class Builder:
    def __init__(self):self.sources={};self.archived_file_count=0

    def ref(self,path):
        if not path.is_file():raise ValueError('missing_source:'+relative(path))
        digest=file_hash(path);name=relative(path)
        if name in self.sources and self.sources[name]!=digest:raise ValueError('source_changed')
        self.sources[name]=digest
        return {'path':name,'sha256':digest,'bytes':path.stat().st_size}

    def evidence(self,folder,cid,run,expected=None):
        retrieval=self.ref(run/'retrieval.json')
        if expected and retrieval['sha256']!=expected:raise ValueError('retrieval_hash_mismatch')
        files=[]
        for name,digest in read(run/'retrieval.json')['files'].items():
            path=safe_path(run,name)
            files.append({'path':relative(path),'sha256':digest,'bytes':path.stat().st_size})
        self.archived_file_count+=len(files)
        index=folder/'evidence-indexes'/(cid+'.json')
        write(index,{'run_root':relative(run),'retrieval':retrieval,'files':files,
            'verification':'All paths exist; retrieval rehashed. Payload hashes retained from original retrieval, not all rehashed in this consolidation.'})
        return {'run_id':run.name,'root':relative(run),'retrieval':retrieval,
            'evidence_index':{'path':relative(index),'sha256':file_hash(index),'bytes':index.stat().st_size}}

    def source(self,seed):
        return {'platform':seed['source'],'task_id':seed.get('task_id',seed['id']),
            'url':seed['source_url'],'revision':seed['source_version'],
            'is_derived':seed['source']=='MCPMark-derived',
            'parent_seed_id':seed.get('parent_seed_id'),'derivation':seed.get('derivation',seed.get('adaptation'))}

    def base(self,cid,kind,seed):
        return {'schema_version':'agentdlp-consolidated-v1','id':cid,'kind':kind,'seed_id':seed['id'],
            'source':self.source(seed),'definition':{},'ground_truth':{},'execution':{},
            'assessment':{'rules':None,'llm':None,'used_verdict':None,'selection_basis':None},'provenance':[]}


def main():
    if OUT.exists():raise ValueError('destination_exists')
    for name,digest in read(REVIEW/'freeze.json')['files'].items():
        if file_hash(ROOT/name)!=digest:raise ValueError('v3_freeze_changed')
    b=Builder();formal_ref=b.ref(FORMAL/'manifest.json');legal_ref=b.ref(LEGAL/'manifest.json')
    review_ref=b.ref(REVIEW/'summary.json');b.ref(DESIGN/'legal-run-selection.json')
    accepted=read(FORMAL/'manifest.json')['rows'];seeds={r['id']:r for r in accepted}
    if len(seeds)!=43:raise ValueError('expected_43_unique_seeds')
    design_rows=read(DESIGN/'legal-run-selection.json');designs={r['case_id']:r for r in design_rows}
    reviews={r['case_id']:r for r in read(REVIEW/'summary.json')['rows']}
    rows=read(LEGAL/'manifest.json')['rows'];kept,excluded,baselines=select_legal(rows,designs,reviews)
    if len(kept)!=152 or {r['case_id'] for r in excluded}!=EXPECTED_EXCLUDED:raise ValueError('unexpected_selection')
    OUT.mkdir();write(OUT/'schema.json',SCHEMA)
    records={'ground-truth':[],'legal-variations':[]}
    for cid,seed in seeds.items():
        if seed['status']!='accepted' or seed['baseline_consistency']!='Consistent' or not all(seed['criteria'].values()):
            raise ValueError('unaccepted_seed')
        source_files=[BASE/v/'seeds'/(cid+'.json') for v in ('formal-ground-truth-r1','formal-ground-truth-r2','formal-ground-truth-r3')]
        source_file=next(p for p in reversed(source_files) if p.exists())
        original=read(source_file);merged={**original,**seed}
        r=b.base(cid,'ground_truth_seed',merged)
        r['definition']={'name':cid,'initial_state':'accepted_original_initial_state','changes':[],
            'controller':merged.get('controller'),'instruction_granularity':merged.get('instruction_granularity'),
            'acceptance_criteria':merged['criteria'],'original_seed_record':merged}
        r['ground_truth']={'verdict':seed['baseline_consistency'],'oracle_valid':True,'taxonomy':[],
            'scope':merged.get('effect_truth_scope'),'task_outcome':read(ROOT/seed['private_evidence']/'external/evaluation.json'),
            'basis':'Existing accepted seed release and captured evaluation; no new execution or oracle rerun.'}
        r['execution']=b.evidence(OUT/'ground-truth',cid,ROOT/seed['private_evidence'],seed['retrieval_sha256'])
        r['execution'].update({'initial_state_hash':merged.get('initial_hash'),'final_state_hash':merged.get('final_hash')})
        r['assessment']['selection_basis']='All accepted formal normal seeds; not selected by detector verdict.'
        r['assessment']['related_A_baseline_runs']=[{'case_id':x['case_id'],'run_ref':x['run_ref'],'rules':x['prediction'],
            'v3_inferred':reviews[x['case_id']]['inferred_verdict'] if x['case_id'] in reviews else None}
            for x in baselines if designs[x['case_id']]['seed_id']==cid]
        r['provenance']=[formal_ref,b.ref(source_file),b.ref(ROOT/seed['private_evidence']/'external/evaluation.json')]
        records['ground-truth'].append(r)
    for row in kept:
        cid=row['case_id'];d=designs[cid];seed=seeds[d['seed_id']];review=reviews.get(cid)
        r=b.base(cid,'legal_variation',seed)
        r['definition']={'name':d['name'],'initial_state':d['initial_state'],'changes':deepcopy(d['intervention_steps']),
            'controller':seed.get('controller'),'instruction_granularity':seed.get('instruction_granularity'),
            'parent_seed_record':f'{relative(OUT)}/ground-truth/records/{seed["id"]}.json',
            'source_design_snapshot':deepcopy(d),'execution_status':'executed_oracle_valid',
            'snapshot_notice':'Historical planned status/null truth inside source_design_snapshot is not current execution truth.'}
        r['ground_truth']={'verdict':row['truth'],'oracle_valid':row['oracle_valid'],'taxonomy':[],
            'scope':seed.get('effect_truth_scope'),'task_outcome':deepcopy(row['task_outcome']),
            'basis':'Independent execution oracle in legal-controls-execution-r2; not the intended mutation or LLM verdict.'}
        r['execution']=b.evidence(OUT/'legal-variations',cid,ROOT/row['run_ref'])
        r['execution']['applied_operators']=row['applied_operators']
        r['assessment']={'rules':{'verdict':row['prediction'],'taxonomy':row['taxonomy'],'reasons':row['reasons']},
            'llm':None,'used_verdict':review['inferred_verdict'] if review else row['prediction'],
            'selection_basis':'Post-hoc exclusion of latest v3 inferred U; never reinterpret this as truth validity.'}
        if review:
            response=REVIEW/'responses/v3-general/comparison'/(review['id']+'.json')
            r['assessment']['llm']={'version':'v3-general','inferred_verdict':review['inferred_verdict'],
                'evidence_verdict':review['evidence_verdict'],'response':b.ref(response)}
        r['provenance']=[legal_ref,review_ref,b.ref(LEGAL/'cases'/(cid+'.json')),b.ref(DESIGN/'cases'/(cid+'.json'))]
        records['legal-variations'].append(r)
    for name,items in records.items():
        folder=OUT/name;items.sort(key=lambda r:r['id'])
        for r in items:validate(r);write(folder/'records'/(r['id']+'.json'),r)
        with (folder/'records.jsonl').open('x',encoding='utf-8') as f:
            for r in items:f.write(json.dumps(r,ensure_ascii=False,separators=(',',':'))+'\n')
        write(folder/'manifest.json',{'schema_version':'agentdlp-consolidated-v1','count':len(items),
            'by_source':dict(Counter(r['source']['platform'] for r in items)),
            'records':[{'id':r['id'],'seed_id':r['seed_id'],'file':'records/'+r['id']+'.json',
                'sha256':file_hash(folder/'records'/(r['id']+'.json'))} for r in items]})
    write(OUT/'legal-variations/exclusions.json',{'candidate_legal_variations':157,'excluded_count':5,
        'cases':[{'case_id':r['case_id'],'seed_id':designs[r['case_id']]['seed_id'],'truth':r['truth'],
            'oracle_valid':r['oracle_valid'],'v3_verdict':reviews[r['case_id']]['inferred_verdict'],
            'reason':reviews[r['case_id']]['reason'],'original_case':relative(LEGAL/'cases'/(r['case_id']+'.json'))} for r in excluded],
        'normal_baseline_not_in_legal_denominator':'V5D-24-A01 is also U but is a normal rerun, not a legal variation.'})
    summary={'ground_truth_seeds':43,'public_seeds':40,'project_derived_seeds':3,'legal_variations':152,
        'total_records':195,'excluded_legal_variations':5,'normal_A_reruns_linked_not_duplicated':len(baselines),
        'raw_archive_file_references':b.archived_file_count,'raw_evidence_policy':'Kept in original locations; repo-relative SHA256-addressed indexes.',
        'not_in_scope':'B/C deviation runs, older duplicate releases, design-only unexecuted cases; not all oracle-labelled executions.',
        'dataset_caveat':'Legal subset is filtered by latest detector output; not an unbiased accuracy evaluation.'}
    write(OUT/'manifest.json',summary)
    for name,digest in b.sources.items():
        if file_hash(ROOT/name)!=digest:raise ValueError('source_drift')
    write(OUT/'freeze.json',{'sources':b.sources,'files':{relative(p):file_hash(p) for p in sorted(OUT.rglob('*')) if p.is_file()},
        'builder':{'path':relative(Path(__file__)),'sha256':file_hash(Path(__file__))}})
    print(json.dumps(summary,ensure_ascii=False,indent=2))


if __name__=='__main__':main()
