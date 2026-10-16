"""Add executed B/C cases and paired evidence views without rewriting v1 data."""
from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
import jsonschema

from .consolidate_current import ROOT, OUT, BASE, SCHEMA as V1, read, safe_path
from .common import file_hash
from consistency.evidence_pilot_v1.postflight import verify

DESIGN=BASE/'intervention-design-r2'
EXEC=BASE/'intervention-execution-r1'
FORMAL=BASE/'formal-ground-truth-r3'
BC=ROOT/'artifacts/reports/bc-evidence-pilot-v1-20260913'
A=ROOT/'artifacts/reports/evidence-loss-pilot-v1-20260913'
LIVE=ROOT/'artifacts/reports/evidence-baseline-v1-live-final-r1/manifest.json'
FOLDERS={'B':'group-b','C':'group-c'}

V2=deepcopy(V1)
V2['title']='AgentDLP executed intervention record v2'
V2['properties']['schema_version']={'const':'agentdlp-consolidated-v2'}
V2['properties']['kind']={'enum':['single_mechanism_case','combined_mechanism_case']}
V2['properties']['ground_truth']['properties']={
    'verdict':{'enum':['Consistent','Inconsistent']},'oracle_valid':{'const':True},
    'taxonomy':{'type':'array','uniqueItems':True,'items':{'enum':[f'T{i}' for i in range(1,9)]}}}
UNION={'$schema':'https://json-schema.org/draft/2020-12/schema','title':'AgentDLP consolidated benchmark v2','oneOf':[V1,V2]}


def rel(path):return str(path.relative_to(ROOT))


def write(path,data):
    path.parent.mkdir(parents=True,exist_ok=True)
    if path.exists():
        if read(path)!=data:raise ValueError('conflicting_existing_generated_file:'+rel(path))
        return
    with path.open('x',encoding='utf-8') as f:json.dump(data,f,ensure_ascii=False,indent=2)


def validate_record(r):
    jsonschema.validate(r,UNION)
    if r['schema_version']=='agentdlp-consolidated-v2':
        group=r['definition']['group'];tags=r['ground_truth']['taxonomy']
        if group not in FOLDERS:raise ValueError('invalid_group')
        if (r['ground_truth']['verdict']=='Consistent')!= (len(tags)==0):raise ValueError('truth_taxonomy_conflict')
        if r['definition']['execution_status']!='executed_oracle_valid':raise ValueError('unexecuted_case')
        if not r['definition']['mechanism_ids']:raise ValueError('missing_mechanism')


class Archive:
    def __init__(self):self.sources={};self.payload_cache={};self.references=0;self.unique_bytes=0
    def ref(self,path):
        digest=file_hash(path);name=rel(path)
        if name in self.sources and self.sources[name]!=digest:raise ValueError('source_changed')
        self.sources[name]=digest
        return {'path':name,'sha256':digest,'bytes':path.stat().st_size}
    def copy(self,source,target):
        reference=self.ref(source);target.parent.mkdir(parents=True,exist_ok=True)
        if not target.exists():shutil.copyfile(source,target)
        if file_hash(target)!=reference['sha256']:raise ValueError('copy_mismatch')
        return {'path':rel(target),'sha256':reference['sha256'],'source':reference}
    def payload_hash(self,path):
        stat=path.stat();key=(stat.st_dev,stat.st_ino,stat.st_size,stat.st_mtime_ns)
        if key not in self.payload_cache:
            h=hashlib.sha256()
            with path.open('rb') as f:
                for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
            after=path.stat()
            if (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)!=key:raise ValueError('payload_changed_during_hash')
            self.payload_cache[key]=h.hexdigest();self.unique_bytes+=stat.st_size
        self.references+=1
        return self.payload_cache[key]
    def evidence(self,folder,cid,run,expected=None):
        retrieval=self.ref(run/'retrieval.json')
        if expected and retrieval['sha256']!=expected:raise ValueError('retrieval_hash_mismatch')
        files=[]
        for name,digest in read(run/'retrieval.json')['files'].items():
            path=safe_path(run,name)
            if self.payload_hash(path)!=digest:raise ValueError('payload_hash_mismatch:'+rel(path))
            files.append({'path':rel(path),'sha256':digest,'bytes':path.stat().st_size})
        index=folder/'evidence-indexes'/(cid+'.json')
        write(index,{'run_root':rel(run),'retrieval':retrieval,'files':files,
            'verification':'Every listed payload rehashed during this consolidation; identical unchanged inodes share a streaming hash check. Raw files stay in original locations.'})
        return {'run_id':run.name,'root':rel(run),'retrieval':retrieval,
            'evidence_index':{'path':rel(index),'sha256':file_hash(index),'bytes':index.stat().st_size}}


def emit_records(folder,records):
    records.sort(key=lambda r:r['id'])
    for r in records:write(folder/'records'/(r['id']+'.json'),r)
    text=''.join(json.dumps(r,ensure_ascii=False,separators=(',',':'))+'\n' for r in records)
    p=folder/'records.jsonl'
    if p.exists():
        if p.read_text(encoding='utf-8')!=text:raise ValueError('jsonl_conflict')
    else:
        with p.open('x',encoding='utf-8') as f:f.write(text)
    write(folder/'manifest.json',{'count':len(records),'records':[{'id':r['id'],'file':'records/'+r['id']+'.json',
        'sha256':file_hash(folder/'records'/(r['id']+'.json'))} for r in records]})


def base_record(cid,group,seed,design):
    return {'schema_version':'agentdlp-consolidated-v2','id':cid,
        'kind':'single_mechanism_case' if group=='B' else 'combined_mechanism_case',
        'seed_id':seed['id'],'source':deepcopy(seed['source']),
        'definition':{'group':group,'name':design['name'],'initial_state':design['initial_state'],
            'changes':deepcopy(design['intervention_steps']),'mechanism_ids':design['mechanism_ids'],
            'mechanism_catalog':'intervention-design-r2','source_cards':design['source_cards'],
            'parent_seed_record':rel(OUT/'ground-truth/records'/(seed['id']+'.json')),
            'execution_status':'executed_oracle_valid','source_design_snapshot':deepcopy(design),
            'snapshot_notice':'Historical intended labels and planned status are not current actual truth.'},
        'ground_truth':{},'execution':{},
        'assessment':{'rules':None,'llm':None,'used_verdict':None,
            'selection_basis':'All executed oracle-valid B/C cases from the existing releases, independent of detector predictions; retain actual C outcomes.'},
        'provenance':[]}


def build():
    if (OUT/'benchmark-freeze.json').exists():raise ValueError('benchmark_already_frozen')
    verify(ROOT,read(OUT/'freeze.json')['files'])
    verify(EXEC,read(EXEC/'freeze.json')['files'])
    execution_freeze=read(EXEC/'freeze.json')
    verify(ROOT/execution_freeze['private_evaluation_root'],execution_freeze['private_files'])
    for source in (A,BC):verify(ROOT,read(source/'freeze.json')['files'])
    archive=Archive();seeds={p.stem:read(p) for p in (OUT/'ground-truth/records').glob('*.json')}
    assert len(seeds)==43
    manifest=read(EXEC/'manifest.json');items={'B':[],'C':[]};byid={};activation=Counter()
    primary_refs=[archive.ref(EXEC/'manifest.json'),archive.ref(FORMAL/'manifest.json'),archive.ref(DESIGN/'manifest.json')]
    for row in manifest['cases']:
        if row['group'] not in FOLDERS:continue
        cid=row['case_id'];group=row['group'];design=read(DESIGN/'cases'/(cid+'.json'))
        if row['status']!='executed_oracle_valid':raise ValueError('invalid_canonical_run')
        attempt=ROOT/manifest['private_evaluation_root']/'attempts'/(row['selected_attempt']+'.json')
        evaluated=read(attempt);oracle=evaluated['oracle'];truth=oracle['truth']
        if not oracle['oracle_valid'] or truth['consistency']!=row['truth']['consistency']:raise ValueError('oracle_disagreement')
        if set(truth.get('violation_tags',[]))!=set(row['truth'].get('violation_tags',[])):raise ValueError('taxonomy_disagreement')
        run=ROOT/evaluated['run_ref'];seed=seeds[row['seed_id']]
        r=base_record(cid,group,seed,design)
        r['ground_truth']={'verdict':truth['consistency'],'oracle_valid':True,'taxonomy':truth.get('violation_tags',[]),
            'scope':oracle['scope'],'task_outcome':truth.get('task'),
            'basis':'Original independent raw-chain oracle for the exact selected execution; not intervention intent or detector output.',
            'oracle_snapshot':oracle,'oracle_reference':archive.ref(attempt)}
        r['execution']=archive.evidence(OUT/FOLDERS[group],cid,run,evaluated['retrieval_sha256'])
        r['execution'].update({'evidence_profile':manifest['evidence_profile'],'activation':deepcopy(row['activation']),
            'all_attempt_ids':row['attempts'],'selected_attempt':row['selected_attempt'],
            'initial_state_hash_source':'See retrieval-pinned initial-state/native state witnesses; not inferred from the plan.'})
        r['assessment']['rules']={'verdict':row['rules_verdict'],'taxonomy':row['rules_taxonomy'],
            'version':'original433-r1','canonical_detector_view_sha256':row['canonical_detector_view_sha256']}
        r['provenance']=primary_refs+[archive.ref(EXEC/'cases'/(cid+'.json')),archive.ref(DESIGN/'cases'/(cid+'.json')),archive.ref(attempt)]
        if truth['consistency']=='Consistent':activation[row['activation']['status']]+=1
        validate_record(r);items[group].append(r);byid[cid]=r
        if len(byid)%25==0:print(json.dumps({'canonical_cases_verified':len(byid),'payload_references_checked':archive.references,'unique_bytes_hashed':archive.unique_bytes}),flush=True)
    for cid in ('V5D-41-B01','V5D-42-B01','V5D-43-B01'):
        design=read(DESIGN/'cases'/(cid+'.json'));record=read(FORMAL/'executions'/(design['run_id']+'.json'));oracle=record['oracle']
        if not oracle['oracle_valid'] or oracle['consistency']!='Inconsistent' or oracle['violation_tags']!=['T6']:raise ValueError('T6_invalid')
        r=base_record(cid,'B',seeds[design['seed_id']],design)
        r['ground_truth']={'verdict':oracle['consistency'],'oracle_valid':True,'taxonomy':oracle['violation_tags'],
            'scope':oracle['scope'],'task_outcome':oracle['task'],'oracle_snapshot':oracle,
            'basis':'Existing independent Gateway/Endpoint/native-state dependency oracle for this exact execution.',
            'oracle_reference':archive.ref(FORMAL/'executions'/(design['run_id']+'.json'))}
        r['execution']=archive.evidence(OUT/'group-b',cid,ROOT/record['evidence'],record['retrieval_sha256'])
        r['execution'].update({'evidence_profile':'verified_explicit_dependency_three_vm','activation':{'operator':'reverse_dependency','is_ground_truth':False}})
        r['provenance']=primary_refs+[archive.ref(DESIGN/'cases'/(cid+'.json')),archive.ref(FORMAL/'executions'/(design['run_id']+'.json'))]
        validate_record(r);items['B'].append(r);byid[cid]=r
    assert len(items['B'])==247 and len(items['C'])==42
    # Later instrumented executions remain separate, never replace original labels.
    related=[]
    for row in read(LIVE)['rows']:
        if row['case_id'] not in byid:continue
        if not row['oracle_valid']:raise ValueError('invalid_related_run')
        cid=row['case_id'];rid='observer-'+cid
        execution=archive.evidence(OUT/'related-executions',rid,ROOT/row['run'])
        r={'id':rid,'case_id':cid,'seed_id':byid[cid]['seed_id'],'execution':execution,
            'ground_truth':{'verdict':row['truth'],'taxonomy':row['oracle_taxonomy'],'oracle_valid':True,'basis':archive.ref(LIVE)},
            'observation_profile':{'label':'live_independent_observers','runtime':row['runtime'],'state_snapshots':row['state_snapshots']},
            'source_snapshot':row,'count_as_new_case':False}
        related.append(r)
        byid[cid]['execution'].setdefault('related_executions',[]).append(rel(OUT/'related-executions/records'/(rid+'.json')))
    emit_records(OUT/'related-executions',related)
    for group,rs in items.items():
        for r in rs:validate_record(r)
        emit_records(OUT/FOLDERS[group],rs)
    # Preserve the exact previously tested evidence views, not regenerated examples.
    views=[];unbuilt=[];noop={r['id'] for r in read(BC/'analysis.json')['no_op_views']}
    for source,cohort in ((A,'A'),(BC,'BC')):
        for row in read(source/'private/selection.json'):
            if cohort=='A' and row['split']=='regression':continue
            if row.get('status') not in (None,'prepared'):
                unbuilt.append(deepcopy(row));continue
            cid=row['case_id'];rid=row['id']
            parent=byid[cid]['seed_id'] if cohort=='BC' else row['seed_id']
            if cohort=='BC':parent_record=OUT/FOLDERS[byid[cid]['definition']['group']]/'records'/(cid+'.json')
            elif row['kind']=='normal':parent_record=OUT/'ground-truth/records'/(parent+'.json')
            else:parent_record=OUT/'legal-variations/records'/(cid+'.json')
            if not parent_record.exists():raise ValueError('missing_view_parent')
            packet=archive.copy(source/row['packet'],OUT/'evidence-views/packets'/(rid+'.json'))
            projection=read(source/'private/projections'/(rid+'.json'))
            if projection['source_run']!=row['run_ref']:raise ValueError('view_run_mismatch')
            v={'id':rid,'case_id':cid,'seed_id':parent,'cohort':cohort,'profile':row['profile'],
                'parent_record':archive.ref(parent_record),'execution_root':row['run_ref'],
                'retrieval':archive.ref(ROOT/row['run_ref']/'retrieval.json'),
                'ground_truth':{'verdict':row['truth'],'same_execution_truth':True,
                    'basis':archive.ref(ROOT/row['oracle_basis']) if cohort=='A' else archive.ref(ROOT/row['oracle_ref'])},
                'observation_source':row.get('stratum','live_independent_observers'),
                'projection':projection,'no_op':rid in noop,
                'effective_degraded':row['profile']!='full' and rid not in noop,
                'detector_input':packet,'input_boundary':'Frozen rule-informed review packet; includes rule diagnostics. NOT a rule-free evidence-only LLM baseline.',
                'split_status':'retrospective_development_exposure; no new held-out claim',
                'provenance':[archive.ref(source/'private/selection.json'),archive.ref(source/'private/projections'/(rid+'.json'))]}
            views.append(v)
    assert len(views)==130 and len(unbuilt)==12
    emit_records(OUT/'evidence-views',views)
    write(OUT/'evidence-views/unmaterialized.json',{'count':len(unbuilt),'cases':unbuilt,
        'reason':'Existing target-dependent projection cannot construct zero-native-action views; engineering coverage gap, not theoretical impossibility.'})
    write(OUT/'benchmark-schema.json',UNION)
    catalogs=[]
    for name in ('mechanisms.json','taxonomy.json','renumbering.json','oracle-contract.json','applicability.json'):
        catalogs.append(archive.copy(DESIGN/name,OUT/'catalog'/name))
    assessments=[]
    for folder in ('bc-evidence-pilot-v1-20260913','prompt-revision-v6-20260913','all-review-v6-20260913'):
        path=ROOT/'artifacts/reports'/folder
        assessments.append({'name':folder,'summary':archive.ref(path/'summary.json'),'freeze':archive.ref(path/'freeze.json'),
            'role':'Historical assessment only; never ground truth or universal benchmark score.'})
    write(OUT/'assessments/manifest.json',{'assessments':assessments,'separate_from_task_input':True})
    all_records=[read(p) for name in ('ground-truth','legal-variations','group-b','group-c') for p in (OUT/name/'records').glob('*.json')]
    assert len(all_records)==484 and len({r['id'] for r in all_records})==484
    for r in all_records:validate_record(r)
    coverage={group:{'count':len(rs),'truth':dict(Counter(r['ground_truth']['verdict'] for r in rs)),
        'source':dict(Counter(r['source']['platform'] for r in rs)),
        'taxonomy':dict(sorted(Counter(t for r in rs for t in r['ground_truth']['taxonomy']).items())),
        'mechanisms':dict(sorted(Counter(m for r in rs for m in r['definition']['mechanism_ids']).items()))} for group,rs in items.items()}
    summary={'version':'agentdlp-benchmark-v5-consolidated-r1','status':'local_frozen_benchmark_catalog',
        'counts':{'ground_truth_seeds':43,'legal_variations':152,'group_b':247,'group_c':42,'total_records':484,
            'related_executions_not_extra_cases':len(related),'evidence_views_not_extra_cases':len(views),
            'effective_degraded_views':sum(v['effective_degraded'] for v in views),'no_op_views':sum(v['no_op'] for v in views),'unmaterialized_views':12},
        'truth_counts':dict(Counter(r['ground_truth']['verdict'] for r in all_records)),
        'groups':coverage,'B_actual_C_activation_counts':dict(activation),
        'schema':rel(OUT/'benchmark-schema.json'),'collections':{k:rel(OUT/k/'manifest.json') for k in ('ground-truth','legal-variations','group-b','group-c')},
        'legacy_v1_manifest':rel(OUT/'manifest.json'),'legacy_v1_freeze':rel(OUT/'freeze.json'),
        'views':rel(OUT/'evidence-views/manifest.json'),'catalog_snapshots':catalogs,
        'policies':{'truth':'Actual independent execution oracle; group/activation/prediction never substitutes for truth.',
            'canonical_runs':'Original selected B/C runs plus three actual T6 derived runs; later four observer runs linked separately.',
            'raw_evidence':'Repo-relative hash-addressed existing archives, not copied; NOT standalone portable distribution.',
            'selection':'All existing B/C retained, including actual C. A legal collection keeps historical post-hoc filtering unchanged.',
            'splits':'No new blind train/test split; preserve development exposure. Group future splits by seed and derivation family.',
            'contribution':'Derived benchmark construction: public-task provenance, real cross-layer execution truth, mechanism interventions and paired evidence projections. Not a new public task corpus or reproduction of all external incidents.'}}
    write(OUT/'benchmark-manifest.json',summary)
    for name,digest in archive.sources.items():
        if file_hash(ROOT/name)!=digest:raise ValueError('source_drift')
    verify(ROOT,read(OUT/'freeze.json')['files'])
    write(OUT/'benchmark-validation.json',{'records_schema_checked':484,'B_C_cases':289,'actual_truth_I':241,'actual_truth_C':48,
        'old_v1_files_unchanged':397,'raw_payload_references_rehashed':archive.references,
        'unique_unchanged_inodes_hashed':len(archive.payload_cache),'unique_payload_bytes_hashed':archive.unique_bytes,
        'A_old_payloads':'Existing A collection files verified; original A raw payloads not all rehashed by this extension.',
        'independent_oracle_rerun':False,'new_VM_runs':0,'new_API_calls':0})
    write(OUT/'benchmark-freeze.json',{'sources':archive.sources,
        'files':{rel(p):file_hash(p) for p in sorted(OUT.rglob('*')) if p.is_file() and p.suffix!='.md'},
        'builder':{'path':rel(Path(__file__)),'sha256':file_hash(Path(__file__))}})
    print(json.dumps({'counts':summary['counts'],'truth':summary['truth_counts'],'groups':coverage,
        'validation':read(OUT/'benchmark-validation.json')},ensure_ascii=False,indent=2))


if __name__=='__main__':build()
