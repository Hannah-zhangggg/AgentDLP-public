"""Existing detector and DeepSeek review_U pipeline; no oracle or injection inputs."""
import sys,json,hashlib,time,argparse,gzip
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor,as_completed
ROOT=Path(__file__).resolve().parents[1];REPO=ROOT.parents[1]
sys.path.insert(0,str(REPO))
from adapter import load,read
from consistency.evidence_baseline_v1.detector import detect
from consistency.benchmark_six_v1.experiment import public_packet,safe_detect,accepted_verdict
from consistency.benchmark_six_v1.encoding import pack,API_MAX_CHARS
from consistency.benchmark_six_v1.transport import request
from consistency.evidence_ablation_v1.projection import project
from consistency.evidence_ablation_v2.semantics import project_contract,semantic_rules,PROFILES,NEW_PROFILES

def dump(path,value):
 path.parent.mkdir(parents=True,exist_ok=True)
 path.write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def prepare(phase):
 index=[];output=ROOT/'detector'/phase
 for job in read(ROOT/'private/run-plan.json'):
  if job['phase']!=phase:continue
  run=ROOT/phase/job['case']/job['condition']/('rep%02d'%job['repetition'])
  if phase=='pilot' and job['case']=='Case1_modify_address' and job['condition']=='normal':run=run.parent/'rep01-attempt04'
  if not (run/'retrieval.json').exists():continue
  v,c,a=load(run)
  runkey=hashlib.sha256(str(run.relative_to(ROOT)).encode()).hexdigest()[:20]
  dump(output/'audits'/(runkey+'.json'),a)
  # Keep exact full view for reproducibility; derived views reconstruct deterministically.
  vp=output/'views'/(runkey+'.json.gz');vp.parent.mkdir(parents=True,exist_ok=True)
  with gzip.open(vp,'wt',encoding='utf-8') as f:json.dump(v,f)
  dump(output/'contracts'/(runkey+'.json'),c)
  start=time.perf_counter();full=safe_detect(v);full_seconds=time.perf_counter()-start
  for profile in PROFILES:
   pview=v;pc=c;removed=[];gating=[]
   start=time.perf_counter()
   if profile=='full':rules=full
   elif profile in NEW_PROFILES:pc,removed=project_contract(c,profile);rules,gating=semantic_rules(v,full,profile)
   else:pview,removed=project(v,profile);rules=safe_detect(pview)
   seconds=full_seconds if profile=='full' else time.perf_counter()-start
   packet=pack(public_packet(pview,pc));key=hashlib.sha256((runkey+'/'+profile).encode()).hexdigest()[:24]
   packetpath=output/'inputs'/(key+'.json');rulepath=output/'rules'/(key+'.json')
   if packetpath.exists() and read(packetpath)!=packet:raise RuntimeError('Prepared input drift')
   dump(packetpath,packet);dump(rulepath,rules)
   row={'id':key,'run_key':runkey,'run':str(run.relative_to(ROOT)).replace('\\','/'),'profile':profile,'rule':rules['verdict'],'rule_seconds':seconds,'removed':removed,'gating':gating,'applicable':profile=='full' or bool(removed),'input':str(packetpath.relative_to(output)).replace('\\','/'),'packet_sha256':sha(packetpath),'packet_chars':len(json.dumps(packet,ensure_ascii=False)),'source_issues':a['issues']}
   index.append(row)
  print(json.dumps({'prepared':runkey,'case':job['case'],'condition':job['condition'],'rule_full':full['verdict'],'audit':a}),flush=True)
 dump(output/'index.json',index)
 dump(output/'input-freeze.json',{str(p.relative_to(output)).replace('\\','/'):sha(p) for folder in ('inputs','rules','audits','contracts','views') for p in (output/folder).glob('*')})

def run_api(phase,workers,limit):
 output=ROOT/'detector'/phase;rows=read(output/'index.json');prompt=(ROOT/'protocol/detector-prompt.txt').read_text(encoding='utf-8-sig')
 for name,digest in read(output/'input-freeze.json').items():
  if sha(output/name)!=digest:raise RuntimeError('Frozen input changed '+name)
 pending=[r for r in rows if r['applicable'] and r['rule']=='Uncertain' and not (output/'responses'/(r['id']+'.json')).exists()]
 if limit:pending=pending[:limit]
 def one(row):
  key=row['id'];path=output/'responses'/(key+'.json');packet=read(output/row['input']);attempts=[]
  if row['packet_chars']>API_MAX_CHARS:answer={'status':'input_budget_exceeded','screen_errors':['input_budget_exceeded']}
  else:
   for n in range(2):
    ap=output/'attempts'/(key+f'.{n+1}.json');marker=ap.with_suffix('.started.json')
    if ap.exists():answer=read(ap)
    elif marker.exists():raise RuntimeError('Ambiguous prior API request, no silent replay '+key)
    else:
     dump(marker,{'started':time.time(),'packet_sha256':row['packet_sha256'],'prompt_sha256':sha(ROOT/'protocol/detector-prompt.txt')})
     answer=request(packet,prompt);dump(ap,answer)
    attempts.append(str(ap.relative_to(output)).replace('\\','/'))
    if answer.get('http_status') not in (429,500,502,503,504):break
   if answer.get('http_status') in (401,402,403):raise RuntimeError('API authentication or quota blocked')
  dump(path,dict(answer,attempt_files=attempts,packet_sha256=row['packet_sha256'],prompt_sha256=sha(ROOT/'protocol/detector-prompt.txt')))
  return {'id':key,'status':answer['status'],'accepted':accepted_verdict(answer),'screen_errors':answer.get('screen_errors',[])}
 with ThreadPoolExecutor(max_workers=workers) as pool:
  for f in as_completed([pool.submit(one,r) for r in pending]):print(json.dumps(f.result()),flush=True)
 scored=[]
 for r in rows:
  response=output/'responses'/(r['id']+'.json')
  if not r['applicable']:pred=None;status='not_applicable'
  elif r['rule']!='Uncertain':pred=r['rule'];status='direct'
  elif response.exists():answer=read(response);pred=accepted_verdict(answer);status=answer['status'] if not answer.get('screen_errors') else 'rejected_output'
  else:pred=None;status='pending'
  scored.append(dict(r,hybrid=pred,api_status=status))
 dump(output/'decisions.json',scored)
 print(json.dumps({'views':len(scored),'pending':sum(r['api_status']=='pending' for r in scored),'new_responses':len(pending)}),flush=True)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('action',choices=['prepare','judge']);p.add_argument('--phase',default='formal');p.add_argument('--workers',type=int,default=4);p.add_argument('--limit',type=int);a=p.parse_args()
 if a.action=='prepare':prepare(a.phase)
 else:run_api(a.phase,a.workers,a.limit)
