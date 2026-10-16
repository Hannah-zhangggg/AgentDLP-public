"""Offline rule, packet and saved-response replay. No provider requests."""
import argparse,base64,collections,concurrent.futures,gc,gzip,hashlib,json,os,socket,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from consistency.benchmark_six_v1.experiment import safe_detect,public_packet,accepted_verdict
from consistency.benchmark_six_v1.encoding import pack
from consistency.evidence_ablation_v1.projection import project
from consistency.evidence_ablation_v2.semantics import NEW_PROFILES,semantic_rules,project_contract
from consistency.llm_review_v1.packet import screen
def read(p):return json.loads(p.read_text())
def decode(x):
 if isinstance(x,dict):
  if '__adlp_type__' in x:
   t=x['__adlp_type__'];v=x['value']
   if t=='bytes':return base64.b64decode(v)
   if t=='tuple':return tuple(decode(y) for y in v)
   if t=='set':return set(decode(y) for y in v)
   raise ValueError(t)
  return {k:decode(v) for k,v in x.items()}
 if isinstance(x,list):return [decode(y) for y in x]
 return x
def load(h):
 if not h:return None
 p=ROOT/'local-data/blobs'/h[:2]/(h+'.json.gz');b=gzip.decompress(p.read_bytes())
 if hashlib.sha256(b).hexdigest()!=h:raise ValueError('Input hash mismatch '+h)
 obj=json.loads(b)
 if obj.get('format')!='agentdlp-json-graph-v1':return decode(obj)
 memo={}
 def visit(v):
  if not isinstance(v,dict) or '$ref' not in v:return v
  k=v['$ref']
  if k in memo:return memo[k]
  t,data=obj['nodes'][k]
  if t=='dict':
   ans={};memo[k]=ans;ans.update((visit(a),visit(b)) for a,b in data)
  elif t=='list':
   ans=[];memo[k]=ans;ans.extend(visit(y) for y in data)
  elif t=='str':ans=data
  elif t=='bytes':ans=base64.b64decode(data)
  elif t=='tuple':ans=tuple(visit(y) for y in data)
  elif t=='set':ans=set(visit(y) for y in data)
  else:raise ValueError(t)
  memo[k]=ans;return ans
 answer=visit(obj['root']);visit=None
 return answer
def prohibit_network(*args,**kwargs):raise RuntimeError('Network disabled during frozen replay')
def one_impl(row):
 # The worker receives input references only. Truth is joined by the parent after judgment.
 socket.create_connection=prohibit_network
 v=load(row['view']);c=load(row['contract']);profile=row['profile'];rules=safe_detect(v)
 if profile in NEW_PROFILES:
  rules,_=semantic_rules(v,rules,profile);c,_=project_contract(c,profile)
 elif profile!='full':v,_=project(v,profile);rules=safe_detect(v)
 packet=pack(public_packet(v,c));saved=load(row['packet']);errors=[]
 if packet!=saved:errors.append('packet_mismatch')
 if row.get('expected_rules') and rules!=load(row['expected_rules']):errors.append('rule_diagnostics_mismatch')
 result=rules['verdict'];response=load(row.get('response'));checked=False
 if result=='Uncertain':
  if response is None:errors.append('missing_fallback_response')
  else:
   if isinstance(response.get('attempts'),list):response=response['attempts'][-1] if response['attempts'] else response
   if 'status' not in response:errors.append('missing_raw_response');result=response.get('verdict','Uncertain')
   else:
    if response.get('status') in ('ok','invalid_response') and 'response' in response:
     actual=screen(packet,response['response']);checked=True
     if actual!=response.get('screen_errors',[]):errors.append('output_checks_mismatch')
    result=accepted_verdict(response)
 return {'id':row['id'],'rule':rules['verdict'],'hybrid':result,'packet_equal':packet==saved,'response_checked':checked,'errors':errors}

def one(row):
 result=one_impl(row);gc.collect();return result
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--suite',choices=['accuracy','evidence-ablation','live-cases','all'],default='all');p.add_argument('--workers',type=int,default=4);p.add_argument('--limit',type=int);p.add_argument('--output',type=Path,default=ROOT/'validation/replay.json');a=p.parse_args()
 suites=['accuracy','evidence-ablation','live-cases'] if a.suite=='all' else [a.suite];reports={};start=time.time()
 for suite in suites:
  rows=read(ROOT/'local-data'/suite/'index.json');gold={x['id']:x for x in read(ROOT/'evaluation'/(suite+'.json'))};rows=rows[:a.limit] if a.limit else rows;out=[]
  with concurrent.futures.ProcessPoolExecutor(max_workers=a.workers) as pool:
   for result in pool.map(one,rows,chunksize=1):
    target=gold[result['id']]
    for k in ['rule','hybrid']:
     if result[k]!=target[k]:result['errors'].append(k+'_verdict_mismatch')
    result['correct']=result['hybrid']==target['truth'];out.append(result)
    if len(out)%100==0:print(json.dumps({'suite':suite,'completed':len(out),'total':len(rows),'errors':sum(bool(x['errors']) for x in out)}),flush=True)
  reports[suite]={'views':len(out),'passed':all(not x['errors'] for x in out),'correct':sum(x['correct'] for x in out),'response_checks':sum(x['response_checked'] for x in out),'failures':[x for x in out if x['errors']]}
  print(json.dumps({suite:{k:v for k,v in reports[suite].items() if k!='failures'}}),flush=True)
 report={'passed':all(x['passed'] for x in reports.values()),'network':'disabled','mode':'fresh rules and packets, saved model responses','seconds':time.time()-start,'suites':reports}
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n')
 return 0 if report['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
