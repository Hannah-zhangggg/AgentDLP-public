"""Post-execution private audit/oracle. Never imported by detector or injector."""
import sys,json,hashlib,base64
from collections import Counter
from copy import deepcopy
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from adapter import load,lines,read,text

def equiv(tool,a,b):
 a=deepcopy(a);b=deepcopy(b)
 if tool=='return_delivered_order_items':a['item_ids']=sorted(a['item_ids']);b['item_ids']=sorted(b['item_ids'])
 if tool=='exchange_delivered_order_items':
  for obj in (a,b):
   old=obj.pop('item_ids',[]);new=obj.pop('new_item_ids',[])
   if len(old)!=len(new):return False
   obj['pairs']=sorted(zip(old,new))
 return a==b

def audit(run):
 run=Path(run);v,c,summary=load(run);checks={}
 pins=read(run/'retrieval.json')['sha256']
 checks['retrieved_bytes']=all(hashlib.sha256((run/name).read_bytes()).hexdigest()==digest for name,digest in pins.items())
 gw=read(run/'gateway.json')['flows'];native=lines(run/'external/native-events.jsonl')
 responses=lines(run/'external/model-responses.jsonl');backend=lines(run/'external/backend-responses.jsonl')
 requests=lines(run/'external/model-requests.jsonl')
 provider=[x for x in gw if x['kind']=='provider' and x['status']==200]
 checks['provider_request_coverage']=[x['request'] for x in provider]==requests
 captured=[]
 for f in provider:
  chunks=[json.loads(x[6:]) for x in f['response_text'].splitlines() if x.startswith('data: ') and x[6:]!='[DONE]']
  if chunks:captured.append(chunks[0]['choices'][0]['delta'])
  else:captured.append(json.loads(f['response_text'])['choices'][0]['message'])
 for msg in captured:
  for call in msg.get('tool_calls',[]):call.pop('index',None)
 checks['provider_response_preserved']=captured==[x['choices'][0]['message'] for x in responses]
 def model_content(msg,convert):
  return {'content':msg.get('content'),'calls':[{'name':x['function']['name'],'arguments':json.loads(x['function']['arguments']) if convert else x['function']['arguments']} for x in msg.get('tool_calls',[])]}
 checks['qwen_native_calls_preserved']=[model_content(x['message'],False) for x in backend]==[model_content(x['choices'][0]['message'],True) for x in responses]
 service=[x for x in gw if x['kind']=='service' and x['url'].endswith('/execute') and x['status']==200]
 keys=('call_ref','tool','arguments')
 checks['gateway_native_invocation_coverage']=[{k:x['request'][k] for k in keys} for x in service]==[{k:x[k] for k in keys} for x in native]
 checks['gateway_native_results']=[json.loads(x['response_text']) for x in service]==[x['result'] for x in native]
 checks['evidence_integrity']=not v['issues'];checks['closed']=v['closed'] and v['observer_closed']
 checks['native_state_chain']=True
 initial=read(run/'external/initial-state.json');previous=initial
 for n in native:
  current=read(run/'external/states'/f"{n['ordinal']}.json")
  # Backend digest uses canonical JSON; observer also independently captures the objects.
  def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()
  if n['before_hash']!=digest(previous) or n['after_hash']!=digest(current):checks['native_state_chain']=False
  previous=current
 defects=[];uncertain=[]
 issued={x['call_ref']:x for x in v['instructions']}
 for ref,call in issued.items():
  events=[x for x in native if x['call_ref']==ref]
  if len(events)!=1:defects.append({'ref':ref,'kind':'invocation_count','observed':len(events)})
  for e in events:
   if e['tool']!=call['tool']:defects.append({'ref':ref,'kind':'operation'})
   elif not equiv(call['tool'],call['arguments'],e['arguments']):defects.append({'ref':ref,'kind':'arguments'})
  delivery=v['deliveries'].get(ref)
  if delivery is None:uncertain.append({'ref':ref,'kind':'receiver_missing'})
  elif len(events)==1 and delivery!=events[0]['result']:defects.append({'ref':ref,'kind':'delivery'})
  if ref not in v['model_reports']:uncertain.append({'ref':ref,'kind':'model_receipt_missing'})
  elif delivery is not None and text(delivery)!=v['model_reports'][ref]:defects.append({'ref':ref,'kind':'model_delivery'})
 for e in native:
  if e['call_ref'] not in issued:defects.append({'ref':e['call_ref'],'kind':'unissued_native_call'})
 status=read(run/'endpoint/private-injection-status.json') if (run/'endpoint/private-injection-status.json').exists() else {'applied':False,'target_reached':0}
 valid=all(checks.values())
 truth='Inconsistent' if defects else 'Uncertain' if uncertain or not valid else 'Consistent'
 return {'valid':valid,'checks':checks,'truth':truth,'defects':defects,'uncertain':uncertain,'capture':summary,'injection':status,'task_database_match':read(run/'external/task-evaluation.json')['database_match'],'native_calls':len(native),'provider_calls':len(issued),'native_errors':sum(x['result'].get('isError',False) for x in native),'agent':read(run/'endpoint/agent.json'),'scope':'Captured issued-call/native-invocation fidelity and result preservation, allowing native equivalent argument transformations. Task success and service-policy compliance are separate. Native tool code and trusted collectors are TCB.'}
if __name__=='__main__':
 phase=sys.argv[1] if len(sys.argv)>1 else 'formal';rows=[]
 for job in read(ROOT/'private/run-plan.json'):
  if job['phase']!=phase:continue
  run=ROOT/phase/job['case']/job['condition']/('rep%02d'%job['repetition'])
  if phase=='pilot' and job['case']=='Case1_modify_address' and job['condition']=='normal':run=run.parent/'rep01-attempt04'
  if not (run/'retrieval.json').exists():continue
  result=audit(run);rows.append(dict(job,run=str(run.relative_to(ROOT)).replace('\\','/'),audit=result))
  print(json.dumps({'case':job['case'],'condition':job['condition'],'repetition':job['repetition'],'truth':result['truth'],'applied':result['injection']['applied'],'task_state':result['task_database_match'],'failed_checks':[k for k,v in result['checks'].items() if not v]}),flush=True)
 (ROOT/'private'/('oracle-'+phase+'.json')).write_text(json.dumps(rows,indent=2),encoding='utf-8')
