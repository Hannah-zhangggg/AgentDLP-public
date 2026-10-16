"""Allowlisted capture adapter. Does not read fault plans, labels or task evaluators."""
import base64,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];REPO=ROOT.parents[1]
sys.path.insert(0,str(REPO))
from consistency.evidence_baseline_v1.loader import decode_journal
from consistency.evidence_baseline_v1.collectors import canonical
from consistency.benchmark_six_v1.experiment import public_contract

def read(p):return json.loads(Path(p).read_text(encoding='utf-8-sig'))
def lines(p):return [json.loads(x) for x in Path(p).read_text(encoding='utf-8-sig').splitlines() if x.strip()] if Path(p).exists() else []
def text(result):return '\n'.join(x['text'] for x in result.get('content',[]) if x.get('type')=='text')
def load(run):
 run=Path(run);pins=read(run/'retrieval.json')['sha256'];issues=[]
 def check(name,optional=False):
  p=run/name
  if not p.exists():
   if not optional:issues.append('missing_capture:'+name)
   return
  if hashlib.sha256(p.read_bytes()).hexdigest()!=pins.get(name):issues.append('capture_hash:'+name)
 for name in ('gateway.json','external/native-events.jsonl','external/closure.json','external/native-tool-schemas.json','external/observer-v1/receipts.jsonl','endpoint/hook-before.jsonl','endpoint/hook-after.jsonl','endpoint/mcp-received.jsonl','endpoint/mcp-sent.jsonl','endpoint/agent.json'):check(name)
 instructions=[];reports={};request_reports={}
 for flow in read(run/'gateway.json')['flows']:
  raw=base64.b64decode(flow['response_body_base64'],validate=True)
  if hashlib.sha256(raw).hexdigest()!=flow['raw_response_sha256']:issues.append('gateway_body_hash')
  if flow['kind']!='provider' or flow['status']!=200:continue
  for m in flow['request'].get('messages',[]):
   if m.get('role')=='tool':
    content=m.get('content');ref=m['tool_call_id']
    if isinstance(content,list) and all(x.get('type')=='text' for x in content):content='\n'.join(x['text'] for x in content)
    request_reports.setdefault(ref,[]).append(content)
    # The first observed receipt is retained; later context compaction is not a new delivery.
    reports.setdefault(ref,content)
  body=raw.decode('utf-8')
  chunks=[json.loads(body)] if body.lstrip().startswith('{') else [json.loads(x[6:]) for x in body.splitlines() if x.startswith('data: ') and x[6:]!='[DONE]']
  for chunk in chunks:
   for choice in chunk.get('choices',[]):
    for call in choice.get('message',choice.get('delta',{})).get('tool_calls',[]):
     fn=call['function'];instructions.append({'call_ref':call['id'],'tool':fn['name'].removeprefix('native_'),'arguments':json.loads(fn['arguments'])})
 journal=decode_journal(lines(run/'external/observer-v1/receipts.jsonl'))
 issues.extend(journal['observer_issues'])
 raw=lines(run/'external/native-events.jsonl')
 def basic(rows):return [{k:x.get(k) for k in ('call_ref','tool','arguments','result')} for x in rows]
 if canonical(basic(raw))!=canonical(basic(journal['events'])):issues.append('independent_native_conflict')
 before=lines(run/'endpoint/hook-before.jsonl');after=lines(run/'endpoint/hook-after.jsonl');sent=lines(run/'endpoint/mcp-sent.jsonl');received=lines(run/'endpoint/mcp-received.jsonl')
 lookup={x['call_ref']:x for x in instructions};deliveries={}
 for h in before:
  c=lookup.get(h['callID'])
  if c is None or h['tool']!='native_'+c['tool'] or canonical(h['arguments'])!=canonical(c['arguments']):issues.append('provider_hook_conflict')
 for r in received:
  matches=[h for h in before if h['callID']==r['call_ref'] and h['sessionID']==r['sessionID'] and h['tool']=='native_'+r['tool'] and canonical(h['arguments'])==canonical(r['arguments'])]
  if len(matches)!=1:issues.append('bridge_hook_binding_conflict')
 for h in after:
  ref=h['callID'];matches=[x for x in sent if x['call_ref']==ref]
  if len(matches)!=1:issues.append('receiver_sender_binding_conflict');continue
  # The pinned MCP after hook actually receives the MCP result, not flattened output.
  got=h['received']
  if canonical(got)!=canonical(matches[0]['result']):issues.append('receiver_sender_result_conflict');continue
  if ref in deliveries:issues.append('duplicate_delivery')
  deliveries[ref]=got
 agent=read(run/'endpoint/agent.json')
 closed=bool(read(run/'external/closure.json').get('complete') and agent['exit']==0 and not agent['timeout'])
 view=dict(source='tau-bench',profile='live_opencode_receiver_and_external_state_v1',issues=sorted(set(issues)),instructions=instructions,model_reports=reports,deliveries=deliveries,closed=closed,honest_rejections=[],honest_transport_failures=[],runtime_events=[],runtime_closed=False,**journal)
 contract={'native-tool-schemas.json':read(run/'external/native-tool-schemas.json'),'public-contract.json':read(ROOT/'protocol/public-contract.json'),'comparison_scope':'Instruction-execution fidelity under public tool semantics. Overall user-task success and conversational policy compliance are separate; do not infer a missing execution from an unissued future action.'}
 audit={'instructions':len(instructions),'native_events':len(raw),'before_hooks':len(before),'after_hooks':len(after),'delivered':len(deliveries),'model_received':len(reports),'issues':view['issues'],'closed':closed,'observer_closed':journal['observer_closed'],'repeated_model_receipts_changed':sum(any(x!=values[0] for x in values[1:]) for values in request_reports.values())}
 return view,contract,audit
