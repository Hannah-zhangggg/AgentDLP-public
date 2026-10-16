"""Trusted host loader: allowlisted raw facts only; no labels/expected ledgers.

Historical state projection is explicitly OFFLINE, not proof an observer was
deployed in those old runs. Live journals are hash-pinned by SSH retrieval.
"""
from collections import defaultdict
from copy import deepcopy
import base64
import hashlib
import json
from pathlib import Path
from .collectors import canonical, sha
from consistency.dataset_v5_formal.common import file_hash


def read(path): return json.loads(Path(path).read_text())
def lines(path): return [json.loads(s) for s in Path(path).read_text().splitlines() if s.strip()] if Path(path).exists() else []


def base_view(run):
    """Read captured bytes directly. Never rewrite placeholders inside content.

    This profile uses the controlled Provider JSON/SSE envelope, not arbitrary
    providers' fragmented tool-argument streams. Labels and fault plans are not
    accessed. Source selects a pinned adapter, not an expected answer.
    """
    run=Path(run);pins=read(run/'retrieval.json')['files'];issues=[]
    allowed=['gateway.json','external/native-events.jsonl','external/closure.json',
             'endpoint/mcp-sent.jsonl','external/admission-decisions.jsonl','external/transport-failures.jsonl']
    for name in allowed:
        if (run/name).exists() and file_hash(run/name)!=pins.get(name):issues.append('capture_hash:'+name)
    instructions,reports=[],{}
    for flow in read(run/'gateway.json')['flows']:
        raw=base64.b64decode(flow['response_body_base64'],validate=True)
        if hashlib.sha256(raw).hexdigest()!=flow['raw_response_sha256']:issues.append('gateway_hash')
        if flow['kind']!='provider' or flow['status']!=200:continue
        for message in flow['request'].get('messages',[]):
            if message.get('role')=='tool':reports[message['tool_call_id']]=message['content']
        text=raw.decode('utf-8')
        objects=[json.loads(text)] if text.lstrip().startswith('{') else [json.loads(s[6:]) for s in text.splitlines() if s.startswith('data: ') and s[6:]!='[DONE]']
        for obj in objects:
            for choice in obj.get('choices',[]):
                for call in choice.get('message',choice.get('delta',{})).get('tool_calls',[]):
                    args=json.loads(call['function']['arguments'])
                    if args.pop('_call_ref',None)!=call['id']:issues.append('instruction_binding')
                    instructions.append({'call_ref':call['id'],'tool':call['function']['name'].removeprefix('fixture_'),'arguments':args})
    closure=run/'external/closure.json'
    return {'source':read(run/'run.json')['source'],'profile':'raw_gateway_native_facts','issues':issues,
        'instructions':instructions,'events':[{k:n[k] for k in ('call_ref','tool','arguments','result')} for n in lines(run/'external/native-events.jsonl')],
        'model_reports':reports,'deliveries':{r['call_ref']:r['result'] for r in lines(run/'endpoint/mcp-sent.jsonl')},
        'honest_rejections':[r['call_ref'] for r in lines(run/'external/admission-decisions.jsonl') if r['decision']=='rejected_unavailable'],
        'honest_transport_failures':[r['call_ref'] for r in lines(run/'external/transport-failures.jsonl')],
        'closed':closure.exists() and read(closure)['complete'] is True}


def decode_journal(rows):
    issues, events, children, services, states = [], [], [], [], []
    previous, state = '0'*64, None
    before_native, before_api = {}, {}
    native, apis, starts = {}, {}, []
    for index, record in enumerate(rows):
        row = deepcopy(record)
        claimed = row.pop('sha256', None)
        if row.get('sequence') != index or row.get('previous') != previous or sha(row) != claimed:
            issues.append('observer_sequence_or_hash'); break
        previous = claimed
        row['evidence_id'] = 'observer:' + str(index)
        kind, ref = row['kind'], row.get('call_ref')
        if kind == 'observer_started':starts.append(row)
        if kind in ('state_initial','state_delta'):
            if kind == 'state_initial':
                if state is not None:issues.append('duplicate_initial_state')
                state = row['objects']
            else:
                if state is None or sha(state) != row['before_sha256']:
                    issues.append('state_continuity');break
                state=dict(state)
                seen=set()
                for change in row['changes']:
                    key=change['object']
                    if key in seen or canonical(state.get(key)) != canonical(change['before']):issues.append('state_delta_conflict')
                    seen.add(key)
                    if change['after'] is None:state.pop(key,None)
                    else:state[key]=change['after']
            if sha(state)!=row['state_sha256']:issues.append('state_hash')
            snapshot={'objects':state, 'complete':row['complete'], 'issues':row['issues'],
                      'evidence_id':row['evidence_id'], 'observer':row['observer']}
            phase=row['phase']
            if phase=='native_before':before_native[ref]=snapshot
            elif phase=='api_before':before_api[ref]=snapshot
            elif phase=='native_after':
                matching=[e for e in events if e['call_ref']==ref]
                if matching:matching[-1]['state_after']=snapshot
                else:issues.append('unbound_native_state')
            elif phase=='api_after':
                matching=[e for e in children if e['call_ref']==ref]
                if matching:matching[-1]['state_after']=snapshot
                else:issues.append('unbound_api_state')
        elif kind in ('native_received','api_received'):
            item={k:row[k] for k in ('call_ref','occurrence','tool','arguments','evidence_id','monotonic_ns')}
            item['state_before']=(before_native if kind=='native_received' else before_api).get(ref)
            if kind=='native_received':events.append(item);native[row['occurrence']]=item
            else:
                item['parent_call_ref']=row.get('parent_call_ref');children.append(item);apis[row['occurrence']]=item
        elif kind in ('native_returned','api_returned'):
            item=(native if kind=='native_returned' else apis).get(row['occurrence'])
            if item is None or item['call_ref']!=ref:issues.append('unbound_native_return');continue
            if 'result' in item:issues.append('duplicate_native_return')
            for key in ('result','exception','exception_message'):
                if key in row:item[key]=row[key]
            item['return_evidence_id']=row['evidence_id'];item['end_ns']=row['monotonic_ns']
        elif kind=='api_delivered':
            matching=[e for e in children if e['call_ref']==ref]
            # A single logical API invocation may have several native receipts.
            for item in matching:
                if 'result' in row:item['delivered']=row['result']
                if 'exception' in row:item['delivered_exception']=row['exception']
                item['delivery_evidence_id']=row['evidence_id']
            if not matching:services.append(dict(row,kind='api_delivery_without_native'))
        elif kind in ('service_accepted','service_delivered'):services.append(row)
    closed=bool(rows and rows[-1]['kind']=='observer_closed' and rows[-1].get('complete') is True)
    if len(starts)!=1:issues.append('observer_start_missing_or_duplicate')
    clock=starts[0].get('environment_clock') if len(starts)==1 else None
    if len(starts)==1 and not starts[0].get('serial'):issues.append('concurrent_scope_not_supported')
    return {'events':events,'children':children,'observer_services':services,'observer_issues':issues,
            'observer_closed':closed,'environment_clock':clock,'observer_started':starts[0] if len(starts)==1 else None}


def _live_view(run):
    run=Path(run)
    view=base_view(run)
    pins=read(run/'retrieval.json')['files']
    name='external/observer-v1/receipts.jsonl'
    path=run/name
    view.update(profile='E0_live_independent_observers_v1', children=[],observer_closed=False, environment_clock=None)
    if not path.exists():
        view['observer_issues']=['observer_not_installed'];return view
    if file_hash(path)!=pins.get(name):
        view['issues'].append('observer_capture_hash');view['observer_issues']=['observer_integrity'];return view
    decoded=decode_journal(lines(path))
    view.update(decoded)
    # Independent native and observer receipts must agree before use.
    def basic(rows):return [{k:e.get(k) for k in ('call_ref','tool','arguments','result')} for e in rows]
    # Compare separate actual receipt streams, preserving exact content bytes.
    raw=lines(run/'external/native-events.jsonl')
    if canonical(basic(raw))!=canonical(basic(view['events'])):view['issues'].append('independent_native_receipt_conflict')
    view['issues'].extend(decoded['observer_issues'])
    trace_name='external/os-runtime-events.jsonl';trace_path=run/trace_name
    view['runtime_events']=[];view['runtime_closed']=False
    if trace_path.exists():
        if file_hash(trace_path)!=pins.get(trace_name):view['issues'].append('runtime_trace_capture_hash')
        else:
            runtime=lines(trace_path)
            if any(r.get('sequence')!=i for i,r in enumerate(runtime)):view['issues'].append('runtime_trace_sequence')
            view['runtime_closed']=bool(runtime and runtime[0]['kind']=='trace_started' and runtime[-1]['kind']=='trace_closed' and runtime[-1]['complete'])
            for record in runtime:
                if record['kind'] not in ('syscall','spawn'):continue
                record['evidence_id']='syscall:'+str(record['sequence'])
                time=record.get('start_ns',record.get('time_ns'))
                record['candidate_calls']=[e['call_ref'] for e in view['events'] if e.get('monotonic_ns',0)<=time<=e.get('end_ns',-1)]
                record['association_basis']='process_tree_and_time_window_not_private_causality'
                view['runtime_events'].append(record)
    # Preserve bytes used in file-content hashing; namespace normalization must
    # never rewrite file content while leaving its observed digest unchanged.
    return view


def _historical_view(run):
    """Offline-only explicit fact projection; never access program-api-intent."""
    run=Path(run);view=base_view(run)
    pins=read(run/'retrieval.json')['files']
    extra=run/'archive-retrieval.json'
    if extra.exists():pins.update(read(extra)['files'])
    def pinned(name):
        path=run/name
        if not path.exists():return None
        if file_hash(path)!=pins.get(name):view['issues'].append('historical_capture_hash:'+name);return None
        return read(path)
    view.update(profile='OFFLINE_archived_actual_state_projection_v1',children=[],observer_closed=view['closed'],
                environment_clock=None,observer_issues=[],observer_services=[])
    source=view['source'];previous=pinned('external/initial-state.json')
    raw=lines(run/'external/native-events.jsonl')
    for index,(event,native) in enumerate(zip(view['events'],raw)):
        before=pinned('external/before-states/'+str(index)+'.json')
        before=previous if before is None else before
        after=pinned('external/states/'+str(index)+'.json')
        event['evidence_id']='native:'+str(index);event['return_evidence_id']=event['evidence_id']
        event['occurrence']=index
        for key,snapshot,filename in (('state_before',before,'before-states'),('state_after',after,'states')):
            if snapshot is None or source=='AppWorld':continue
            objects=snapshot
            if source=='tau-bench':objects={t+'/'+str(k):v for t,rows in snapshot.items() for k,v in rows.items()}
            else:objects={k:dict(v,kind=v.get('kind','file')) for k,v in snapshot.items()}
            event[key]={'objects':objects,'complete':True,'issues':[],
                        'evidence_id':'archive:'+filename+':'+str(index),'observer':'historical_raw_state',
                        'directory_coverage':source!='MCPMark' or any(v.get('kind')=='directory' for v in snapshot.values())}
        previous=after
    if source=='AppWorld':
        children_path='external/child-native-events.jsonl'
        path=run/children_path
        if path.exists():
            if file_hash(path)!=pins.get(children_path):view['issues'].append('child_capture_hash')
            children=lines(path)
            deliveries_name='external/program-api-delivered.jsonl'
            deliveries_path=run/deliveries_name
            if deliveries_path.exists() and file_hash(deliveries_path)!=pins.get(deliveries_name):view['issues'].append('child_delivery_hash')
            deliveries={r['id']:r for r in lines(deliveries_path)}
            for i,row in enumerate(children):
                event={'call_ref':row['id'],'parent_call_ref':row['id'].split('/api-')[0], 'tool':row['tool'],
                       'arguments':row['arguments'],'evidence_id':'child:'+str(i), 'occurrence':i}
                if 'result' in row:event['result']=row['result']
                if 'exception' in row:event['exception']=row['exception']
                if 'result' in deliveries.get(row['id'],{}):event['delivered']=deliveries[row['id']]['result']
                view['children'].append(event)
        else:
            # Baseline has no intervening API hook; its original wrapper sees
            # callee return and the value returned to the caller at one boundary.
            name='external/native-api-events.jsonl';path=run/name
            if path.exists() and file_hash(path)!=pins.get(name):view['issues'].append('child_capture_hash')
            for i,row in enumerate(lines(path)):
                args=deepcopy(row['arguments']);kwargs=args.pop('kwargs',{})
                app=args.pop('_app_name',None);api=args.pop('_api_name',None)
                merged=dict(args,**kwargs)
                data=merged.pop('data',{})
                view['children'].append({'call_ref':row['id'],'parent_call_ref':row['parent_call_ref'],
                    'tool':str(app)+'.'+str(api),'arguments':{'_app_name':app,'_api_name':api,'data':data,
                    'raise_on_failure':merged.get('raise_on_failure')}, 'result':row.get('result'),
                    'delivered':deepcopy(row.get('result')),'evidence_id':'child:'+str(i),'occurrence':i})
    return view


def guarded_view(function,run,profile):
    try:return function(run)
    except (OSError,ValueError,KeyError,IndexError,TypeError,AttributeError) as exc:
        return {'source':'unknown','profile':profile,'issues':['evidence_read_or_parse_failure:'+type(exc).__name__],
            'instructions':[],'events':[],'children':[],'closed':False,'observer_closed':False,
            'observer_issues':['evidence_unavailable'],'deliveries':{},'model_reports':{}}


def live_view(run):return guarded_view(_live_view,run,'E0_live_independent_observers_v1')
def historical_view(run):return guarded_view(_historical_view,run,'OFFLINE_archived_actual_state_projection_v1')
