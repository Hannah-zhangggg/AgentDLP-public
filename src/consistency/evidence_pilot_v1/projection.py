from collections import Counter
from copy import deepcopy
import json
from consistency.evidence_baseline_v1 import contracts
from consistency.llm_review_v1.packet import Redactor, sha

PROFILES=('full','E2_binding','E3_effect','E3_delivery','E4_closure')


def project(view,profile):
    v=deepcopy(view);changes=[]
    v['profile']='observed_evidence_projection'
    if profile=='full':return v,changes
    events=v['events']
    target=next((e for e in events if e['tool'] not in contracts.READ_FILES|contracts.TAU_READ),events[0])
    ref=target['call_ref']
    if profile=='E2_binding':
        for i,e in enumerate(events):e['call_ref']=None;changes.append(f'events/{i}/call_ref')
        for i,e in enumerate(v.get('children',[])):
            e['call_ref']=None;e['parent_call_ref']=None;changes.append(f'children/{i}/binding')
        for e in v.get('runtime_events',[]):e.pop('candidate_calls',None)
        v['observer_services']=[]
    elif profile=='E3_effect':
        target.pop('state_after',None);changes.append('native_after_state:'+str(ref))
        # Later independently captured pre-state observations are retained.
    elif profile=='E3_delivery':
        v['deliveries'].pop(ref,None);v['model_reports'].pop(ref,None)
        changes.extend(['endpoint_delivery:'+str(ref),'provider_received_copy:'+str(ref)])
        child=[c for c in v.get('children',[]) if c.get('parent_call_ref')==ref]
        if child:
            child[-1].pop('delivered',None);child[-1].pop('delivery_evidence_id',None)
            changes.append('last_nested_delivery:'+str(ref))
    elif profile=='E4_closure':
        for key in ('closed','observer_closed','runtime_closed'):v[key]=False;changes.append(key)
    elif profile=='E1_context':
        v['environment_clock']=None
        if v.get('observer_started'):v['observer_started'].pop('environment_clock',None)
        changes.append('environment_clock')
    else:raise ValueError('unknown_profile')
    return v,changes


def make_packet(view,result,contract,max_chars=240000):
    evidence=[];seen=set()
    def state_object(value):
        size=len(json.dumps(value))
        if size<=8000:return value
        return {'payload_omitted':True,'object_sha256':sha(value),'serialized_characters':size,
            'kind':value.get('kind') if isinstance(value,dict) else type(value).__name__,
            'field_names':list(value)[:32] if isinstance(value,dict) else None,
            'recorded_content_sha256':value.get('sha256') if isinstance(value,dict) else None,
            'recorded_bytes':value.get('bytes') if isinstance(value,dict) else None}
    def add(identifier,kind,value):
        if identifier and identifier not in seen:
            seen.add(identifier);evidence.append({'id':identifier,'kind':kind,'value':value})
    add('public:contract','public_execution_contract',contract)
    add('public:integrity','observation_status',{k:view.get(k) for k in
        ('closed','observer_closed','runtime_closed','issues','environment_clock')})
    add('public:runtime','runtime_activity_summary',{'closed':view.get('runtime_closed'),
        'backend':(view.get('observer_started') or {}).get('os_trace_backend'),
        'events':len(view.get('runtime_events',[])),
        'kinds':dict(Counter(e.get('syscall',e['kind']) for e in view.get('runtime_events',[])))})
    for call in view['instructions']:add('provider:'+call['call_ref'],'issued_instruction',call)
    for e in view['events']+view.get('children',[]):
        child='parent_call_ref' in e
        add(e.get('evidence_id'),'nested_invocation' if child else 'native_invocation',
            {k:e[k] for k in ('call_ref','parent_call_ref','tool','arguments','monotonic_ns','end_ns') if k in e})
        if 'result' in e:add(e.get('return_evidence_id'),'native_return',e['result'])
        if 'delivered' in e:add(e.get('delivery_evidence_id'),'nested_delivery',e['delivered'])
        a,b=e.get('state_before'),e.get('state_after')
        changed=set()
        if a and b:
            changed={k for k in set(a['objects'])|set(b['objects']) if a['objects'].get(k)!=b['objects'].get(k)}
        args=e.get('arguments',{})
        targets={x for k,x in args.items() if isinstance(x,str) and k in ('path','source','destination')}
        for phase,s in (('state_before',a),('state_after',b)):
            if not s:continue
            keys=sorted(changed|targets)
            # State payload summaries use ONLY surviving snapshots.
            add(s['evidence_id'],phase,{'complete':s['complete'],'issues':s['issues'],
                'objects_count':len(s['objects']),'objects_sha256':sha(s['objects']),
                'selected_objects':{k:state_object(s['objects'].get(k)) for k in keys[:12]},
                'selected_keys_truncated':len(keys)>12,'full_objects_not_transmitted':True})
    for ref,value in view['deliveries'].items():add('delivery:'+ref,'endpoint_result_delivery',value)
    for ref,value in view['model_reports'].items():add('model:'+ref,'provider_received_result',value)
    selected=[{k:deepcopy(c[k]) for k in ('id','kind','verdict','refs','reason','evidence_matrix')}
        for c in result['claims'] if c['verdict'] in ('Inconsistent','Uncertain')]
    if not selected:
        selected=[{'id':'scope-review','kind':'review_observed_scope','verdict':result['verdict'],
            'refs':['public:contract','public:integrity'],'reason':'Reassess the supplied execution under its public obligations.',
            'evidence_matrix':{'E1_semantics':'see_contract','E2_causality':'see_binding_evidence',
                'E3_effect':'see_observations','E4_integrity':'see_observation_status'}}]
    data={'scope':'Review issued instruction to actual invocation, effect within the supported contract, and result fidelity. Not arbitrary task completion.',
        'source_platform':view['source'],'rule_verdict':result['verdict'],'claims':selected,
        'other_rule_checks':dict(Counter(c['kind'] for c in result['claims'] if c['verdict']=='Consistent')),
        'evidence':evidence,
        'projection_notice':'All available invocation and result records in this view are included. State objects are summarized; runtime activity is summarized, not per-call proof. Unavailable records are not reconstructed from other runs. Rule and matrix fields are diagnostics, not truth. Secrets and run identifiers are redacted.'}
    redact=Redactor();redact.collect(data);data=redact.apply(data)
    if max_chars is not None and len(json.dumps(data))>max_chars:raise ValueError('packet_budget_exceeded')
    return data
