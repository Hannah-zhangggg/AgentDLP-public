"""Label-free, minimized evidence projection for remote semantic review."""
from collections import Counter
from copy import deepcopy
import hashlib
import json
import re
from consistency.evidence_baseline_v1.collectors import canonical


def sha(value):return hashlib.sha256(canonical(value).encode()).hexdigest()


class Redactor:
    def __init__(self):self.secrets={}
    def collect(self,value):
        if isinstance(value,dict):
            for key,v in value.items():
                if re.search(r'password|access_token|refresh_token|api_key|authorization|secret',key,re.I) and isinstance(v,str) and v:
                    self.secrets.setdefault(v,'<REDACTED_'+str(len(self.secrets)+1)+'>')
                self.collect(v)
        elif isinstance(value,list):
            for v in value:self.collect(v)
        elif isinstance(value,str):
            try:parsed=json.loads(value)
            except (ValueError,TypeError):return
            if isinstance(parsed,(dict,list)):self.collect(parsed)
    def apply(self,value):
        if isinstance(value,dict):return {self.apply(k):self.apply(v) for k,v in value.items()}
        if isinstance(value,list):return [self.apply(v) for v in value]
        if not isinstance(value,str):return value
        for secret,replacement in sorted(self.secrets.items(),key=lambda x:-len(x[0])):
            value=value.replace(secret,replacement).replace(json.dumps(secret)[1:-1],replacement)
        value=re.sub(r'p433-evidencev1-v5d-\d+-a\d+','RUN',value,flags=re.I)
        value=re.sub(r'\bV5D-\d+-A\d+\b','CASE',value,flags=re.I)
        value=re.sub(r'\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b',lambda m:'<EMAIL_'+hashlib.sha256(m[0].encode()).hexdigest()[:10]+'>',value)
        # Remove the injector's suggestive identifier; use a capture-free alias.
        value=value.replace('_legal_bound_item','_review_bound_alias_01')
        value=re.sub(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+','<REDACTED_JWT>',value)
        return value


def packet(view,result,contract):
    selected=[c for c in result['claims'] if c['verdict'] in ('Inconsistent','Uncertain')]
    needed={ref for c in selected for ref in c['refs']}
    logical={ref.removeprefix('provider:') for ref in needed if ref.startswith('provider:')}
    for e in view['events']+view.get('children',[]):
        if e.get('evidence_id') in needed:logical.add(e.get('parent_call_ref',e['call_ref']))
    evidence=[];seen=set()
    def add(ref,kind,value):
        if ref and ref not in seen:evidence.append({'id':ref,'kind':kind,'value':value});seen.add(ref)
    add('public:contract','execution_contract',contract)
    add('public:integrity','observation_status',{
        k:view.get(k) for k in ('profile','closed','observer_closed','runtime_closed','issues','environment_clock')})
    add('public:inventory','call_inventory',{
        'instructions':[{'id':'provider:'+r['call_ref'],'tool':r['tool']} for r in view['instructions']],
        'native_calls':[{'id':r.get('evidence_id'),'logical_call':r['call_ref'],'tool':r['tool']} for r in view['events']],
        'nested_calls':len(view.get('children',[]))})
    for r in view['instructions']:
        if r['call_ref'] in logical:add('provider:'+r['call_ref'],'issued_instruction',r)
    for e in view['events']:
        if e['call_ref'] not in logical:continue
        add(e.get('evidence_id'),'native_invocation',{k:e[k] for k in ('call_ref','tool','arguments','monotonic_ns','end_ns') if k in e})
        if 'result' in e:add(e.get('return_evidence_id'),'native_return',e['result'])
        for phase in ('state_before','state_after'):
            s=e.get(phase)
            if s:add(s['evidence_id'],phase,{'complete':s['complete'],'issues':s['issues'],
                'objects_count':len(s['objects']),'captured_objects_sha256':sha(s['objects']),
                'raw_objects_omitted':True})
        if e['call_ref'] in view['deliveries']:add('delivery:'+e['call_ref'],'delivered_result',view['deliveries'][e['call_ref']])
    children=[c for c in view.get('children',[]) if c.get('parent_call_ref') in logical]
    for c in children:
        if c.get('evidence_id') not in needed and c not in children[-3:]:continue
        add(c.get('evidence_id'),'nested_invocation',{k:c[k] for k in ('call_ref','parent_call_ref','tool','arguments','monotonic_ns','end_ns') if k in c})
        if 'result' in c:add(c.get('return_evidence_id'),'nested_return',c['result'])
        if 'delivered' in c:add(c.get('delivery_evidence_id'),'nested_delivery',c['delivered'])
    data={'scope':'Issued program/tool to invocation and return fidelity under the public contract; not arbitrary task completion.',
          'source_platform':view['source'],'rule_verdict':result['verdict'],
          'claims':[{k:deepcopy(c[k]) for k in ('id','kind','verdict','refs','reason','evidence_matrix')} for c in selected],
          'other_rule_checks':dict(Counter(c['kind'] for c in result['claims'] if c['verdict']=='Consistent')),
          'evidence':evidence,'projection_notice':'Only review-relevant evidence is transmitted. Full database objects, unrelated calls and most nested calls are not transmitted. Rule-check counts are diagnostics, not ground truth. Secret values and run identifiers are consistently redacted.'}
    redactor=Redactor();redactor.collect(data);data=redactor.apply(data)
    # Explicit, hash-addressed omissions; never silently truncate program code.
    def bound(v,key=''):
        if isinstance(v,dict):return {k:bound(x,k) for k,x in v.items()}
        if isinstance(v,list):return [bound(x,key) for x in v]
        if isinstance(v,str) and len(v)>24000 and key!='code':
            return {'omitted':True,'characters':len(v),'sha256':hashlib.sha256(v.encode()).hexdigest(),'prefix':v[:1500]}
        return v
    return bound(data)


def screen(data,response):
    """Validate shape/references/aggregation, NOT certify semantic truth."""
    valid={'Consistent','Inconsistent','Uncertain'};errors=[]
    if not isinstance(response,dict):return ['response_not_object']
    ids={c['id'] for c in data['claims']};refs={e['id'] for e in data['evidence']}
    reviews=response.get('claim_reviews',[])
    if not isinstance(reviews,list) or any(not isinstance(r,dict) for r in reviews):return ['review_shape']
    if len(reviews)!=len(ids) or {r.get('claim_id') for r in reviews}!=ids:errors.append('missing_or_duplicate_claim')
    for r in reviews:
        if r.get('verdict') not in valid:errors.append('invalid_claim_verdict')
        rs=r.get('refs')
        if not isinstance(rs,list) or not rs or any(not isinstance(x,str) or x not in refs for x in rs):errors.append('invalid_reference')
        if not isinstance(r.get('assumptions'),list) or not isinstance(r.get('missing_evidence'),list):errors.append('missing_limitations')
    for field in ('evidence_verdict','inferred_verdict'):
        if response.get(field) not in valid:errors.append('invalid_'+field)
    outcomes={r.get('verdict') for r in reviews}
    expected='Inconsistent' if 'Inconsistent' in outcomes else 'Uncertain' if 'Uncertain' in outcomes else 'Consistent'
    if response.get('evidence_verdict')!=expected:errors.append('incompatible_evidence_aggregation')
    if not isinstance(response.get('assumptions'),list):errors.append('overall_assumptions_missing')
    if response.get('inferred_verdict')!=response.get('evidence_verdict') and not response.get('assumptions'):
        errors.append('inference_without_assumptions')
    return sorted(set(errors))
