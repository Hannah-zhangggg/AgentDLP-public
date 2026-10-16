"""Evidence-availability routing; never inspect case IDs, truth, or loss profiles."""
from .experiment import OUT,PROMPTS,read,write,file_hash
from consistency.llm_review_v1.experiment import request


def select_prompt(packet):
    reasons=set()
    for claim in packet.get('claims',[]):
        matrix=claim.get('evidence_matrix',{})
        if matrix.get('E1_semantics')=='missing_fact':reasons.add('semantic_context_unavailable')
        effect=matrix.get('E3_effect')
        if isinstance(effect,dict) and effect.get('missing') is True:reasons.add('required_observation_unavailable')
        if claim.get('kind') in ('integrity','runtime_visibility','closure') and claim.get('verdict')=='Uncertain':
            reasons.add('observation_integrity_open')
    for item in packet.get('evidence',[]):
        value=item.get('value',{})
        if not isinstance(value,dict):continue
        if item.get('kind') in ('native_invocation','nested_invocation') and value.get('call_ref') is None:
            reasons.add('causal_binding_unavailable')
        if item.get('kind')=='observation_status' and any(value.get(k) is False for k in ('closed','observer_closed')):
            reasons.add('observation_window_open')
    return {'version':'v4' if reasons else 'v3','reasons':sorted(reasons),
        'scope':'semantic interpretation when sufficient; best-effort inference when facts are unavailable'}


def review(packet):
    route=select_prompt(packet)
    result=request(packet,(PROMPTS/(route['version']+'.txt')).read_text())
    return {'route':route,'result':result,'advisory_only':True}


def audit():
    rows=read(OUT/'private/selection.json');decisions=[]
    for row in rows:
        # The selector only receives the public packet, not this private row.
        packet=read(OUT/row['packet']);route=select_prompt(packet)
        decisions.append({'id':row['id'],'case_id':row['case_id'],'split':row['split'],
            'profile':row['profile'],**route,'packet_sha256':file_hash(OUT/row['packet'])})
    regression=[r for r in decisions if r['split']=='regression']
    assert len(regression)==48 and all(r['version']=='v3' for r in regression)
    from collections import Counter
    result={'implementation':'consistency/evidence_pilot_v1/routing.py','decisions':decisions,
        'route_counts':dict(Counter(r['version'] for r in decisions)),
        'all_48_complete_legal_inputs_keep_v3':True,
        'prompt_sha256':{v:file_hash(PROMPTS/(v+'.txt')) for v in ('v3','v4')},
        'scope':'Post-regression architecture safeguard; route decisions checked, not a fresh end-to-end routed accuracy experiment.',
        'existing_full_legal_v3_results':'artifacts/reports/llm-review-general-v3-20260913/summary.json',
        'automatic_repair_or_retry':False}
    write(OUT/'routing-audit.json',result)
    print({k:v for k,v in result.items() if k!='decisions'})


if __name__=='__main__':audit()
