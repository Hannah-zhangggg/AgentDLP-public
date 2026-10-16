"""Rules + evidence matrix + bounded program semantics. Label-free API.

Evidence insufficiency, semantic support and result are separate dimensions.
The optional LLM produces proposals; it cannot bless missing facts as verified.
"""
from collections import Counter
from copy import deepcopy
import json
from . import VERSION
from .collectors import canonical
from . import contracts
from .program import interpret
from consistency.dataset_v5_formal.public433_rules import comparable
from consistency.semantic_adapters import adapt_tool_call
from consistency.semantic_model import behavior_projection, slot, validate_action

RESOURCE_FIELDS={'path','source','destination','paths','product_id','order_id','user_id','reservation_id',
                 'payment_id','payment_method_id','flight_number','file_path','directory_path','recipient_id'}


def equivalent(a,b,tool):return canonical(comparable(a,tool))==canonical(comparable(b,tool))


def graph(view):
    actions,edges=[],[]
    for plane,rows in (('expected',view['instructions']),('observed',view['events'])):
        for index,row in enumerate(rows):
            aid=plane+':'+str(index)
            ref=row.get('evidence_id') or 'provider:'+row['call_ref']
            action=adapt_tool_call(aid,row['tool'],row['arguments'],run='current-run',source_ref=ref)
            action.update(plane=plane,stage='instruction' if plane=='expected' else 'invocation',invocation_id=row['call_ref'])
            if row['tool']=='execute_python':action.update(operation='execute',structure='opaque')
            if row['tool']=='create_directory':action.update(operation='create')
            action['pathway'].update(protocol='json_rpc',placement='cross_host',actuator='filesystem' if view['source']=='MCPMark' else 'application_api')
            contract='provider_requirement' if plane=='expected' else 'runtime_observation'
            action['contracts'][contract]['call_multiplicity']=slot(1,type='integer',refs=[ref])
            action['fields']['result_mode']=slot('tool_return',refs=[ref])
            if 'result' in row:action['fields']['result_value']=slot(row['result'],type='json',refs=[row.get('return_evidence_id',ref)])
            actions.append(validate_action(action))
    parents={a['invocation_id']:a['id'] for a in actions if a['plane']=='observed'}
    for index,row in enumerate(view.get('children',[])):
        aid='api:'+str(index);ref=row.get('evidence_id','api:'+str(index))
        action=adapt_tool_call(aid,row['tool'],row['arguments'],run='current-run',source_ref=ref)
        action['invocation_id']=row['call_ref'];action['pathway'].update(interface='direct_api',actuator='application_api',placement='cross_host')
        actions.append(action)
        if row.get('parent_call_ref') in parents:
            edges.append({'source':parents[row['parent_call_ref']],'target':aid,'relation':'member_of','basis':'observed','refs':[ref]})
    return {'actions':actions,'coverage':behavior_projection(actions,edges)}


def detect(view):
    claims=[]
    def add(kind,verdict,refs,reason,tags=(),semantic='supported',basis='direct',payload=None):
        missing=verdict=='Uncertain' and semantic!='unsupported'
        route='rules' if verdict!='Uncertain' else 'llm_semantic_review' if semantic=='unsupported' else 'acquire_evidence'
        claim={'id':'claim-'+str(len(claims)),'kind':kind,'verdict':verdict,'refs':list(dict.fromkeys(refs)),
               'reason':reason,'taxonomy':list(tags),'basis':basis,'route':route,
               'evidence_matrix':{'E1_semantics':semantic,'E2_causality':'explicit_call_scope',
                    'E3_effect':{'profile':view['profile'],'needed':kind,'missing':missing},
                    'E4_integrity':{'verified':not view.get('issues'),'observer_closed':view.get('observer_closed',False)}}}
        if payload is not None:claim['payload']=payload
        claims.append(claim)
    issues=list(view.get('issues',[]))
    calls,events=view['instructions'],view['events'];ids=[c.get('call_ref') for c in calls]
    if any(not i for i in ids) or len(set(ids))!=len(ids) or any(not e.get('call_ref') for e in events):issues.append('missing_or_conflicting_identity')
    if issues:
        add('integrity','Uncertain',[],','.join(sorted(set(issues))))
        return finish(claims,view,include_graph=False)
    closed=bool(view.get('closed') and view.get('observer_closed'))
    if (view.get('observer_started') or {}).get('os_trace_backend')=='ptrace-child-x86_64':
        add('runtime_visibility','Consistent' if view.get('runtime_closed') else 'Uncertain',[],
            'native_process_tree_trace_closed' if view.get('runtime_closed') else 'runtime_trace_missing_or_incomplete')
    for call in calls:
        ref=call['call_ref'];expected_ref='provider:'+ref
        rows=[e for e in events if e['call_ref']==ref]
        observed_refs=[e.get('evidence_id','native:'+ref) for e in rows]
        refs=[expected_ref]+observed_refs
        rejected=ref in view.get('honest_rejections',[])
        delivered=view.get('deliveries',{}).get(ref)
        if not rows:
            if rejected:
                okay=delivered is not None and delivered.get('isError') is True
                add('admission','Consistent' if okay else 'Inconsistent',refs,'honest_pre_effect_rejection' if okay else 'rejection_report_changed',() if okay else ('T8',))
            else:
                add('count','Inconsistent' if closed else 'Uncertain',refs,'no_native_call_in_closed_scope' if closed else 'native_call_or_closure_missing',('T1',) if closed else ())
                if delivered is not None and delivered.get('isError',False) is False and closed:
                    add('result','Inconsistent',refs,'success_report_without_native_execution',('T8',))
        elif len(rows)>1:add('count','Inconsistent',refs,'more_than_one_execution_for_one_call',('T2',))
        else:add('count','Consistent',refs,'one_observed_native_call')
        for event in rows:
            eref=event.get('evidence_id','native:'+ref)
            if event['tool']!=call['tool']:add('operation','Inconsistent',[expected_ref,eref],'different_native_operation',('T3',))
            else:
                try:
                    same=equivalent(call['arguments'],event['arguments'],call['tool'])
                    if not same:
                        a,b=call['arguments'],event['arguments']
                        changed={k for k in set(a)|set(b) if canonical(a.get(k))!=canonical(b.get(k))}
                        tag='T5' if changed&RESOURCE_FIELDS else 'T4'
                        add('arguments','Inconsistent',[expected_ref,eref],'typed_argument_difference',(tag,))
                    else:add('arguments','Consistent',[expected_ref,eref],'typed_arguments_equivalent')
                except (ValueError,TypeError,KeyError,SyntaxError):add('arguments','Uncertain',[expected_ref,eref],'unsupported_argument_representation',semantic='unsupported')
            if view['source']=='MCPMark':checks=contracts.filesystem(event)
            elif view['source']=='tau-bench':checks=contracts.tau(event)
            elif event['tool']=='execute_python':
                checks=[]
                child=[r for r in view.get('children',[]) if r.get('parent_call_ref')==ref]
                parsed=interpret(call['arguments']['code'],child,view.get('environment_clock'))
                for expected in parsed['calls']:
                    ordinal=expected['ordinal']
                    if ordinal>=len(child):continue
                    observed=child[ordinal];cref=observed.get('evidence_id','api:'+str(ordinal))
                    if expected['tool']!=observed['tool']:
                        add('program_api_operation','Inconsistent',[expected_ref,cref],'program_call_vs_callee_operation',('T3',),basis='bounded_ast')
                    else:
                        actual=observed['arguments'].get('data',{})
                        # Returned real values drive branch evaluation, not an
                        # unmodified reference run. kwargs defaults are explicit.
                        same=canonical(expected['arguments'])==canonical(actual)
                        add('program_api_arguments','Consistent' if same else 'Inconsistent',[expected_ref,cref],
                            'provider_program_expression_vs_received_API_arguments',() if same else ('T4',),basis='bounded_ast')
                    if 'result' not in observed or 'delivered' not in observed:
                        add('program_api_result','Uncertain',[cref],'missing_callee_or_program_delivery')
                    else:
                        same=canonical(observed['result'])==canonical(observed['delivered'])
                        add('program_api_result','Consistent' if same else 'Inconsistent',[cref,observed.get('delivery_evidence_id',cref)],
                            'callee_result_preserved_into_program',() if same else ('T8',))
                if parsed['complete']:
                    same=parsed['consumed']==len(child)
                    add('program_api_coverage','Consistent' if same else 'Inconsistent',refs,'bounded_program_and_child_trace_complete',() if same else ('T2',),basis='bounded_ast')
                else:
                    reason=parsed['reason'];semantic='missing_fact' if reason in ('missing_environment_clock','missing_child_observation','missing_child_delivery') else 'unsupported'
                    add('program_api_coverage','Uncertain',refs,reason,semantic=semantic,basis='bounded_ast',
                        payload={'code':call['arguments']['code'],'interpreted_prefix':parsed['consumed'],'observed_children':len(child)})
                # State snapshots are exported to support further API-specific
                # contracts. Full business effects are NOT implied by API fidelity.
            else:checks=[contracts.check('tool_semantics',None,'unregistered_tool')]
            for result in checks:
                srefs=[eref]+[event[k]['evidence_id'] for k in ('state_before','state_after') if event.get(k)]
                semantic='unsupported' if any(x in result['reason'] for x in ('semantics','contract','unregistered','unsupported')) else 'supported'
                add('effect:'+result['name'],result['verdict'],srefs,result['reason'],('T7',) if result['verdict']=='Inconsistent' else (),semantic=semantic)
        # Even duplicate invocation cases retain result-integrity checks. The
        # delivery may match any actual return; count remains separately wrong.
        if rows and delivered is not None:
            honest=ref in view.get('honest_transport_failures',[]) and delivered.get('isError') is True
            actual_results=[e['result'] for e in rows if 'result' in e]
            if honest:add('delivery','Consistent',refs,'explicit_honest_transport_unavailability')
            elif actual_results:
                same=any(canonical(r)==canonical(delivered) for r in actual_results)
                add('delivery','Consistent' if same else 'Inconsistent',refs,'native_result_preservation',() if same else ('T8',))
            else:add('delivery','Uncertain',refs,'native_result_missing')
        elif rows:add('delivery','Uncertain',refs,'delivered_result_missing')
        if delivered is not None:
            text='\n'.join(r['text'] for r in delivered.get('content',[]) if r.get('type')=='text')
            report=view.get('model_reports',{}).get(ref)
            if report is None:add('model_reporting','Uncertain',refs,'model_received_result_missing')
            else:
                same=canonical(report)==canonical(text)
                add('model_reporting','Consistent' if same else 'Inconsistent',refs,'model_received_actual_MCP_text',() if same else ('T8',))
    for event in events:
        if event['call_ref'] not in ids:add('extra','Inconsistent',[event.get('evidence_id','native')],'unissued_native_call',('T2',))
    for edge in view.get('dependencies',[]):
        first=[e for e in events if e['call_ref']==edge['source']]
        second=[e for e in events if e['call_ref']==edge['target']]
        refs=edge.get('refs',[])
        if len(first)!=1 or len(second)!=1 or 'end_ns' not in first[0] or 'monotonic_ns' not in second[0]:add('dependency','Uncertain',refs,'dependency_clock_or_binding_missing')
        else:
            okay=first[0]['end_ns']<=second[0]['monotonic_ns'] and not first[0].get('result',{}).get('isError')
            add('dependency','Consistent' if okay else 'Inconsistent',refs,'declared_success_before_dependent_entry',() if okay else ('T6',))
    if not closed:add('closure','Uncertain',[],'complete_observer_window_missing')
    return finish(claims,view)


def finish(claims,view,include_graph=True):
    outcomes={c['verdict'] for c in claims}
    verdict='Inconsistent' if 'Inconsistent' in outcomes else 'Uncertain' if not claims or not view['instructions'] or 'Uncertain' in outcomes else 'Consistent'
    return {'schema_version':VERSION,'verdict':verdict,'taxonomy':sorted({t for c in claims for t in c['taxonomy']}),
            'claims':claims,'routes':dict(Counter(c['route'] for c in claims)),
            'coverage':{'verified_claims':sum(c['verdict']!='Uncertain' for c in claims),'total_claims':len(claims),
                        'profile':view['profile'],'program_scope':'issued program to nested API invocation and return fidelity; not arbitrary business task completion'},
            'runtime_observation':{'events':len(view.get('runtime_events',[])),
                'backend':(view.get('observer_started') or {}).get('os_trace_backend','historical_or_not_installed'),
                'closed':view.get('runtime_closed',False),'syscalls':dict(Counter(e.get('syscall',e['kind']) for e in view.get('runtime_events',[])))},
            'behavior_graph':graph(view) if include_graph else None}
