"""Rules-only public-tool detector. Input is a label-free evidence view only.

Does not load case plans, oracle decisions, reference answers or fault metadata.
Unknown effect semantics are retained, not filled in using task success.
"""
import ast
from collections import Counter
from copy import deepcopy
import hashlib
import json
import posixpath


def comparable(arguments, tool):
    out = deepcopy(arguments)
    for k in ('path', 'source', 'destination'):
        if k in out: out[k] = posixpath.normpath(out[k])
    if 'paths' in out: out['paths'] = [posixpath.normpath(p) for p in out['paths']]
    if tool == 'execute_python' and isinstance(out.get('code'), str):
        out['code'] = ast.dump(ast.parse(out['code']))
    if tool == 'return_delivered_order_items' and 'item_ids' in out:
        out['item_ids'] = sorted(out['item_ids'])
    return out


def detect(view):
    claims = []
    def add(kind, verdict, refs, reason, tag=None):
        claims.append({'kind': kind, 'verdict': verdict, 'refs': refs, 'reason': reason,
                       'taxonomy': [tag] if tag else [], 'route': 'rules_only',
                       'evidence_matrix': {'semantics': 'unsupported_or_missing' if verdict == 'Uncertain' else 'supported',
                                           'association': 'explicit_call_ref', 'visibility': view['profile'],
                                           'integrity': 'failed' if view['issues'] else 'host_pinned_capture'}})
    if view['issues']:
        add('integrity', 'Uncertain', [], ','.join(view['issues']))
        return {'verdict': 'Uncertain', 'taxonomy': [], 'claims': claims}
    calls, events = view['instructions'], view['events']
    ids = [c['call_ref'] for c in calls]
    if len(set(ids)) != len(ids) or any(not e.get('call_ref') for e in events):
        add('binding', 'Uncertain', [], 'missing_or_conflicting_identity')
    for call in calls:
        ref = call['call_ref']
        rows = [e for e in events if e.get('call_ref') == ref]
        rejected = ref in view['honest_rejections']
        if not rows:
            if rejected:
                add('admission', 'Consistent', [ref], 'declared_pre_effect_unavailability_reported')
            else:
                add('count', 'Inconsistent' if view['closed'] else 'Uncertain', [ref], 'no_native_invocation_in_closed_accepted_scope', 'T1' if view['closed'] else None)
        elif len(rows) > 1:
            add('count', 'Inconsistent', [ref], 'repeated_invocation_under_one_authorization', 'T2')
        else:
            add('count', 'Consistent', [ref], 'one_native_invocation')
        for event in rows:
            if event['tool'] != call['tool']:
                add('operation', 'Inconsistent', [ref], 'different_native_tool', 'T3')
            else:
                try:
                    a, b = comparable(call['arguments'], call['tool']), comparable(event['arguments'], event['tool'])
                    if json.dumps(a, sort_keys=True, allow_nan=False) != json.dumps(b, sort_keys=True, allow_nan=False):
                        keys = {k for k in set(a) | set(b) if a.get(k) != b.get(k)}
                        resource = bool(keys & {'path','source','destination','paths','product_id','order_id','user_id','reservation_id','payment_id','flight_number','file_path','directory_path'})
                        add('arguments', 'Inconsistent', [ref], 'typed_arguments_differ', 'T5' if resource else 'T4')
                    else:
                        add('arguments', 'Consistent', [ref], 'typed_arguments_equivalent')
                except (ValueError, SyntaxError, TypeError, KeyError):
                    add('arguments', 'Uncertain', [ref], 'unsupported_argument_representation')
            if event['tool'] == 'write_file' and not event['result'].get('isError'):
                path = posixpath.normpath(event['arguments']['path'])
                after = event.get('state')
                content = event['arguments']['content'].encode('utf-8')
                expected = hashlib.sha256(content).hexdigest()
                if after is None:
                    add('effect', 'Uncertain', [ref], 'missing_file_effect_witness')
                else:
                    okay = after.get(path, {}).get('sha256') == expected and after.get(path, {}).get('bytes') == len(content)
                    add('effect', 'Consistent' if okay else 'Inconsistent', [ref], 'successful_write_vs_independent_file_hash', None if okay else 'T7')
            elif event['tool'] == 'execute_python':
                add('program_effects', 'Uncertain', [ref], 'program_to_nested_api_semantics_not_implemented')
            elif view['source'] == 'MCPMark' and event['tool'] in ('create_directory', 'move_file', 'edit_file') and not event['result'].get('isError'):
                add('filesystem_effects', 'Uncertain', [ref], 'no_deployable_directory_move_or_edit_commit_witness')
            elif view['source'] == 'tau-bench' and not event['tool'].startswith(('get_', 'find_', 'list_')):
                add('business_effects', 'Uncertain', [ref], 'tool_specific_business_effect_contract_not_registered')
        delivered = view['deliveries'].get(ref)
        if 'model_reports' in view and delivered is not None:
            expected_text = '\n'.join(c['text'] for c in delivered.get('content', []) if c.get('type') == 'text')
            report = view['model_reports'].get(ref)
            if report is None:
                add('model_reporting', 'Uncertain', [ref], 'model_return_not_observed')
            elif report != expected_text:
                add('model_reporting', 'Inconsistent', [ref], 'model_received_content_differs_from_delivered_MCP_text', 'T8')
            else:
                add('model_reporting', 'Consistent', [ref], 'MCP_text_preserved_in_actual_provider_request')
        if len(rows) == 1 and delivered is not None:
            same = rows[0]['result'] == delivered
            if ref in view['honest_transport_failures']:
                add('delivery', 'Consistent', [ref], 'honest_transport_failure_allowed_not_success')
            else:
                add('delivery', 'Consistent' if same else 'Inconsistent', [ref], 'native_result_preservation', None if same else 'T8')
        elif not rejected:
            add('delivery', 'Uncertain', [ref], 'no_unique_native_result_and_delivery')
    for event in events:
        if event.get('call_ref') not in ids:
            add('extra', 'Inconsistent', [event.get('call_ref')], 'native_invocation_without_issued_call', 'T2')
    if not view['closed']:
        add('closure', 'Uncertain', [], 'observation_window_not_closed')
    verdicts = {c['verdict'] for c in claims}
    verdict = 'Inconsistent' if 'Inconsistent' in verdicts else 'Uncertain' if not calls or 'Uncertain' in verdicts else 'Consistent'
    return {'verdict': verdict, 'taxonomy': sorted({t for c in claims for t in c['taxonomy']}), 'claims': claims,
            'scope': 'issued calls, typed arguments, declared return contract, supported file effects; no LLM'}
