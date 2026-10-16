"""Evidence-only projections. No labels, predictions, or treatment plans."""
from copy import deepcopy
import hashlib

PROFILES = ('E1_context', 'E2_binding', 'E3_effect', 'E3_delivery', 'E4_closure')


def project(view, profile):
    v = deepcopy(view)
    changes = []
    def remove(obj, key, path, replacement=None, keep=False):
        if key in obj and obj[key] is not None:
            changes.append(path + '/' + key)
            if keep:
                obj[key] = replacement
            else:
                obj.pop(key)
    rows = [('events', v.get('events', [])), ('children', v.get('children', []))]
    if profile == 'E1_context':
        remove(v, 'environment_clock', '', keep=True)
        if v.get('observer_started'):
            remove(v['observer_started'], 'environment_clock', '/observer_started')
    elif profile == 'E2_binding':
        for name, events in rows:
            for i, e in enumerate(events):
                for key in ('call_ref', 'parent_call_ref'):
                    remove(e, key, f'/{name}/{i}', keep=True)
        for i, e in enumerate(v.get('runtime_events', [])):
            for key in ('candidate_calls', 'call_ref', 'parent_call_ref'):
                remove(e, key, f'/runtime_events/{i}')
        if v.get('observer_services'):
            changes.append('/observer_services')
            v['observer_services'] = []
        # Preserve observations and cross-channel equality, but not their binding
        # to a Provider call. Content/time/order remain legitimate partial clues.
        def alias(ref):
            return 'unbound-' + hashlib.sha256(('e2/' + str(ref)).encode()).hexdigest()[:20]
        for field in ('deliveries', 'model_reports'):
            if v.get(field):
                changes.extend('/' + field + '/' + str(k) + '/binding' for k in v[field])
                v[field] = {alias(k): value for k, value in v[field].items()}
        for field in ('honest_rejections', 'honest_transport_failures'):
            if v.get(field):
                changes.append('/' + field + '/binding')
                v[field] = [alias(k) for k in v[field]]
        # Current captures use native/observer ordinal evidence addresses. If a
        # future capture encodes a Provider identity, remove that duplicate too.
        instruction_refs = {c['call_ref'] for c in v.get('instructions', [])}
        def neutralize(obj):
            if isinstance(obj, dict):
                for k, value in list(obj.items()):
                    if k.endswith('evidence_id') and isinstance(value, str) and any(r in value for r in instruction_refs):
                        obj[k] = 'evidence-' + hashlib.sha256(value.encode()).hexdigest()[:20]
                        changes.append('/encoded_evidence_identity/' + k)
                    elif k not in ('arguments', 'result', 'delivered', 'objects'):
                        neutralize(value)
            elif isinstance(obj, list):
                for item in obj: neutralize(item)
        for _, events in rows: neutralize(events)
    elif profile == 'E3_effect':
        for name, events in rows:
            for i, e in enumerate(events):
                for key in ('state_before', 'state_after'):
                    remove(e, key, f'/{name}/{i}')
    elif profile == 'E3_delivery':
        for field in ('deliveries', 'model_reports'):
            if v.get(field):
                changes.extend('/' + field + '/' + str(k) for k in v[field])
                v[field] = {}
        for name, events in rows:
            for i, e in enumerate(events):
                for key in ('delivered', 'delivery_evidence_id', 'delivered_exception'):
                    remove(e, key, f'/{name}/{i}')
        if v.get('observer_services'):
            kept=[]
            for i,e in enumerate(v['observer_services']):
                if 'deliver' in e.get('kind', ''):
                    changes.append('/observer_services/' + str(i))
                else: kept.append(e)
            v['observer_services'] = kept
    elif profile == 'E4_closure':
        for field in ('closed', 'observer_closed', 'runtime_closed'):
            if v.get(field) is True:
                v[field] = False
                changes.append('/' + field)
    else:
        raise ValueError('unknown_profile')
    return v, changes
