"""Prepare, run and score 484 full/degraded pairs without using private truth as input."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path

from consistency.dataset_v5_formal.common import ROOT, write
from consistency.dataset_v5_formal.benchmark_postflight import check as benchmark_check
from consistency.evidence_baseline_v1.loader import live_view, historical_view
from consistency.evidence_baseline_v1.detector import detect
from consistency.evidence_pilot_v1.projection import make_packet
from consistency.bc_evidence_pilot_v1.experiment import legacy_record_adapter, redact_run_identifiers
from consistency.llm_review_v1.packet import Redactor
from .transport import request

HERE = Path(__file__).parent
COL = ROOT / 'datasets/behavior-consistency-v5/consolidated-r1'
OUT = ROOT / 'artifacts/benchmark-v5-six-arm-r1-20260913'
PROFILES = ('E1_context', 'E2_binding', 'E3_effect', 'E3_delivery', 'E4_closure')
QUESTIONS = (
    ('scope', 'Are relevant observations trustworthy and sufficiently closed to assess this execution?'),
    ('count', 'Do required logical actions and their permitted multiplicities match observed execution?'),
    ('operation', 'Are the observed semantic operations faithful to the issued operations?'),
    ('arguments', 'Are non-resource arguments faithful under the applicable interpretation and allowed equivalences?'),
    ('resources', 'Are resource identities, roles, scope and required execution context faithful?'),
    ('dependencies', 'Are explicitly established dependencies and preconditions respected?'),
    ('effects', 'Do observed effects satisfy the applicable transition contract, including permitted failure?'),
    ('results', 'Are results accurately bound, reported and delivered under the applicable result contract?'),
)


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def file_hash(path):
    digest=hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):digest.update(chunk)
    return digest.hexdigest()


def verify(base,files):
    def check(item):
        name,digest=item
        if file_hash(base/name)!=digest:raise ValueError('hash_mismatch:'+name)
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(check,files.items()))
    return len(files)


def opaque(text):
    return hashlib.sha256(text.encode()).hexdigest()[:20]


def rel(path):
    return str(path.relative_to(ROOT))


def portable_pins(pins):
    out={}
    for name,digest in pins.items():
        key=name.replace('\\','/')
        if key in out and out[key]!=digest:raise ValueError('conflicting_portable_path')
        out[key]=digest
    return out


def load_view(run,live):
    # Normalize only retrieval path keys, never evidence content or recorded hashes.
    from unittest.mock import patch
    from consistency.evidence_baseline_v1 import loader
    original=loader.read
    def portable_read(path):
        value=original(path)
        return {**value,'files':portable_pins(value['files'])} if Path(path).name=='retrieval.json' else value
    with patch.object(loader,'read',side_effect=portable_read):
        return live_view(run) if live else legacy_record_adapter(historical_view(run))


def saved_view_header(path):
    prefix=''
    with Path(path).open() as f:
        for line in f:
            if line.startswith('  "instructions":'):break
            prefix+=line
        else:raise ValueError('view_header_not_found')
    return json.loads(prefix.rstrip().removesuffix(',')+'\n}')


def write_once_exact(path,value):
    if path.exists():
        if read(path)!=value:raise ValueError('resumed_plan_changed')
    else:write(path,value)


def effective_project(view, profile):
    """Remove surviving observations, without assuming a native event exists."""
    v = deepcopy(view)
    removed = []
    def drop(obj, key, address):
        if key in obj and obj[key] is not None:
            removed.append(address)
            obj.pop(key)
    events = v.get('events', []) + v.get('children', [])
    if profile == 'E1_context':
        if v.get('environment_clock') is not None:
            v['environment_clock'] = None
            removed.append('environment_clock')
        if v.get('observer_started'):
            drop(v['observer_started'], 'environment_clock', 'observer_started/environment_clock')
    elif profile == 'E2_binding':
        for i, event in enumerate(events):
            for key in ('call_ref', 'parent_call_ref'):
                if event.get(key) is not None:
                    event[key] = None
                    removed.append(f'execution/{i}/{key}')
        for i, event in enumerate(v.get('runtime_events', [])):
            drop(event, 'candidate_calls', f'runtime/{i}/candidate_calls')
        if v.get('observer_services'):
            v['observer_services'] = []
            removed.append('observer_services')
    elif profile == 'E3_effect':
        for i, event in enumerate(events):
            if event.get('state_after'):
                drop(event, 'state_after', f'execution/{i}/state_after')
                break
    elif profile == 'E3_delivery':
        refs = sorted(set(v.get('deliveries', {})) | set(v.get('model_reports', {})))
        if refs:
            ref = refs[0]
            for field in ('deliveries', 'model_reports'):
                drop(v.get(field, {}), ref, field + '/' + ref)
            for i, event in enumerate(v.get('children', [])):
                if event.get('parent_call_ref') == ref:
                    for field in ('delivered', 'delivery_evidence_id', 'delivered_exception'):
                        drop(event, field, f'children/{i}/{field}')
        else:
            for i, event in enumerate(events):
                if 'delivered' in event or 'delivered_exception' in event:
                    for field in ('delivered', 'delivery_evidence_id', 'delivered_exception'):
                        drop(event, field, f'execution/{i}/{field}')
                    break
    elif profile == 'E4_closure':
        for field in ('closed', 'observer_closed', 'runtime_closed'):
            if v.get(field) is True:
                v[field] = False
                removed.append(field)
    else:
        raise ValueError('unknown_projection')
    return v, removed


def public_packet(view, contract):
    # Evidence collection never depends on rule claims, labels or predictions.
    packet = make_packet(view, {'verdict': 'Uncertain', 'claims': []}, contract, max_chars=None)
    for field in ('rule_verdict', 'claims', 'other_rule_checks'):
        packet.pop(field)
    packet['claims'] = [{'id': 'review-' + name, 'question': question} for name, question in QUESTIONS]
    packet['projection_notice'] = (
        'Input contains permitted observations only, not rule predictions or oracle labels. '
        'All supplied native invocations and returns are included; large state objects and runtime '
        'activity are explicitly summarized. Missing records are not reconstructed. '
        'E1 means semantic context, E2 association, E3 observed actions/effects/delivery, '
        'and E4 integrity/closure. Review obligations independently under these dimensions.')
    # Restore explicit observational ownership omitted by the old flat review packet.
    ownership = {}
    extras = []
    for event in view.get('events', []) + view.get('children', []):
        subject = event.get('evidence_id')
        for key in ('return_evidence_id', 'delivery_evidence_id'):
            if event.get(key):
                ownership.setdefault(event[key], []).append(subject)
        for phase in ('state_before', 'state_after'):
            if event.get(phase):
                ownership.setdefault(event[phase]['evidence_id'], []).append(subject)
        for key in ('exception', 'delivered_exception'):
            if key in event:
                extras.append({'id': subject + ':' + key, 'kind': key,
                               'subject_refs': [subject], 'value': event[key]})
    # make_packet redacts values; evidence addresses use the same deterministic mask.
    for item in packet['evidence']:
        if item['id'] in ownership:
            item['subject_refs'] = list(dict.fromkeys(ownership[item['id']]))
    extras.append({'id': 'public:admission', 'kind': 'admission_and_transport_observations',
                   'value': {k: view.get(k, []) for k in ('honest_rejections', 'honest_transport_failures')}})
    packet['evidence'].extend(extras)
    redact = Redactor()
    redact.collect(packet)
    packet = redact_run_identifiers(redact.apply(packet))
    # Hide benchmark/run naming while preserving equal values consistently.
    text = json.dumps(packet, ensure_ascii=False)
    import re
    text = re.sub(r'v5formal-[A-Za-z0-9_-]+', 'RUN', text)
    packet = json.loads(text)
    assert not {'rule_verdict', 'other_rule_checks'} & packet.keys()
    assert all(set(claim) == {'id', 'question'} for claim in packet['claims'])
    return packet


def public_contract(run, pins):
    pins=portable_pins(pins)
    out = {}
    for name in ('public-contract.json', 'legal-public-contract.json', 'native-tool-schemas.json'):
        path = run / 'external' / name
        if not path.exists():
            continue
        if file_hash(path) != pins.get('external/' + name):
            raise ValueError('public_contract_hash:' + rel(path))
        value = read(path)
        if isinstance(value, dict):
            value = {k: v for k, v in value.items() if k not in ('task_id', 'source')}
        out[name] = value
    out['comparison_scope'] = (
        'Instruction-execution fidelity, not arbitrary user-task success. '
        'Interpret captured calls using the supplied public tool contracts/schema. '
        'If necessary business semantics or permissions are absent, state the limitation; '
        'do not import a permission from another workflow or experiment.')
    return out


def safe_detect(view):
    try:
        return detect(view)
    except (ValueError, TypeError, KeyError, IndexError, AttributeError) as exc:
        return {'verdict': 'Uncertain', 'taxonomy': [], 'claims': [],
                'evaluation_error': type(exc).__name__}


def prepare():
    if (OUT/'input-freeze.json').exists() or (OUT/'responses').exists():
        raise ValueError('preparation_already_frozen_or_used')
    checked = benchmark_check()
    rows = []
    sources = {}
    profile_counts = Counter()
    layout = read(COL / 'benchmark-layout.json')
    cases = []
    for group in layout['groups']:
        for path in sorted((COL / group['path'] / 'records').glob('*.json')):
            r = read(path)
            cases.append((group['name'], path, r))
    seed_ids = sorted({r['seed_id'] for _, _, r in cases}, key=lambda s: opaque('selection-v1/' + s))
    selection_seeds = set(seed_ids[:max(1, len(seed_ids) // 3)])
    write_once_exact(OUT / 'plan.json', {
        'cases': 484, 'conditions': ['full', 'degraded'], 'views': 968,
        'arms': ['rules_full', 'llm_full', 'hybrid_full', 'rules_degraded', 'llm_degraded', 'hybrid_degraded'],
        'degradation': 'Exactly one effective profile per case, balanced by group among actually removable E1/E2/E3-effect/E3-delivery/E4 observations. All other applicable profiles get rule-only audit results. No selection on oracle labels or predictions.',
        'full_definition': 'All available permitted archived evidence for the exact canonical run, not a guarantee that every required witness was originally collected.',
        'LLM': 'Rule-free static eight-obligation review, derived from the latest v6 principles; same model, prompt and public packet for standalone and hybrid. No rule diagnostics or rule-derived claims in API input.',
        'hybrid_primary': 'Preserve rule C; for rule I/U use the accepted LLM inferred_verdict; invalid/failed review gives U. Original rules always retained.',
        'paired_reuse': 'One actual LLM response per view. Six logical evaluation arms; Hybrid accesses this exact cached response only on I/U, eliminating resampling confounds. Physical API calls and policy-required logical calls reported separately.',
        'selection': {'seed_ids': sorted(selection_seeds), 'candidates': ['rules', 'review_I', 'review_U', 'review_IU'],
                      'criterion': 'Highest full+degraded accuracy on selection seeds; then fewer false C; then fewer logical API calls. Report remaining seeds and pooled retrospective optimum separately.',
                      'scope': 'Previously exposed benchmark; this is not a fresh blind generalization claim.'},
        'metrics': 'Accuracy includes U/API/parser/checker failures as incorrect. Overall and Normal/A/B/C, Normal+A, profile and observation-source strata; I recall, false C, rule-vs-LLM disagreement and helpful/harmful overrides.',
        'api': {'model': 'deepseek-v4-flash', 'temperature': 0, 'max_tokens': 3200,
                'thinking': 'disabled', 'workers': 8, 'max_transport_attempts': 2},
        'preservation': 'No benchmark relabeling or exclusions, no VM runs or raw-log deletion; original captures referenced with hashes. Evaluation and private labels are separate from model input.'})
    for group, path, record in sorted(cases, key=lambda x: opaque('profile-allocation/' + x[2]['id'])):
        run = ROOT / record['execution']['root']
        retrieval = run / 'retrieval.json'
        if file_hash(retrieval) != record['execution']['retrieval']['sha256']:
            raise ValueError('retrieval_changed')
        sources[rel(path)] = file_hash(path)
        sources[rel(retrieval)] = file_hash(retrieval)
        pins = portable_pins(read(retrieval)['files'])
        # Availability only, never labels or later reruns, selects the raw loader.
        live = (run / 'external/observer-v1/receipts.jsonl').exists()
        contract = public_contract(run, pins)
        for name, digest in pins.items():
            if not any(s in name for s in ('expected', 'oracle', 'intent', 'evaluation', 'mutation', 'plan')):
                sources[rel(run / name)] = digest
        cid = opaque('case/' + record['id'])
        audit_path=OUT/'private/projection-audit'/(cid+'.json')
        ids={c:'sample-'+opaque(record['id']+'/'+c) for c in ('full','degraded')}
        cached=audit_path.exists() and all((OUT/folder/(rid+'.json')).exists()
                    for rid in ids.values() for folder in ('inputs','rules','private/views'))
        if cached:
            audit=read(audit_path)
            candidates={a['profile']:(None,a['removed']) for a in audit if a['effective']}
            view=saved_view_header(OUT/'private/views'/(ids['full']+'.json'))
        else:
            view=load_view(run,live)
            candidates = {}
            audit = []
            for profile in PROFILES:
                projected, removed = effective_project(view, profile)
                if removed:
                    candidates[profile] = (projected, removed)
                    audit.append({'profile': profile, 'effective': True, 'removed': removed,
                                  'rules': safe_detect(projected)})
                else:
                    audit.append({'profile': profile, 'effective': False, 'reason': 'no_surviving_target_observation'})
            write_once_exact(audit_path,audit)
        if not candidates:
            raise ValueError('no_effective_projection:' + record['id'])
        chosen = min(candidates, key=lambda p: (profile_counts[group, p], opaque(record['id'] + '/' + p)))
        profile_counts[group, chosen] += 1
        for condition in ('full', 'degraded'):
            current, removed = (view, []) if condition == 'full' else candidates[chosen]
            rid = ids[condition]
            rules = read(OUT/'rules'/(rid+'.json')) if cached else safe_detect(current)
            packet = read(OUT/'inputs'/(rid+'.json')) if cached else public_packet(current, contract)
            packet_chars = len(json.dumps(packet))
            if not cached:
                write(OUT / 'inputs' / (rid + '.json'), packet)
                write(OUT / 'rules' / (rid + '.json'), rules)
                # Private views are local replay artifacts, not model inputs.
                write(OUT / 'private/views' / (rid + '.json'), current)
            rows.append({'id': rid, 'case_id': record['id'], 'seed_id': record['seed_id'],
                         'group': group, 'condition': condition,
                         'profile': 'full' if condition == 'full' else chosen,
                         'truth': record['ground_truth']['verdict'],
                         'truth_taxonomy': record['ground_truth'].get('taxonomy', []),
                         'split': 'selection' if record['seed_id'] in selection_seeds else 'confirmation',
                         'source_run': rel(run), 'source_record': rel(path),
                         'observation_profile': view['profile'], 'source': view['source'],
                         'source_issues': view.get('issues', []), 'removed': removed,
                         'rule_verdict': rules['verdict'], 'rule_error': rules.get('evaluation_error'),
                         'packet_chars': packet_chars, 'input_status': 'ready' if packet_chars <= 240000 else 'oversize',
                         'input': 'inputs/' + rid + '.json'})
        print(json.dumps({'prepared': record['id'], 'group': group, 'degraded': chosen,
                          'loader': 'live' if live else 'historical','resumed':cached}), flush=True)
    rows.sort(key=lambda r: (r['condition'] != 'full', r['id']))
    write(OUT / 'private/selection.json', rows)
    prompt = (HERE / 'prompt.txt').read_text()
    (OUT / 'prompts').mkdir()
    import shutil
    shutil.copyfile(HERE / 'prompt.txt', OUT / 'prompts/prompt.txt')
    code_paths = []
    for folder in ('benchmark_six_v1', 'evidence_baseline_v1', 'llm_review_v1'):
        code_paths.extend((ROOT / 'consistency' / folder).glob('*.py'))
    code_paths += [HERE / 'prompt.txt', ROOT / 'consistency/evidence_pilot_v1/projection.py',
                   ROOT / 'consistency/bc_evidence_pilot_v1/experiment.py',
                   ROOT / 'consistency/dataset_v5_formal/public433_rules.py',
                   ROOT / 'consistency/semantic_adapters.py', ROOT / 'consistency/semantic_model.py']
    sources.update({rel(p): file_hash(p) for p in code_paths})
    sources[rel(COL / 'benchmark-freeze.json')] = file_hash(COL / 'benchmark-freeze.json')
    write(OUT / 'source-freeze.json', sources)
    write(OUT / 'input-freeze.json', {str(p.relative_to(OUT)): file_hash(p) for p in OUT.rglob('*')
                                    if p.is_file() and p.name != 'input-freeze.json'})
    report = {'benchmark_checked': checked, 'views': len(rows),
              'rules_by_condition': {c: dict(Counter(r['rule_verdict'] for r in rows if r['condition'] == c)) for c in ('full', 'degraded')},
              'profiles': {g: {p: profile_counts[g, p] for p in PROFILES} for g in ('normal', 'A', 'B', 'C')},
              'oversize': sum(r['input_status'] != 'ready' for r in rows),
              'source_issues': sum(bool(r['source_issues']) for r in rows),
              'rule_errors': sum(bool(r['rule_error']) for r in rows)}
    write(OUT / 'preflight.json', report)
    print(json.dumps(report, indent=2))


def run(workers=8, limit=None):
    print(json.dumps({'DEEPSEEK_API_KEY_present': bool(os.environ.get('DEEPSEEK_API_KEY')),
                      'WSLENV_present': bool(os.environ.get('WSLENV'))}), flush=True)
    if not os.environ.get('DEEPSEEK_API_KEY'):
        raise ValueError('missing_key')
    verify(ROOT, read(OUT / 'source-freeze.json'))
    verify(OUT, read(OUT / 'input-freeze.json'))
    verify(OUT, read(OUT / 'api-input-freeze.json'))
    rows = read(OUT / 'private/api-selection.json')
    pending = [r for r in rows if not (OUT / 'responses' / (r['id'] + '.json')).exists()]
    if limit:
        pending = pending[:limit]
    system = (OUT / 'prompts/prompt.txt').read_text()
    def one(row):
        path = OUT / 'responses' / (row['id'] + '.json')
        if path.exists():
            return row['id'], 'cached'
        if row['input_status'] != 'ready':
            write(path, {'status': 'input_budget_exceeded', 'api_calls': 0})
            return row['id'], 'input_budget_exceeded'
        packet = read(OUT / row['input'])
        attempts = 0
        for n in range(2):
            ap = OUT / 'attempts' / (row['id'] + f'.attempt-{n+1}.json')
            result = read(ap) if ap.exists() else request(packet, system)
            if not ap.exists():
                write(ap, result)
            attempts += 1
            if result['status'] in ('ok', 'invalid_response') or result.get('http_status') in (400, 401, 402, 403):
                break
        write(path, {**result, 'api_calls': attempts, 'id': row['id'],
                     'system_sha256': file_hash(OUT / 'prompts/prompt.txt'),
                     'packet_sha256': file_hash(OUT / row['input'])})
        return row['id'], result['status']
    if not pending:
        return
    first = one(pending[0])
    print(json.dumps({'response': first}), flush=True)
    if first[1] in ('http_error', 'transport_error'):
        raise RuntimeError('first_request_transport_failure')
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for future in as_completed([pool.submit(one, r) for r in pending[1:]]):
            rid, status = future.result()
            print(json.dumps({'response': rid, 'status': status}), flush=True)


def accepted_verdict(saved, field='inferred_verdict'):
    if saved.get('status') == 'ok' and not saved.get('screen_errors'):
        return saved['response'][field]
    return 'Uncertain'


def apply_policy(rule, llm, policy):
    return llm if (rule == 'Inconsistent' and policy in ('review_I', 'review_IU') or
                   rule == 'Uncertain' and policy in ('review_U', 'review_IU')) else rule


def metrics(rows, key):
    n = len(rows)
    true_i = sum(r['truth'] == 'Inconsistent' for r in rows)
    correct = sum(r[key] == r['truth'] for r in rows)
    false_c = sum(r[key] == 'Consistent' and r['truth'] == 'Inconsistent' for r in rows)
    return {'n': n, 'correct': correct, 'accuracy': correct / n if n else None,
            'verdicts': dict(Counter(r[key] for r in rows)), 'true_I': true_i,
            'false_C': false_c, 'false_C_rate_among_I': false_c / true_i if true_i else None,
            'I_recall': sum(r[key] == 'Inconsistent' and r['truth'] == 'Inconsistent' for r in rows) / true_i if true_i else None,
            'false_I': sum(r[key] == 'Inconsistent' and r['truth'] == 'Consistent' for r in rows)}


def disagreements(rows):
    eligible = [r for r in rows if r['rule_verdict'] != 'Consistent']
    diff = [r for r in eligible if r['rule_verdict'] != r['llm']]
    return {'review_eligible': len(eligible), 'disagree': len(diff),
            'transitions': dict(Counter(r['rule_verdict'] + ' -> ' + r['llm'] for r in eligible)),
            'rule_correct_llm_wrong': sum(r['rule_verdict'] == r['truth'] and r['llm'] != r['truth'] for r in diff),
            'rule_wrong_llm_correct': sum(r['rule_verdict'] != r['truth'] and r['llm'] == r['truth'] for r in diff),
            'both_wrong': sum(r['rule_verdict'] != r['truth'] and r['llm'] != r['truth'] for r in diff),
            'by_rule': {v: {'rules': metrics([r for r in eligible if r['rule_verdict'] == v], 'rule_verdict'),
                           'llm': metrics([r for r in eligible if r['rule_verdict'] == v], 'llm')}
                        for v in ('Inconsistent', 'Uncertain')}}


def score():
    verify(ROOT, read(OUT / 'source-freeze.json'))
    verify(OUT, read(OUT / 'input-freeze.json'))
    verify(OUT, read(OUT / 'api-input-freeze.json'))
    rows = read(OUT / 'private/api-selection.json')
    if any(not (OUT / 'responses' / (r['id'] + '.json')).exists() for r in rows):
        raise ValueError('incomplete_campaign')
    for r in rows:
        saved = read(OUT / 'responses' / (r['id'] + '.json'))
        r['llm'] = accepted_verdict(saved)
        r['llm_evidence'] = accepted_verdict(saved, 'evidence_verdict')
        r['api_status'] = saved['status']
        r['screen_errors'] = saved.get('screen_errors', [])
        for policy in ('rules', 'review_I', 'review_U', 'review_IU'):
            r[policy] = apply_policy(r['rule_verdict'], r['llm'], policy)
        r['hybrid'] = r['review_IU']
    keys = ('rules', 'llm', 'hybrid')
    result = {'complete': True, 'views': len(rows), 'cases': len({r['case_id'] for r in rows}),
              'six_arms': {c: {k: metrics([r for r in rows if r['condition'] == c], k) for k in keys}
                           for c in ('full', 'degraded')},
              'overall_paired': {k: metrics(rows, k) for k in keys}}
    result['by_group'] = {g: {c: {k: metrics([r for r in rows if r['group'] == g and r['condition'] == c], k) for k in keys}
                                  for c in ('full', 'degraded')} for g in ('normal', 'A', 'B', 'C')}
    result['normal_plus_A'] = {c: {k: metrics([r for r in rows if r['group'] in ('normal', 'A') and r['condition'] == c], k) for k in keys} for c in ('full', 'degraded')}
    result['by_profile'] = {p: {k: metrics([r for r in rows if r['profile'] == p], k) for k in keys} for p in ('full',) + PROFILES}
    result['by_observation_profile'] = {p: {c: {k: metrics([r for r in rows if r['observation_profile'] == p and r['condition'] == c], k) for k in keys} for c in ('full', 'degraded')} for p in sorted({r['observation_profile'] for r in rows})}
    result['disagreements'] = {c: disagreements([r for r in rows if r['condition'] == c]) for c in ('full', 'degraded')}
    result['disagreements_by_group'] = {g: {c: disagreements([r for r in rows if r['group'] == g and r['condition'] == c]) for c in ('full', 'degraded')} for g in ('normal', 'A', 'B', 'C')}
    policies = ('rules', 'review_I', 'review_U', 'review_IU')
    def calls(rs, policy):
        return sum((r['rule_verdict'] == 'Inconsistent' and policy in ('review_I', 'review_IU')) or
                   (r['rule_verdict'] == 'Uncertain' and policy in ('review_U', 'review_IU')) for r in rs)
    def best(rs):
        return min(policies, key=lambda p: (-metrics(rs, p)['correct'], metrics(rs, p)['false_C'], calls(rs, p), p))
    selected = best([r for r in rows if r['split'] == 'selection'])
    result['policy_selection'] = {'chosen_on_selection_seeds': selected, 'pooled_retrospective_best': best(rows),
        'by_split': {s: {p: {**metrics([r for r in rows if s == 'all' or r['split'] == s], p),
                             'logical_calls': calls([r for r in rows if s == 'all' or r['split'] == s], p)} for p in policies}
                     for s in ('selection', 'confirmation', 'all')},
        'scope': 'Prospective policy tie-break within this campaign, but benchmark previously exposed during prompt development; not a new blind test.'}
    attempts = [read(p) for p in (OUT / 'attempts').glob('*.json')]
    usage = Counter()
    for a in attempts:
        for key, value in (a.get('usage') or {}).items():
            if isinstance(value, int):
                usage[key] += value
    result['api'] = {'physical_attempts': len(attempts), 'usage': dict(usage),
                     'models': dict(Counter(a.get('model') for a in attempts)),
                     'statuses': dict(Counter(r['api_status'] for r in rows)),
                     'screen_rejected': sum(bool(r['screen_errors']) for r in rows),
                     'logical_calls': {c: {'rules': 0, 'llm': sum(r['condition'] == c for r in rows),
                                          'hybrid': calls([r for r in rows if r['condition'] == c], 'review_IU')}
                                       for c in ('full', 'degraded')}}
    write(OUT / 'results.json', result)
    write(OUT / 'private/scored-rows.json', rows)
    for condition in ('full', 'degraded'):
        for arm in keys:
            write(OUT / 'arms' / (arm + '-' + condition + '.json'),
                  [{'id': r['id'], 'case_id': r['case_id'], 'group': r['group'], 'truth': r['truth'],
                    'prediction': r[arm], 'rule': r['rule_verdict'], 'llm': r['llm'] if arm == 'llm' or arm == 'hybrid' and r['rule_verdict'] != 'Consistent' else None,
                    'model_response_accessed': arm == 'llm' or arm == 'hybrid' and r['rule_verdict'] != 'Consistent'}
                   for r in rows if r['condition'] == condition])
    write(OUT / 'selected-detector.json', {'policy': selected,
          'source': 'selection-seed accuracy, false-C, then API cost tie-break',
          'prompt': 'prompts/prompt.txt', 'prompt_sha256': file_hash(OUT / 'prompts/prompt.txt'),
          'model': read(OUT / 'plan.json')['api'],
          'on_rule_C': 'keep_rules', 'on_rule_I': 'llm_inferred' if selected in ('review_I', 'review_IU') else 'keep_rules',
          'on_rule_U': 'llm_inferred' if selected in ('review_U', 'review_IU') else 'keep_rules',
          'on_review_failure': 'Uncertain', 'preserve_original_rules': True,
          'scope': 'Offline benchmark configuration; no unrequested VM deployment. Retrospective benchmark exposure disclosed.'})
    write(OUT / 'result-freeze.json', {'files': {str(p.relative_to(OUT)): file_hash(p) for p in OUT.rglob('*') if p.is_file()},
                                      'input_freeze_sha256': file_hash(OUT / 'input-freeze.json')})
    print(json.dumps({k: result[k] for k in ('six_arms', 'policy_selection', 'api')}, indent=2))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('prepare', 'run', 'score'))
    parser.add_argument('--workers', type=int, default=8)
    parser.add_argument('--limit', type=int)
    args = parser.parse_args()
    if args.action == 'prepare': prepare()
    elif args.action == 'run': run(args.workers, args.limit)
    else: score()


if __name__ == '__main__':
    main()
