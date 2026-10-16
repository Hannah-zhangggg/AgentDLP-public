"""Label-free semantic-information projections and dependent-check ablation.

Neither projection edits a captured instruction, invocation, result, state,
identity, clock, or window marker. The rule adapter withdraws dependent rule
claims, not complete case decisions. Literal equality and independent
contradictions remain usable. Applicability never depends on prediction loss.
"""
from collections import Counter
from copy import deepcopy
from consistency.evidence_baseline_v1.collectors import canonical
from consistency.evidence_baseline_v1.detector import finish

NEW_PROFILES = ('E1_contract', 'E1_field')
RETAINED = ('full', 'E2_binding', 'E3_effect', 'E3_delivery', 'E4_closure')
PROFILES = ('full', *NEW_PROFILES, *RETAINED[1:])

# Published policy distinguishes operational obligations from representation.
CONTRACT_KEYS = {'invocation', 'result', 'write_file', 'nested_api', 'stop'}
FIELD_KEYS = {'arguments'}
CONTRACT_LEGAL = {'read_attempts', 'read_tools', 'unchanged'}
FIELD_LEGAL = {'program', 'json_result'}
CONTRACT_CLAIMS = {
    'admission', 'count', 'extra', 'dependency', 'delivery',
    'model_reporting', 'program_api_result', 'program_api_coverage',
}


def project_contract(contract, profile):
    if profile not in NEW_PROFILES:
        raise ValueError(profile)
    result = deepcopy(contract)
    removed = []
    removed_text = []
    def drop(obj, key, path):
        if key in obj:
            value = obj.pop(key)
            removed.append(path + '/' + key)
            if isinstance(value, str) and value:
                removed_text.append(value)
    policy = result.get('public-contract.json', {})
    legal = result.get('legal-public-contract.json', {})
    keys = CONTRACT_KEYS if profile == 'E1_contract' else FIELD_KEYS
    legal_keys = CONTRACT_LEGAL if profile == 'E1_contract' else FIELD_LEGAL
    for key in sorted(keys):
        drop(policy, key, '/public-contract.json')
    for key in sorted(legal_keys):
        drop(legal, key, '/legal-public-contract.json')
    # Mixed precedence text repeats both sorts of policy. Do not retain a copy.
    if legal:
        drop(legal, 'precedence', '/legal-public-contract.json')
        drop(legal, 'version', '/legal-public-contract.json')
    for i, tool in enumerate(result.get('native-tool-schemas.json', [])):
        path = f'/native-tool-schemas.json/{i}'
        if profile == 'E1_contract':
            for key in ('description', 'annotations', 'execution'):
                drop(tool, key, path)
        else:
            for key in ('inputSchema', 'outputSchema'):
                drop(tool, key, path)
    # Legal clauses are also appended to tool descriptions. Remove the same
    # exact strings everywhere in the metadata tree; preserve other clauses.
    def erase_copies(value, path=''):
        if isinstance(value, dict):
            return {k: erase_copies(v, path+'/'+k) for k, v in value.items()}
        if isinstance(value, list):
            return [erase_copies(v, path+'/'+str(i)) for i, v in enumerate(value)]
        if isinstance(value, str):
            for text in sorted(set(removed_text), key=len, reverse=True):
                if text in value:
                    value = value.replace(text, '')
                    removed.append(path+'/duplicate_clause')
            return value.strip()
        return value
    result = erase_copies(result)
    # No ablation label or experimental instruction is supplied to the model.
    return result, sorted(set(removed))


def _literal_argument_match(view, claim):
    instructions = {'provider:'+x['call_ref']: x for x in view['instructions']}
    observations = {x.get('evidence_id'): x for x in view['events']}
    left = next((instructions[r] for r in claim['refs'] if r in instructions), None)
    right = next((observations[r] for r in claim['refs'] if r in observations), None)
    return left is not None and right is not None and canonical(left['arguments']) == canonical(right['arguments'])


def semantic_rules(view, full_rules, profile):
    """Disable semantic-dependent checks without changing unrelated rules.

Full uses the unchanged baseline result. For E1, the baseline claim inventory
locates checks; disabled results, payloads, reasons, and taxonomy never enter
aggregation or LLM inputs. The private audit alone keeps their prior labels.
This is an explicit semantic-capability ablation, not merely LLM-text deletion.
"""
    if profile == 'full':
        return deepcopy(full_rules), []
    if profile not in NEW_PROFILES:
        raise ValueError(profile)
    claims = []
    audit = []
    for original in full_rules['claims']:
        claim = deepcopy(original)
        kind = claim['kind']
        # Effect checks embed argument-to-state field roles and domain
        # postconditions. Both projections must withdraw this redundant
        # compiled knowledge, while observed state itself remains intact.
        dependency = 'field_roles_and_effect_contract' if kind.startswith('effect:') else None
        if profile == 'E1_contract' and kind in CONTRACT_CLAIMS:
            dependency = 'operational_contract'
        if profile == 'E1_field' and kind == 'arguments' and not _literal_argument_match(view, claim):
            dependency = 'argument_interpretation_and_equivalence'
        if profile == 'E1_field' and kind == 'program_api_arguments':
            # Exact program expressions and JSON equality need no external
            # field schema; differing values need the missing interpretation.
            if claim['verdict'] != 'Consistent':
                dependency = 'nested_argument_interpretation'
        if dependency:
            audit.append({'claim_id': claim['id'], 'kind': kind,
                          'dependency': dependency, 'before': claim['verdict'],
                          'after': 'Uncertain'})
            claim.update(verdict='Uncertain', reason='required_semantic_information_unavailable',
                         taxonomy=[], basis='semantic_availability', route='llm_semantic_review')
            claim.pop('payload', None)
            claim['evidence_matrix']['E1_semantics'] = 'unavailable'
            claim['evidence_matrix']['E3_effect']['missing'] = False
        claims.append(claim)
    result = finish(claims, view, include_graph=False)
    result['semantic_availability'] = {
        'operational_contract': profile != 'E1_contract',
        'field_schema_and_equivalence': profile != 'E1_field',
        'disabled_checks': len(audit),
    }
    return result, audit
