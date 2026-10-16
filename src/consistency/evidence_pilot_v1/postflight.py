"""Verify frozen inputs/results; separately pin later routing and documentation."""
from .experiment import ROOT, OUT, COL, read, file_hash
import json


def verify(base, files):
    for relative, digest in files.items():
        if file_hash(base / relative) != digest:
            raise ValueError('hash_mismatch:' + relative)
    return len(files)


def main():
    verified = {
        'experiment_files': verify(ROOT, read(OUT / 'freeze.json')['files']),
        'source_pins': verify(ROOT, read(OUT / 'source-freeze.json')),
        'public_packets': verify(OUT, read(OUT / 'packet-freeze.json')),
        'consolidated_files': verify(ROOT, read(COL / 'freeze.json')['files']),
    }
    routing = read(OUT / 'routing-audit.json')
    assert routing['all_48_complete_legal_inputs_keep_v3']
    assert routing['route_counts'] == {'v3': 64, 'v4': 46}
    paths = [
        ROOT / 'consistency/evidence_pilot_v1/routing.py',
        ROOT / 'consistency/evidence_pilot_v1/postflight.py',
        ROOT / 'consistency/evidence_pilot_v1/README.md',
        ROOT / 'tests/test_evidence_pilot_routing.py',
        ROOT / 'consistency/reports/EVIDENCE_LOSS_PILOT_20260913.md',
        ROOT / 'docs/IMPLEMENTATION.md',
        ROOT / 'docs/DIRECTORY.md',
        ROOT / 'docs/计划文档/2026-09-13_A组证据退化与LLM推断试验.md',
        OUT / 'README.md', OUT / 'routing-audit.json', OUT / 'freeze.json',
    ]
    result = {
        'verified': verified,
        'files': {str(p.relative_to(ROOT)): file_hash(p) for p in paths},
        'scope': 'Post-experiment route/report additions, not a replacement of the original freeze or a new model evaluation.',
        'tests': {'run': 610, 'skipped': 10, 'status': 'OK'},
        'primary_criterion': 'Overall degraded recovery; no minimum for every evidence-loss subgroup.',
    }
    # Exclusive creation avoids silently replacing a previous audit.
    with (OUT / 'postflight-freeze.json').open('x', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
        f.write('\n')
    print(json.dumps({'verified': verified, 'postflight_files': len(paths)}, indent=2))


if __name__ == '__main__':
    main()
