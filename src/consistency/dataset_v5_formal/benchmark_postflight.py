"""Read-only benchmark verification; optionally pin the final layout/docs separately."""
import argparse
from collections import Counter
import json

from .consolidate_benchmark import ROOT, OUT, EXEC, read, validate_record
from .common import file_hash
from consistency.evidence_pilot_v1.postflight import verify


def check():
    freeze = read(OUT / 'benchmark-freeze.json')
    execution_freeze = read(EXEC / 'freeze.json')
    checked = {
        'original_collection_files': verify(ROOT, read(OUT / 'freeze.json')['files']),
        'benchmark_files': verify(ROOT, freeze['files']),
        'benchmark_sources': verify(ROOT, freeze['sources']),
        'original_execution_files': verify(EXEC, execution_freeze['files']),
        'original_private_evaluations': verify(
            ROOT / execution_freeze['private_evaluation_root'], execution_freeze['private_files']),
    }
    assert file_hash(ROOT / freeze['builder']['path']) == freeze['builder']['sha256']
    layout = read(OUT / 'benchmark-layout.json')
    for alias, target in layout['compatibility_aliases'].items():
        assert (OUT / alias).is_symlink(), alias
        assert not (OUT / target).is_symlink(), target
        assert (OUT / alias).resolve() == (OUT / target).resolve()
    ids = set()
    truth = Counter()
    counts = {}
    for group in layout['groups']:
        folder = OUT / group['path']
        rows = [json.loads(line) for line in (folder / 'records.jsonl').read_text().splitlines()]
        manifest = read(folder / 'manifest.json')
        assert len(rows) == manifest['count'] == group['count']
        assert {r['id'] for r in rows} == {r['id'] for r in manifest['records']}
        assert {p.stem for p in (folder / 'records').glob('*.json')} == {r['id'] for r in rows}
        for entry in manifest['records']:
            assert file_hash(folder / entry['file']) == entry['sha256']
        for row in rows:
            validate_record(row)
            assert row == read(folder / 'records' / (row['id'] + '.json'))
            assert row['id'] not in ids
            ids.add(row['id'])
            truth[row['ground_truth']['verdict']] += 1
        counts[group['path']] = len(rows)
    assert len(ids) == layout['total_records'] == 484
    assert truth == {'Consistent': 243, 'Inconsistent': 241}
    for name, count in [('evidence-views', 130), ('related-executions', 4)]:
        folder = OUT / name
        rows = [json.loads(line) for line in (folder / 'records.jsonl').read_text().splitlines()]
        assert len(rows) == read(folder / 'manifest.json')['count'] == count
        for row in rows:
            assert row == read(folder / 'records' / (row['id'] + '.json'))
    checked.update({'counts': counts, 'truth': dict(truth), 'record_ids_unique': True,
                    'canonical_aliases_valid': True, 'schema_and_jsonl_equal': True})
    return checked


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--freeze', action='store_true', help='Create a separate final documentation/layout pin, exclusively.')
    args = parser.parse_args()
    checked = check()
    paths = sorted(OUT.rglob('*.md')) + [
        OUT / 'benchmark-layout.json', OUT / 'benchmark-freeze.json',
        OUT.parent / 'current-collections.json',
        ROOT / 'consistency/dataset_v5_formal/benchmark_postflight.py',
    ]
    pins = {str(path.relative_to(ROOT)): file_hash(path) for path in paths}
    final = OUT / 'release-postflight.json'
    if args.freeze:
        with final.open('x', encoding='utf-8') as stream:
            json.dump({'checked': checked, 'files': pins,
                       'scope': 'Layout/documentation finalization; no new execution or oracle rerun.'},
                      stream, ensure_ascii=False, indent=2)
            stream.write('\n')
    elif final.exists():
        checked['release_documentation_files'] = verify(ROOT, read(final)['files'])
    print(json.dumps(checked, indent=2))


if __name__ == '__main__':
    main()
