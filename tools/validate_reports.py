"""Check frozen statistics independently, without overwriting published outputs."""
import json,os,shutil,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
 results={}
 for name,script in [('accuracy_components_backends','tools/recompute.py'),('live_cases','results/live-cases/recompute.py'),('evidence_ablation_intervals','results/evidence-ablation/code/consistency/evidence_ablation_v2/report.py')]:
  extra=['--public',str(ROOT/'results/evidence-ablation')] if name=='evidence_ablation_intervals' else []
  p=subprocess.run([sys.executable,'-I',str(ROOT/script),*extra],cwd='/tmp',text=True,capture_output=True)
  results[name]={'passed':p.returncode==0,'stdout':p.stdout,'stderr':p.stderr}
 with tempfile.TemporaryDirectory(prefix='agentdlp-statistics-') as tmp:
  target=Path(tmp);shutil.copytree(ROOT/'results/performance',target/'public')
  p=subprocess.run([sys.executable,'-I',str(target/'public/code/report.py')],env={**os.environ,'AGENTDLP_EXPERIMENT_ROOT':str(target)},cwd=tmp,text=True,capture_output=True)
  old=json.loads((ROOT/'results/performance/summary.json').read_text());new=json.loads((target/'public/summary.json').read_text())
  # Public reaggregation has no private accuracy verdicts; the documented comparison is absent.
  ignored=['new_hybrid_vs_accuracy_disagreements']
  diff=[k for k in old if k not in ignored and old[k]!=new.get(k)]
  results['performance']={'passed':p.returncode==0 and not diff,'different_fields':diff,'excluded_private_only_fields':ignored,'stderr':p.stderr}
 output={'passed':all(x['passed'] for x in results.values()),'checks':results}
 dest=ROOT/'validation/report-recomputation.json';dest.parent.mkdir(exist_ok=True);dest.write_text(json.dumps(output,indent=2)+'\n')
 print(json.dumps({k:v['passed'] for k,v in results.items()}));return int(not output['passed'])
if __name__=='__main__':raise SystemExit(main())
