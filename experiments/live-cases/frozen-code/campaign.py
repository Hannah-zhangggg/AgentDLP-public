"""Sequential VM campaign; no selective retries. Credentials stay in memory."""
import sys,json,subprocess,time,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
phase=sys.argv[1];password=sys.stdin.readline().strip();plan=json.loads((ROOT/'private/run-plan.json').read_text())
if phase=='formal':
 frozen=json.loads((ROOT/'protocol/source-freeze.json').read_text())
 for name,digest in frozen['files'].items():
  if hashlib.sha256((ROOT.parents[1]/name).read_bytes()).hexdigest()!=digest:raise RuntimeError('Source drift: '+name)
for i,job in enumerate(plan):
 if job['phase']!=phase:continue
 local=ROOT/phase/job['case']/job['condition']/('rep%02d'%job['repetition'])
 if phase=='pilot' and i==0:continue
 if (local/'retrieval.json').exists():continue
 if local.exists():raise RuntimeError('Incomplete existing attempt requires audit, never overwrite: '+str(local))
 print(json.dumps({'job':i,**job}),flush=True)
 p=subprocess.run([sys.executable,str(ROOT/'scripts/host.py'),'--index',str(i)],input=password+'\n',text=True)
 if p.returncode or not (local/'retrieval.json').exists() or (local/'error.json').exists():raise RuntimeError('Infrastructure failure; pause remaining campaign for audit')
 print(json.dumps({'completed':i,'time':time.time()}),flush=True)
print('CAMPAIGN_COMPLETE '+phase,flush=True)
