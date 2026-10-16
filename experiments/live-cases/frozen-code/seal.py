"""Seal local results after all writers stop; verify archive and public bundle."""
import json,hashlib,zipfile,os,time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
secret=os.environ.get('DEEPSEEK_API_KEY','').encode()
public=ROOT/'public'
files=[p for p in public.rglob('*') if p.is_file() and p.name!='manifest.json' and '__pycache__' not in p.parts]
pins={p.relative_to(public).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
(public/'manifest.json').write_text(json.dumps({'files':pins},indent=2))
bundle=ROOT/'public-summary.zip'
with zipfile.ZipFile(bundle,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
 for p in sorted(public.rglob('*')):
  if p.is_file() and '__pycache__' not in p.parts:z.write(p,'public/'+p.relative_to(public).as_posix())
with zipfile.ZipFile(bundle) as z:
 for name,digest in pins.items():
  if hashlib.sha256(z.read('public/'+name)).hexdigest()!=digest:raise RuntimeError('Public ZIP mismatch')
excluded={'archive-manifest.json','archive-verification.json'}
files=[p for p in ROOT.rglob('*') if p.is_file() and p.name not in excluded and '__pycache__' not in p.parts]
def one(p):
 data=p.read_bytes()
 if secret and secret in data:raise RuntimeError('API credential appeared in artifact: '+str(p.relative_to(ROOT)))
 return p.relative_to(ROOT).as_posix(),{'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)}
with ThreadPoolExecutor(max_workers=4) as pool:manifest=dict(pool.map(one,files))
metadata={'created':time.time(),'file_count':len(manifest),'total_bytes':sum(v['bytes'] for v in manifest.values()),'excluded':['__pycache__/',*sorted(excluded)],'files':manifest}
(ROOT/'archive-manifest.json').write_text(json.dumps(metadata,indent=2))
print(json.dumps({'manifest_files':len(manifest),'bytes':metadata['total_bytes']}),flush=True)
def check(item):
 name,data=item;p=ROOT/name
 return p.stat().st_size==data['bytes'] and hashlib.sha256(p.read_bytes()).hexdigest()==data['sha256']
with ThreadPoolExecutor(max_workers=4) as pool:passed=all(pool.map(check,manifest.items()))
result={'passed':passed,'files':len(manifest),'bytes':metadata['total_bytes'],'public_zip_verified':True,'api_key_absent':True,'manifest_sha256':hashlib.sha256((ROOT/'archive-manifest.json').read_bytes()).hexdigest(),'public_zip_sha256':hashlib.sha256(bundle.read_bytes()).hexdigest()}
(ROOT/'archive-verification.json').write_text(json.dumps(result,indent=2));print(json.dumps(result),flush=True)
if not passed:raise SystemExit(1)
