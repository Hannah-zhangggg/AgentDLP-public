"""Pin deployed native implementation and instrumented harness dependencies."""
import sys,json,hashlib,stat
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
from host import connect,remote,PINS,HOSTS,ENV,PY
password=sys.stdin.readline().strip();manifest={}
for role in ('external','endpoint'):
 c,_=connect(HOSTS[role],password,PINS[role]);s=c.open_sftp();paths=[]
 if role=='external':
  base='/home/zhang/v5-formal-public-r1/app'
  paths=[base+'/consistency/dataset_v5_formal/'+n for n in ('backend.py','common.py','tau_source.py')]
  td=base+'/artifacts/reports/v5-formal-sources/tau-bench/tau_bench/envs/retail'
  paths += [td+'/tools/'+e.filename for e in s.listdir_attr(td+'/tools') if e.filename.endswith('.py')]
  paths += [td+'/tasks_test.py',td+'/wiki.md']
  paths += [td+'/data/'+e.filename for e in s.listdir_attr(td+'/data') if stat.S_ISREG(e.st_mode)]
 else:paths=['/home/zhang/.opencode/bin/opencode','/home/zhang/.opencode/package.json','/home/zhang/.opencode/package-lock.json','/home/zhang/.opencode/node_modules/@opencode-ai/plugin/package.json','/home/zhang/.opencode/node_modules/@opencode-ai/sdk/package.json']
 hashes={}
 for i,path in enumerate(paths):
  digest=remote(c,'sha256sum '+path)['stdout'].split()[0];hashes[path]=digest
  if not path.endswith('/bin/opencode'):
   dest=ROOT/'protocol/deployed-sources'/role/path.removeprefix('/home/zhang/');dest.parent.mkdir(parents=True,exist_ok=True);s.get(path,str(dest))
   if hashlib.sha256(dest.read_bytes()).hexdigest()!=digest:raise RuntimeError('Retrieval changed')
 manifest[role]=hashes;s.close();c.close()
(ROOT/'protocol/remote-source-pins.json').write_text(json.dumps(manifest,indent=2))
print(json.dumps({k:len(v) for k,v in manifest.items()}))
