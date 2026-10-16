"""Windows host orchestration. Password read from stdin; never written."""
import os,sys,json,time,threading,socket,select,stat,hashlib,argparse,urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
REPO=ROOT.parents[1]
sys.path.insert(0,str(REPO/'consistency/harness'))
from v5_vm_host import connect,remote
from v5_vm_inspect import PINS
HOSTS={'gateway':'172.23.108.34','external':'172.23.106.9','endpoint':'172.23.111.78'}
BASE='/home/zhang/qwen3-live-case-study-r1-20260922'
PY='/home/zhang/v5-formal-public-r1/python/bin/python3.11'
ENV='PYTHONHOME=/home/zhang/v5-formal-public-r1/python PYTHONPATH=/home/zhang/v5-formal-public-r1/app:/home/zhang/v5-formal-public-r1/app/artifacts/reports/v5-formal-env/runtime/lib/python3.11/site-packages '

def dump(p,v):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(v,indent=2),encoding='utf-8')
def pump(ch):
 sock=socket.create_connection(('127.0.0.1',11436))
 try:
  while True:
   ready,_,_=select.select([ch,sock],[],[],30)
   for src in ready:
    data=src.recv(65536)
    if not data:return
    (sock if src is ch else ch).sendall(data)
 finally:sock.close();ch.close()
def main():
 if os.name!='nt':raise RuntimeError('SSH orchestration must originate on the Windows host')
 p=argparse.ArgumentParser();p.add_argument('--index',type=int,default=0);p.add_argument('--attempt',type=int,default=1);a=p.parse_args();password=sys.stdin.readline().strip()
 cs={role:connect(host,password,PINS[role])[0] for role,host in HOSTS.items()}
 for c in cs.values():c.get_transport().set_keepalive(15)
 ext=cs['external'];end=cs['endpoint'];job=json.loads((ROOT/'private/run-plan.json').read_text())[a.index];case=next(x for x in json.loads((ROOT/'protocol/cases.json').read_text()) if x['id']==job['case']);spec={'id':case['id'],'plan':case['plan'],'model_seed':job['model_seed']};base=BASE+'/'+spec['id'];rid=job['run_id']
 if a.attempt!=1 and job['phase']!='pilot':raise ValueError('Formal reruns prohibited')
 if a.attempt!=1:rid+='p'+str(a.attempt)
 local=ROOT/job['phase']/spec['id']/job['condition']/('rep%02d'%job['repetition']+('' if a.attempt==1 else '-attempt%02d'%a.attempt))
 if local.exists():raise FileExistsError(str(local))
 local.mkdir(parents=True)
 (local/'runtime.py').write_text((ROOT/'scripts/runtime.py').read_text(encoding='utf-8-sig'),encoding='utf-8')
 (local/'host.py').write_text(Path(__file__).read_text(encoding='utf-8-sig'),encoding='utf-8')
 dump(local/'start.json',{'time':time.time(),'spec':spec,'hosts':HOSTS,'host_key_pins':PINS,'runtime_sha256':hashlib.sha256((local/'runtime.py').read_bytes()).hexdigest(),'job':job})
 def cmd(c,s,**kw):
  r=remote(c,s,**kw)
  if r['exit']:raise RuntimeError(json.dumps(r))
  return r['stdout']
 def put(c,text,path):
  s=c.open_sftp()
  with s.file(path,'w') as f:f.write(text)
  s.close()
 def fetch(c,path,dest):
  s=c.open_sftp()
  def visit(p,d):
   d.mkdir(parents=True,exist_ok=True)
   for e in s.listdir_attr(p):
    if e.filename in ('data','cache','state','config','workspace'):continue
    if stat.S_ISDIR(e.st_mode):visit(p+'/'+e.filename,d/e.filename)
    elif stat.S_ISREG(e.st_mode):s.get(p+'/'+e.filename,str(d/e.filename))
  try:visit(path,dest)
  finally:s.close()
 active=False
 try:
  if job['phase']=='formal':
   for name,digest in json.loads((ROOT/'protocol/source-freeze.json').read_text())['files'].items():
    if hashlib.sha256((REPO/name).read_bytes()).hexdigest()!=digest:raise RuntimeError('Frozen source drift: '+name)
  source_pins=ROOT/'protocol/remote-source-pins.json'
  if source_pins.exists():
   verified={}
   for role,pins in json.loads(source_pins.read_text()).items():
    observed={line.split(maxsplit=1)[1].strip():line.split()[0] for line in cmd(cs[role],'sha256sum '+' '.join(pins)).splitlines()}
    if observed!=pins:raise RuntimeError('Remote source drift: '+role)
    verified[role]=len(observed)
   dump(local/'remote-source-verification.json',verified)
  for role,c in cs.items():
   free=int(cmd(c,'df -B1 --output=avail /home/zhang').splitlines()[-1])
   if free<1500*1024*1024:raise RuntimeError(role+' below free-space guard; no automatic deletion')
  op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
  tags=json.load(op.open('http://127.0.0.1:11436/api/tags',timeout=10))
  model=next(m for m in tags['models'] if m['name']=='qwen3:8b')
  dump(local/'model.json',model)
  if model['digest']!='500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41':raise RuntimeError('Model digest drift')
  deployed={}
  for role,c in [('external',ext),('endpoint',end)]:
   cmd(c,'mkdir -p '+base)
   hashes={}
   for name in ('runtime.py','injector.py','native_observer.py','cs_collectors.py','observer.js'):
    if role=='external' and name in ('injector.py','observer.js'):continue
    source=(ROOT/'scripts'/name).read_text(encoding='utf-8-sig')
    put(c,source,base+'/'+name)
    wire_hash=cmd(c,'sha256sum '+base+'/'+name).split()[0]
    if wire_hash!=hashlib.sha256(source.encode()).hexdigest():raise RuntimeError('Deployment hash mismatch')
    hashes[name]=wire_hash
   put(c,json.dumps(spec),base+'/spec.json')
   deployed[role]=hashes
  dump(local/'deployment.json',deployed)
  put(end,json.dumps({'case':case['id'],'condition':job['condition']}),base+'/fault-'+rid+'.json')
  prompt=(ROOT/'protocol/prompts'/f"{spec['id']}.txt").read_text(encoding='utf-8')
  put(end,prompt,base+'/prompt.txt');(local/'prompt.txt').write_text(prompt,encoding='utf-8')
  def accept(ch,*args):threading.Thread(target=pump,args=(ch,),daemon=True).start()
  ext.get_transport().request_port_forward('127.0.0.1',11435,handler=accept)
  cmd(ext,"test -z \"$(ss -ltnH '( sport = :8000 )')\"")
  cmd(ext,'mkdir -p '+base+'/runs/'+rid)
  start='nohup env '+ENV+PY+' -u '+base+'/runtime.py provider --root '+base+' --run-id '+rid+' > '+base+'/runs/'+rid+'/provider.log 2>&1 < /dev/null & echo $!'
  pid=cmd(ext,start).strip();active=True
  for _ in range(45):
   health=remote(ext,"curl --noproxy '*' -fsS --max-time 2 http://192.168.20.10:8000/health")
   if not health['exit']:break
   time.sleep(1)
  if health['exit']:raise RuntimeError(cmd(ext,'cat '+base+'/runs/'+rid+'/provider.log'))
  flow='/home/zhang/agentdlp/artifacts/three-vm/gateway/flows/three-vm-smoke-001.flow'
  sf=cs['gateway'].open_sftp();offset=sf.stat(flow).st_size;sf.close()
  print(json.dumps({'started':spec['id'],'run':rid}),flush=True)
  execution=remote(end,'python3 '+base+'/runtime.py endpoint --root '+base+' --run-id '+rid,timeout=1260)
  dump(local/'execution.json',execution)
  if execution['exit']:dump(local/'error.json',{'error':'Endpoint runner failed','execution':execution})
  extract=remote(cs['gateway'],'docker exec -i agentdlp-gateway-vm-mitmproxy-1 python - '+str(offset)+' '+spec['id']+'-'+rid,input_text=(REPO/'consistency/workflow_v1/gateway_extract.py').read_text(),timeout=60)
  if extract['exit']==0:dump(local/'gateway.json',json.loads(extract['stdout']))
  else:dump(local/'gateway-error.json',extract)
  finish=remote(ext,"curl --noproxy '*' --max-time 180 -fsS -X POST -d '{}' http://192.168.20.10:8000/finish",timeout=190)
  dump(local/'finish.json',finish)
  if finish['exit']:dump(local/'error.json',{'error':'Native evaluator finalization failed','finish':finish})
 except Exception as e:dump(local/'error.json',{'error':str(e)});print(str(e),flush=True)
 finally:
  if active:remote(ext,'kill '+pid)
  for role,c in [('external',ext),('endpoint',end)]:
   try:fetch(c,base+'/runs/'+rid,local/role)
   except Exception as e:dump(local/(role+'-fetch-error.json'),{'error':str(e)})
  dump(local/'retrieval.json',{'sha256':{p.relative_to(local).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in local.rglob('*') if p.is_file()},'ended':time.time()})
  for c in cs.values():c.close()
  print(json.dumps({'finished':spec['id'],'run':rid,'directory':str(local)}),flush=True)
if __name__=='__main__':main()
