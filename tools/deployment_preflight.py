"""Validate three-host configuration locally. Does not open SSH connections."""
import argparse,json
from pathlib import Path
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--config',required=True,type=Path);a=p.parse_args();data=json.loads(a.config.read_text());errors=[]
 hosts=data.get('hosts',{})
 for role in ['gateway','external','endpoint']:
  item=hosts.get(role,{})
  for key in ['host','username','host_key_sha256','workdir']:
   if not item.get(key) or item[key]=='REPLACE_ME':errors.append(role+': configure '+key)
  if not isinstance(item.get('ssh_port'),int) or not 1<=item.get('ssh_port',0)<=65535:errors.append(role+': invalid ssh_port')
  if not item.get('workdir','').startswith('/'):errors.append(role+': workdir must be absolute')
  fp=item.get('host_key_sha256','')
  if fp!='REPLACE_ME' and (len(fp)!=64 or any(c not in '0123456789abcdef' for c in fp.lower())):errors.append(role+': host key must be 64 hex digits')
 def scan(obj):
  if isinstance(obj,dict):
   for k,v in obj.items():
    if k.lower() in ['password','api_key','private_key','token']:errors.append('Do not store secrets in this configuration: '+k)
    scan(v)
  elif isinstance(obj,list):
   for v in obj:scan(v)
 scan(data)
 print(json.dumps({'configuration_valid':not errors,'remote_checks_performed':False,'errors':errors},indent=2))
 return int(bool(errors))
if __name__=='__main__':raise SystemExit(main())
