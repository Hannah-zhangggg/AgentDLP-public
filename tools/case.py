"""List or replay one frozen input without loading evaluation truth."""
import argparse,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from replay import ROOT,one,read
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--suite',choices=['accuracy','evidence-ablation','live-cases'],required=True);p.add_argument('--id');p.add_argument('--list',action='store_true');p.add_argument('--output',type=Path);a=p.parse_args()
 rows=read(ROOT/'local-data'/a.suite/'index.json')
 if a.list:
  print(json.dumps([{k:r[k] for k in ['id','profile','harness','condition'] if k in r} for r in rows],indent=2));return 0
 if not a.id:p.error('--id is required unless --list is used')
 found=[r for r in rows if r['id']==a.id]
 if len(found)!=1:p.error('id must identify exactly one input in this suite')
 result=one(found[0]);text=json.dumps(result,indent=2)+'\n'
 if a.output:a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(text)
 else:print(text,end='')
 return int(bool(result['errors']))
if __name__=='__main__':raise SystemExit(main())
