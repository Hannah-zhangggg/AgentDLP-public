"""Recompute final paper counts without model calls or private evidence."""
import argparse,collections,json,sys
from pathlib import Path
R=Path(__file__).resolve().parents[1]
def read(p):return json.loads(p.read_text())
def stats(rows,field):return {'n':len(rows),'correct':sum(x[field]==x['truth'] for x in rows),'U':sum(x[field]=='Uncertain' for x in rows),'accuracy':sum(x[field]==x['truth'] for x in rows)/len(rows)}
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,default=R/'validation/statistics.json');a=p.parse_args();report={}
 rows=read(R/'results/accuracy/case-results.json');assert len(rows)==2862
 assert len({(x['harness'],x['case_id'],x['condition']) for x in rows})==2862
 report['accuracy']={}
 for h in ['opencode','claude-code','gemini-cli']:
  report['accuracy'][h]={}
  for c in ['full','degraded']:
   group=[x for x in rows if x['harness']==h and x['condition']==c];s=stats(group,'verdict');assert s['n']==477
   expected=read(R/'results/accuracy/metrics.json')[h][c]['overall'];assert s['correct']==expected['correct'];report['accuracy'][h][c]=s
 report['backends']={}
 for m in ['deepseek','gpt','glm']:
  rr=read(R/'results/backends'/m/'scored-rows.json');s=stats(rr,'review_U');assert s['n']==954;assert s['correct']==read(R/'results/accuracy/backend-metrics.json')[m]['overall']['correct'];report['backends'][m]=s
 rr=read(R/'results/components/scored-rows.json');report['components']={}
 for policy,m in read(R/'results/accuracy/ablation-metrics.json').items():
  s=stats(rr,policy);assert s['correct']==m['overall']['correct'];report['components'][policy]=s
 for name in ['evidence-ablation','live-cases']:
  rr=read(R/'results'/name/('outcomes.json' if name=='evidence-ablation' else 'decisions.json'));assert len(rr)==(3231 if name=='evidence-ablation' else 350)
  report[name]={profile:stats([x for x in rr if x['profile']==profile],'hybrid') for profile in sorted({x['profile'] for x in rr})}
 report['passed']=True;a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
