"""Revalidate recorded backend responses and recompute routing policies; no API calls."""
import argparse,json,socket,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from replay import ROOT,load,read,prohibit_network
from consistency.benchmark_six_v1.experiment import accepted_verdict
from consistency.llm_review_v1.packet import screen
def main():
 socket.create_connection=prohibit_network
 rows=read(ROOT/'local-data/model-comparisons/index.json');gold={r['id']:r for r in read(ROOT/'evaluation/model-comparisons.json')};failures=[];checked=0
 for row in rows:
  packet=load(row['packet']);response=load(row['response']);target=gold[row['id']];errors=[]
  if 'response' in response and response.get('status') in ['ok','invalid_response']:
   current=screen(packet,response['response']);checked+=1
   if current!=response.get('screen_errors',[]):errors.append('screen_mismatch')
  llm=accepted_verdict(response)
  if llm!=target['llm']:errors.append('llm_mismatch')
  rule=target['rules']
  for policy,reviewed in [('review_U',{'Uncertain'}),('review_I',{'Inconsistent'}),('review_IU',{'Inconsistent','Uncertain'})]:
   prediction=llm if rule in reviewed else rule
   if prediction!=target[policy]:errors.append(policy+'_mismatch')
  if errors:failures.append({'id':row['id'],'errors':errors})
 report={'passed':not failures,'responses':len(rows),'screened_responses':checked,'failures':failures,'network':'disabled','scope':'recorded LLM responses and routing; rule outputs independently checked by accuracy replay'}
 (ROOT/'validation/model-response-replay.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k!='failures'}));return int(bool(failures))
if __name__=='__main__':raise SystemExit(main())
