"""Detect one normalized evidence view; no labels are accepted by this interface."""
import argparse,json,sys,os
from pathlib import Path
R=Path(__file__).resolve().parents[1];sys.path.insert(0,str(R/'src'))
from consistency.benchmark_six_v1.experiment import safe_detect,public_packet,accepted_verdict
from consistency.benchmark_six_v1.encoding import pack,API_MAX_CHARS
from consistency.llm_review_v1.packet import screen
from consistency.benchmark_six_v1.transport import request
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--view',required=True,type=Path);p.add_argument('--contract',required=True,type=Path);p.add_argument('--saved-response',type=Path);p.add_argument('--live',action='store_true',help='Explicitly use the frozen DeepSeek V4 Flash transport if rules return U; makes a billable API request');p.add_argument('--output',required=True,type=Path);a=p.parse_args()
 if a.live and a.saved_response:p.error('Choose saved response or live inference')
 v=json.loads(a.view.read_text());c=json.loads(a.contract.read_text());forbidden={'truth','ground_truth','oracle','fault_plan','injection_plan'}
 if forbidden.intersection(v):raise ValueError('Evaluation metadata is not allowed in detector inputs')
 rules=safe_detect(v);out={'rules':rules,'hybrid':rules['verdict'],'basis':'rules'}
 if rules['verdict']=='Uncertain':
  data=pack(public_packet(v,c));ans=None
  if len(json.dumps(data))>API_MAX_CHARS:out['basis']='input_budget_exceeded'
  elif a.saved_response:
   ans=json.loads(a.saved_response.read_text())
   if isinstance(ans.get('attempts'),list):ans=ans['attempts'][-1] if ans['attempts'] else {}
   if 'response' in ans:ans['screen_errors']=screen(data,ans['response'])
  elif a.live:
   ans=request(data,(R/'config/detector-prompt.txt').read_text())
  if ans is not None:out.update(hybrid=accepted_verdict(ans),basis='saved_response' if a.saved_response else 'live_model',assessment=ans)
  elif out['basis']=='rules':out['basis']='fallback_not_requested'
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n');print(out['hybrid'])
if __name__=='__main__':main()
