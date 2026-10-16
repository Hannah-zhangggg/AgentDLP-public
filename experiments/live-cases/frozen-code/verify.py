"""Independent acceptance checks: setup, freezes, aggregation, API provenance."""
import sys,json,hashlib
from pathlib import Path
from collections import Counter
ROOT=Path(__file__).resolve().parents[1];REPO=ROOT.parents[1]
sys.path.insert(0,str(ROOT/'scripts'));sys.path.insert(0,str(REPO))
from adapter import read,lines
from consistency.benchmark_six_v1.experiment import accepted_verdict
from consistency.llm_review_v1.packet import screen

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
 checks={};source=read(ROOT/'protocol/source-freeze.json')
 checks['frozen_source_unchanged']=all(digest(REPO/p)==h for p,h in source['files'].items())
 frozen=read(ROOT/'detector/formal/input-freeze.json');checks['input_hashes']=all(digest(ROOT/'detector/formal'/p)==h for p,h in frozen.items())
 jobs=[r for r in read(ROOT/'private/run-plan.json') if r['phase']=='formal'];oracle=read(ROOT/'private/oracle-formal.json');decisions=read(ROOT/'detector/formal/decisions.json')
 checks['50_attempts_10_conditions']=len(oracle)==len(jobs)==50 and set(Counter((x['case'],x['condition']) for x in oracle).values())=={5}
 checks['350_seven_profile_views']=len(decisions)==350 and set(Counter(x['run'] for x in decisions).values())=={7}
 checks['all_raw_audits_pass']=all(x['audit']['valid'] for x in oracle)
 setup=[];sessions=[];initial=[];generation_requests=0
 for j in jobs:
  run=ROOT/'formal'/j['case']/j['condition']/('rep%02d'%j['repetition']);initial.append(digest(run/'external/initial-state.json'))
  settings={'prompt':digest(run/'prompt.txt')==digest(ROOT/'protocol/prompts'/(j['case']+'.txt')),'model':read(run/'model.json')['digest']=='500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41','host_job':read(run/'start.json')['job']==j,'runtime':digest(run/'runtime.py')==digest(ROOT/'scripts/runtime.py')}
  requests=lines(run/'external/backend-requests.jsonl');generation_requests+=len(requests)
  settings['qwen_options']=bool(requests) and all(x['model']=='qwen3:8b' and x['think'] is False and x['options']=={'num_ctx':16384,'num_predict':4096,'temperature':0.7,'top_p':0.95,'top_k':20,'seed':j['model_seed']} for x in requests)
  ses={h['sessionID'] for h in lines(run/'endpoint/hook-before.jsonl')};sessions.extend(ses)
  settings['one_session']=len(ses)==1;settings['remote_source_check']=read(run/'remote-source-verification.json')=={'external':27,'endpoint':5};setup.append(settings)
 checks['setup_all_50']=all(all(x.values()) for x in setup);checks['fresh_session_ids']=len(sessions)==len(set(sessions))==50;checks['database_reset_identical']=len(set(initial))==1
 checks['hybrid_policy']=True;checks['API_packet_provenance']=True;checks['output_validation_reproduced']=True;checks['no_unfinished_api_requests']=True;checks['no_pending_views']=True
 fallback=0
 for r in decisions:
  if r['hybrid'] is None:checks['no_pending_views']=False
  rules=read(ROOT/'detector/formal/rules'/(r['id']+'.json'))
  if rules['verdict']!=r['rule']:checks['hybrid_policy']=False
  expected=r['rule']
  if r['rule']=='Uncertain' and r['applicable']:
   fallback+=1;answer=read(ROOT/'detector/formal/responses'/(r['id']+'.json'));expected=accepted_verdict(answer)
   packet=read(ROOT/'detector/formal'/r['input'])
   if answer['packet_sha256']!=digest(ROOT/'detector/formal'/r['input']) or answer['prompt_sha256']!=digest(ROOT/'protocol/detector-prompt.txt'):checks['API_packet_provenance']=False
   if answer.get('status') in ('ok','invalid_response') and screen(packet,answer.get('response'))!=answer.get('screen_errors'):checks['output_validation_reproduced']=False
   for name in answer['attempt_files']:
    ap=ROOT/'detector/formal'/name;marker=ap.with_suffix('.started.json');start=read(marker)
    if not ap.exists() or start['packet_sha256']!=r['packet_sha256']:checks['no_unfinished_api_requests']=False
  if expected!=r['hybrid']:checks['hybrid_policy']=False
 public=read(ROOT/'public/decisions.json');checks['public_rows_match']=len(public)==len(decisions) and all(next(p for p in public if p['id']==r['id'])['hybrid']==r['hybrid'] for r in decisions)
 result={'passed':all(checks.values()),'checks':checks,'formal_attempts':50,'views':len(decisions),'fallbacks':fallback,'qwen_actual_requests':generation_requests,'source_files':len(source['files']),'frozen_input_files':len(frozen),'per_run_setup':setup}
 (ROOT/'public/validation.json').write_text(json.dumps(result,indent=2))
 print(json.dumps({k:v for k,v in result.items() if k!='per_run_setup'},indent=2))
 if not result['passed']:raise SystemExit(1)
if __name__=='__main__':main()
