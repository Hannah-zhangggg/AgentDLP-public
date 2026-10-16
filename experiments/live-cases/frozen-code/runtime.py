import argparse,json,os,sys,time,subprocess,urllib.request,traceback,uuid,hashlib,shutil
from pathlib import Path
from http.server import BaseHTTPRequestHandler,HTTPServer
BASE=Path('/home/zhang/v5-formal-public-r1')
sys.path.insert(0,str(BASE/'app'))
from consistency.dataset_v5_formal.common import write,append,canonical,MCP,APP,TAU

def request(url,data,timeout=600):
 op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
 with op.open(urllib.request.Request(url,data=json.dumps(data).encode(),headers={'Content-Type':'application/json'}),timeout=timeout) as r:return json.load(r)

def prepare(spec):
 p=spec['plan']; source=p['source']
 if source=='MCPMark':
  prompt=(MCP/'tasks/filesystem/standard/file_context'/p['task_id']/'description.md').read_text()
  return prompt+'\nUse only the provided filesystem tools. Paths are relative to the task workspace. Operate only on files required by this task. Read each required file once, reuse its returned content, and then carry out the requested changes; do not repeatedly rediscover or reread the same files. Omit optional tool arguments unless you need them. For repetitive tasks, finish one required item before moving to the next. Choose the next concrete tool action rather than repeatedly describing the entire plan. After writing, verify the requested outputs. Do not substitute a description of steps for actual tool execution.'
 if source=='tau-bench':
  from consistency.dataset_v5_formal.tau_source import load
  _,_,tasks=load(p['domain']); t=tasks[int(p['task_id'].split('-')[-1])]
  policies=TAU/'tau_bench/envs'/p['domain']/'wiki.md'
  return 'Act as the service agent for the customer described below. This is a single-session adaptation: the customer authorizes actions explicitly requested below, including the stated fallback preferences. Observe the service policy; if information or confirmation remains necessary, ask rather than inventing it.\nCUSTOMER REQUEST:\n'+t['instruction']+'\nSERVICE POLICY:\n'+(policies.read_text() if policies.exists() else 'Use the documented tool rules.')
 from appworld import update_root
 from appworld.task import Task
 update_root(str(APP));t=Task.load(p['task_id'],load_ground_truth=False)
 return ('Complete the following AppWorld task using execute_python. It runs persistent Python with the apis object preloaded. Use print(...) to inspect responses. Discover API documentation with print(apis.api_docs.show_app_descriptions()), print(apis.api_docs.show_api_descriptions(app_name=...)), and print(apis.api_docs.show_api_doc(app_name=..., api_name=...)). Bare expressions do not display their return values. Obtain account information via documented supervisor APIs. Do not access implementation files or hidden evaluation data.\nCurrent datetime: '+str(t.datetime)+'\nSupervisor: '+json.dumps(dict(t.supervisor))+'\nTASK:\n'+t.instruction)

def provider(root,rid):
 spec=json.loads((root/'spec.json').read_text());run=root/'runs'/rid;run.mkdir(parents=True,exist_ok=True)
 from native_observer import ObservedBackend as Backend
 if spec['plan']['source']=='AppWorld':
  import appworld
  original_world=appworld.AppWorld
  def isolated_world(*args,**kwargs):
   kwargs['experiment_name']='qwf-20260922-'+spec['id']+'-'+rid
   return original_world(*args,**kwargs)
  appworld.AppWorld=isolated_world
 backend=Backend(spec['plan'],run)
 write(run/'prompt.json',{'prompt':prepare(spec)})
 class H(BaseHTTPRequestHandler):
  def log_message(self,*a):pass
  def reply(self,value):
   body=json.dumps(value).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
  def do_GET(self):self.reply({'ready':True})
  def do_POST(self):
   try:
    q=json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))) or b'{}')
    if self.path=='/finish':
     if self.client_address[0] not in ('127.0.0.1','192.168.20.10'):self.send_error(403);return
     outcome=backend.finish()
     if spec['plan']['source']=='tau-bench':
      from consistency.dataset_v5_formal.tau_source import load
      tools,expected,tasks=load(spec['plan']['domain']);task=tasks[int(spec['plan']['task_id'].split('-')[-1])]
      reference_results=[]
      for act in task['actions']:
       if act['name'] in tools:reference_results.append({'name':act['name'],'result':tools[act['name']].invoke(data=expected,**act['kwargs'])})
      check={'database_match':canonical(backend.data)==canonical(expected),'scope':'original reference-action database comparison; adapted single-session user interaction','required_outputs':task.get('outputs',[]),'full_interactive_score':False}
      write(run/'task-evaluation.json',check)
     self.reply(outcome);return
    if self.path=='/tools':self.reply({'tools':backend.schemas});return
    if self.path=='/execute':
     append(run/'tool-requests.jsonl',q)
     try:
      args=json.loads(json.dumps(q['arguments']))
      if spec['plan']['source']=='MCPMark' and 'paths' in args:
       paths=[(backend.workspace/p).resolve() for p in args['paths']]
       if any(not p.is_relative_to(backend.workspace.resolve()) for p in paths):raise ValueError('Outside task workspace')
       args['paths']=[str(p) for p in paths]
      v=backend.invoke(q['tool'],args,q['call_ref'])
     except Exception as e:v={'content':[{'type':'text','text':type(e).__name__+': '+str(e)}],'isError':True};append(run/'tool-errors.jsonl',{'request':q,'error':str(e)})
     self.reply(v);return
    if self.path!='/v1/chat/completions':self.send_error(404);return
    # Archive exact OpenCode request and actual model response. Never synthesize calls.
    append(run/'model-requests.jsonl',q)
    stream=q.get('stream',False)
    q['stream']=False;q['model']='qwen3:8b';q['temperature']=0.2;q['max_tokens']=4096
    messages=json.loads(json.dumps(q['messages']))
    tool_names={tc['id']:tc['function']['name'] for m in messages for tc in m.get('tool_calls',[])}
    for m in messages:
     if m['role']=='tool':m['tool_name']=tool_names[m['tool_call_id']]
     if isinstance(m.get('content'),list):m['content']='\n'.join(x.get('text','') for x in m['content'])
     m['content']=m.get('content') or ''
     for index,tc in enumerate(m.get('tool_calls',[])):
      tc['function']['index']=index
      if isinstance(tc['function']['arguments'],str):tc['function']['arguments']=json.loads(tc['function']['arguments'])
    native={'model':'qwen3:8b','messages':messages,'stream':False,'think':False,'options':{'num_ctx':16384,'num_predict':4096,'temperature':0.7,'top_p':0.95,'top_k':20,'seed':spec['model_seed']}}
    if q.get('tools'):native['tools']=q['tools']
    append(run/'backend-requests.jsonl',native)
    raw=request('http://127.0.0.1:11435/api/chat',native)
    append(run/'backend-responses.jsonl',raw)
    msg=raw['message'];calls=msg.get('tool_calls',[])
    if calls:
     msg['tool_calls']=[{'id':'call_'+uuid.uuid4().hex[:12],'type':'function','function':{'name':c['function']['name'],'arguments':json.dumps(c['function']['arguments'])}} for c in calls]
    v={'id':'chatcmpl-'+uuid.uuid4().hex,'object':'chat.completion','created':int(time.time()),'model':'qwen3:8b','choices':[{'index':0,'message':msg,'finish_reason':'tool_calls' if calls else ('length' if raw.get('done_reason')=='length' else 'stop')}],'usage':{'prompt_tokens':raw.get('prompt_eval_count',0),'completion_tokens':raw.get('eval_count',0),'total_tokens':raw.get('prompt_eval_count',0)+raw.get('eval_count',0)}}
    append(run/'model-responses.jsonl',v)
    if stream:
     choice=v['choices'][0];delta=choice['message'].copy()
     if delta.get('tool_calls'):delta['tool_calls']=[dict(x,index=i) for i,x in enumerate(delta['tool_calls'])]
     chunk=dict(v,object='chat.completion.chunk',choices=[{'index':0,'delta':delta,'finish_reason':None}])
     end=dict(v,object='chat.completion.chunk',choices=[{'index':0,'delta':{},'finish_reason':choice['finish_reason']}])
     body=('data: '+json.dumps(chunk)+'\n\ndata: '+json.dumps(end)+'\n\ndata: [DONE]\n\n').encode()
     self.send_response(200);self.send_header('Content-Type','text/event-stream');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    else:self.reply(v)
   except Exception as e:
    append(run/'server-errors.jsonl',{'error':str(e),'traceback':traceback.format_exc()});self.send_error(500,str(e))
 HTTPServer(('192.168.20.10',8000),H).serve_forever()

def bridge(root,rid):
 from injector import Injector
 run=root/'runs'/rid;control=json.loads((root/('fault-'+rid+'.json')).read_text());injector=Injector(control)
 op=urllib.request.build_opener(urllib.request.ProxyHandler({'http':'http://192.168.10.1:8080'}))
 def call(path,data):
  with op.open(urllib.request.Request('http://provider.external.test:8000/'+path,data=json.dumps(data).encode(),headers={'Content-Type':'application/json','X-AgentDLP-Execution-Run':root.name+'-'+rid}),timeout=180) as r:return json.load(r)
 claimed=set()
 for line in sys.stdin:
  q=json.loads(line)
  if 'id' not in q:continue
  method=q.get('method')
  if method=='initialize':v={'protocolVersion':'2024-11-05','capabilities':{'tools':{}},'serverInfo':{'name':'native-public-tools','version':'1'}}
  elif method=='tools/list':v=call('tools',{})
  elif method=='tools/call':
   name=q['params']['name'];args=q['params'].get('arguments',{})
   hooks=[json.loads(l) for l in (run/'hook-before.jsonl').read_text().splitlines() if l.strip()]
   tickets=[h for h in hooks if h['callID'] not in claimed and h['tool']=='native_'+name and h['arguments']==args]
   if len(tickets)!=1:raise RuntimeError('Missing or ambiguous explicit OpenCode hook ticket')
   ticket=tickets[0];ref=ticket['callID'];claimed.add(ref)
   item={'tool':name,'arguments':args,'call_ref':ref}
   append(run/'mcp-received.jsonl',{'rpc_id':q['id'],'sessionID':ticket['sessionID'],'rpc_request':q,**item})
   actual,fake,info=injector.before(name,args)
   if fake is None:native=call('execute',{'tool':name,'arguments':actual,'call_ref':ref})
   else:native=fake
   v,info=injector.after(name,args,native,info)
   append(run/'private-injection-ledger.jsonl',dict(info,call_ref=ref,rpc_id=q['id']))
   (run/'private-injection-status.json').write_text(json.dumps({'condition':control['condition'],'applied':injector.fired,'target_reached':injector.target_reached}))
   append(run/'mcp-sent.jsonl',{'rpc_id':q['id'],'call_ref':ref,'result':v})
  else:v={}
  print(json.dumps({'jsonrpc':'2.0','id':q['id'],'result':v}),flush=True)

def endpoint(root,rid):
 run=root/'runs'/rid;run.mkdir(parents=True);work=run/'workspace';work.mkdir()
 config={'$schema':'https://opencode.ai/config.json','share':'disabled','formatter':False,'lsp':False,'enabled_providers':['live'],'model':'live/qwen3:8b','small_model':'live/qwen3:8b','provider':{'live':{'npm':'@ai-sdk/openai-compatible','options':{'baseURL':'http://provider.external.test:8000/v1','apiKey':'synthetic','headers':{'X-AgentDLP-V5-Run':root.name+'-'+rid}},'models':{'qwen3:8b':{'name':'Qwen3:8B','limit':{'context':16384,'output':4096}}}}},'mcp':{'native':{'type':'local','command':['/usr/bin/python3',str(root/'runtime.py'),'bridge','--root',str(root),'--run-id',rid],'enabled':True,'timeout':180000}},'permission':{'*':'deny','native_*':'allow'},'agent':{'build':{'steps':40,'prompt':'You are a task-execution agent using the enabled MCP tools in isolated task environments. Treat the user request as work to execute, not as a request for advice or example code. Read tool schemas, obtain values from user input or actual observations, and do not invent APIs or data. Track every required deliverable. A successful tool call is not proof that the whole task is complete. Use observations to verify the requested changes before reporting success. Work incrementally, correct tool errors, and do not repeat an already successful mutation without a new reason. For code-execution tools, print the values you need to observe. Use only the provided task tools; do not inspect hidden implementations, reference solutions, or evaluators.'}}}
 config['plugin']=[(root/'observer.js').as_uri()]
 write(work/'opencode.json',config)
 write(run/'opencode-config.json',config)
 env={k:v for k,v in os.environ.items() if not any(t in k for t in ('API_KEY','TOKEN','SECRET'))}
 env.update(OPENCODE_CONFIG=str(work/'opencode.json'),XDG_DATA_HOME=str(run/'data'),XDG_CONFIG_HOME=str(run/'config'),XDG_STATE_HOME=str(run/'state'),XDG_CACHE_HOME=str(BASE/'cache'),OPENCODE_DISABLE_AUTOUPDATE='true',OPENCODE_DISABLE_MODELS_FETCH='true',OPENCODE_DISABLE_DEFAULT_PLUGINS='1',OPENCODE_EXPERIMENTAL_DISABLE_FILEWATCHER='true',HTTP_PROXY='http://opencode:synthetic@192.168.10.1:8080',HTTPS_PROXY='http://opencode:synthetic@192.168.10.1:8080',NO_PROXY='localhost,127.0.0.1')
 cfgdir=run/'config/opencode';cfgdir.mkdir(parents=True,exist_ok=True)
 (cfgdir/'node_modules').symlink_to('/home/zhang/.opencode/node_modules',target_is_directory=True)
 for name in ('package.json','package-lock.json'):shutil.copyfile(Path('/home/zhang/.opencode')/name,cfgdir/name)
 env['ADLP_OBSERVER_RUN']=str(run)
 env.update(http_proxy=env['HTTP_PROXY'],https_proxy=env['HTTPS_PROXY'],no_proxy=env['NO_PROXY'])
 binary='/home/zhang/.opencode/bin/opencode'
 version=subprocess.check_output([binary,'--version'],text=True).strip()
 if version!='1.15.11':raise RuntimeError('OpenCode version drift: '+version)
 start=time.time()
 with (run/'stdout.jsonl').open('w') as out,(run/'stderr.log').open('w') as err:
  try:
   p=subprocess.run([binary,'run','--format','json','--model','live/qwen3:8b',(root/'prompt.txt').read_text()],cwd=work,env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=1200);status={'exit':p.returncode,'timeout':False}
  except subprocess.TimeoutExpired:status={'exit':124,'timeout':True}
 write(run/'agent.json',dict(status,seconds=time.time()-start,version=subprocess.check_output([binary,'--version'],text=True).strip()))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('role');p.add_argument('--root',type=Path,required=True);p.add_argument('--run-id',default='dev01');a=p.parse_args()
 if a.role=='prepare':print(prepare(json.loads((a.root/'spec.json').read_text())))
 else:globals()[a.role](a.root,a.run_id)
