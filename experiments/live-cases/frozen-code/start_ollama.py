"""Start an experiment-only Ollama server; no global environment changes."""
import os,subprocess,json,time,urllib.request
from pathlib import Path
root=Path(__file__).resolve().parents[1]
env=os.environ|{'OLLAMA_HOST':'127.0.0.1:11436','OLLAMA_FLASH_ATTENTION':'1','OLLAMA_KV_CACHE_TYPE':'q8_0','OLLAMA_NUM_PARALLEL':'1','OLLAMA_MAX_LOADED_MODELS':'1'}
with (root/'protocol/ollama-server.log').open('ab') as log:
 p=subprocess.Popen([str(Path(os.environ['LOCALAPPDATA'])/'Programs/Ollama/ollama.exe'),'serve'],env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=log,creationflags=subprocess.CREATE_NO_WINDOW)
(root/'protocol/ollama-process.json').write_text(json.dumps({'pid':p.pid,'port':11436,'overrides':{k:env[k] for k in ('OLLAMA_HOST','OLLAMA_FLASH_ATTENTION','OLLAMA_KV_CACHE_TYPE','OLLAMA_NUM_PARALLEL','OLLAMA_MAX_LOADED_MODELS')}},indent=2))
op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
for _ in range(20):
 try:print(op.open('http://127.0.0.1:11436/api/version',timeout=2).read().decode());break
 except Exception:time.sleep(.5)
else:raise RuntimeError('Ollama startup failed')
