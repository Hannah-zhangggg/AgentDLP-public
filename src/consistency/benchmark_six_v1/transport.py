"""Frozen model transport for large evidence packets; no oracle access."""
import json
import os
import time
import urllib.error
import urllib.request
from consistency.llm_review_v1.packet import screen

TIMEOUT_SECONDS=180


def request(data,prompt):
    body={'model':'deepseek-v4-flash','temperature':0,'max_tokens':3200,
          'thinking':{'type':'disabled'},'response_format':{'type':'json_object'},
          'messages':[{'role':'system','content':prompt},
                      {'role':'user','content':json.dumps(data,ensure_ascii=False)}]}
    req=urllib.request.Request('https://api.deepseek.com/v1/chat/completions',
        data=json.dumps(body).encode(),
        headers={'Authorization':'Bearer '+os.environ['DEEPSEEK_API_KEY'],
                 'Content-Type':'application/json'})
    start=time.monotonic()
    try:
        with urllib.request.urlopen(req,timeout=TIMEOUT_SECONDS) as response:
            raw=json.load(response)
        choice=raw['choices'][0];content=choice['message']['content']
        try:parsed=json.loads(content)
        except (ValueError,TypeError):parsed=None
        return {'status':'ok' if choice.get('finish_reason')=='stop' and isinstance(parsed,dict) else 'invalid_response',
                'response':parsed,'raw_content':content,'finish_reason':choice.get('finish_reason'),
                'model':raw.get('model'),'usage':raw.get('usage'),
                'request_id':raw.get('id'),'seconds':time.monotonic()-start,
                'screen_errors':screen(data,parsed)}
    except urllib.error.HTTPError as exc:
        return {'status':'http_error','http_status':exc.code,'seconds':time.monotonic()-start}
    except (urllib.error.URLError,TimeoutError,OSError):
        return {'status':'transport_error','seconds':time.monotonic()-start}
    except (ValueError,KeyError,IndexError,TypeError):
        return {'status':'invalid_response','response':None,
                'screen_errors':['invalid_provider_envelope'],'seconds':time.monotonic()-start}
