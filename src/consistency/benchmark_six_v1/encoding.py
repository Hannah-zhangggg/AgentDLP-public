"""Lossless sharing of repeated strings; verify exact round-trip before API use."""
import json
import hashlib
from collections import Counter
from copy import deepcopy
from .experiment import OUT, ROOT, read, write, file_hash, PROFILES, opaque
from .experiment import effective_project, public_packet, public_contract, safe_detect

API_MAX_CHARS=900000


def pack(packet):
    payloads={}
    def encode(value):
        if isinstance(value,str) and len(value)>1024:
            key='sha256:'+hashlib.sha256(value.encode()).hexdigest()
            if key in payloads and payloads[key]!=value:raise ValueError('payload_hash_collision')
            payloads[key]=value
            return {'__payload_ref__':key}
        if isinstance(value,dict):
            if set(value)=={'__payload_ref__'}:raise ValueError('reserved_encoding_key')
            return {k:encode(v) for k,v in value.items()}
        if isinstance(value,list):return [encode(v) for v in value]
        return value
    out=deepcopy(packet)
    for item in out['evidence']:
        item['value']=encode(item['value'])
    if not payloads:return out
    out['shared_payloads']=payloads
    out['payload_encoding']='Lossless string sharing: a value {"__payload_ref__": key} denotes the exact full string in shared_payloads[key]. Resolve it when comparing. The same value reference does not merge distinct action occurrences. No content is omitted by this encoding.'
    if unpack(out)!=packet:raise ValueError('non_lossless_encoding')
    return out


def unpack(packet):
    out=deepcopy(packet);payloads=out.pop('shared_payloads',{})
    out.pop('payload_encoding',None)
    def decode(value):
        if isinstance(value,dict):
            if set(value)=={'__payload_ref__'}:return payloads[value['__payload_ref__']]
            return {k:decode(v) for k,v in value.items()}
        if isinstance(value,list):return [decode(v) for v in value]
        return value
    for item in out['evidence']:item['value']=decode(item['value'])
    return out


def main():
    if (OUT/'api-input-freeze.json').exists():raise ValueError('API_inputs_already_frozen')
    rows=read(OUT/'private/selection.json');saved=[]
    full={r['case_id']:r for r in rows if r['condition']=='full'}
    noops=[]
    for r in rows:
        if r['condition']=='degraded' and read(OUT/r['input'])==read(OUT/full[r['case_id']]['input']):
            noops.append(r)
    counts=Counter((r['group'],r['profile']) for r in rows
                   if r['condition']=='degraded' and r not in noops)
    corrections=[]
    for r in sorted(noops,key=lambda r:opaque('public-reallocation/'+r['case_id'])):
        original=read(OUT/full[r['case_id']]['input'])
        view=read(OUT/'private/views'/(full[r['case_id']]['id']+'.json'))
        run=ROOT/r['source_run']
        contract=public_contract(run,read(run/'retrieval.json')['files'])
        chosen=None
        for profile in sorted(PROFILES,key=lambda p:(counts[r['group'],p],opaque(r['case_id']+'/'+p))):
            projected,removed=effective_project(view,profile)
            if not removed:continue
            packet=public_packet(projected,contract)
            if packet==original:continue
            chosen=(profile,projected,removed,packet)
            break
        if chosen is None:raise ValueError('no_effective_public_projection:'+r['id'])
        profile,projected,removed,packet=chosen
        prediction=safe_detect(projected)
        base='projection-corrections/'+r['id']
        write(OUT/(base+'.input.json'),packet)
        write(OUT/(base+'.rules.json'),prediction)
        write(OUT/'private'/(base+'.view.json'),projected)
        corrections.append({'id':r['id'],'previous_profile':r['profile'],'profile':profile,
            'previous_input':r['input'],'corrected_input':base+'.input.json',
            'corrected_rules':base+'.rules.json','reason':'Removed raw facts were absent from the public packet; reallocate on effective public evidence before any API call, without consulting truth or predictions.'})
        r.update(profile=profile,removed=removed,input=base+'.input.json',
                 rule_verdict=prediction['verdict'],rule_error=prediction.get('evaluation_error'),
                 rule_record=base+'.rules.json',packet_chars=len(json.dumps(packet)))
        counts[r['group'],profile]+=1
    write(OUT/'public-projection-corrections.json',corrections)
    for r in rows:
        original=read(OUT/r['input']);encoded=pack(original)
        path=OUT/'api-inputs'/(r['id']+'.json');write(path,encoded)
        r['original_input']=r['input'];r['input']='api-inputs/'+r['id']+'.json'
        r['original_packet_chars']=r['packet_chars'];r['packet_chars']=len(json.dumps(encoded))
        r['input_status']='ready' if r['packet_chars']<=API_MAX_CHARS else 'oversize'
        saved.append(r)
    write(OUT/'private/api-selection.json',saved)
    write(OUT/'api-input-freeze.json',{str(p.relative_to(OUT)):file_hash(p) for p in
          list((OUT/'api-inputs').glob('*.json'))+list((OUT/'projection-corrections').glob('*.json'))+
          list((OUT/'private/projection-corrections').glob('*.json'))+
          [OUT/'private/api-selection.json',OUT/'public-projection-corrections.json']})
    write(OUT/'encoding-audit.json',{'round_trip_equal':len(rows),
          'effective_public_pairs':len(full),
          'public_projection_reallocations':len(corrections),
          'api_char_budget':API_MAX_CHARS,
          'context_basis':'DeepSeek official model docs advertise 1M-token context; conservative 900k ASCII-serialized characters leave space for prompt/output. https://api-docs.deepseek.com/quick_start/pricing',
          'original_oversize':sum(r['original_packet_chars']>240000 for r in saved),
          'remaining_oversize':sum(r['input_status']!='ready' for r in saved),
          'original_chars':sum(r['original_packet_chars'] for r in saved),
          'encoded_chars':sum(r['packet_chars'] for r in saved),
          'scope':'Lossless repeated-string sharing only, prior to API calls. No rule output or private truth affects encoding.'})
    print(json.dumps(read(OUT/'encoding-audit.json'),indent=2))


if __name__=='__main__':main()
