"""Recompute published counts with Python standard library; no API or raw archive."""
import json,csv
from pathlib import Path
from collections import Counter
p=Path(__file__).resolve().parent
rows=json.loads((p/'decisions.json').read_text(encoding='utf-8'))
assert len(rows)==350 and len({r['id'] for r in rows})==350
assert len({r['run'] for r in rows})==50
assert set(Counter(r['run'] for r in rows).values())=={7}
expected=json.loads((p/'summary.json').read_text(encoding='utf-8'))
for saved in expected['profiles']:
 allrows=[r for r in rows if r['profile']==saved['profile']]
 eligible=[r for r in allrows if r['oracle_valid'] and r['truth'] in ('Consistent','Inconsistent') and r['applicable']]
 measured={'n':len(allrows),'scorable':len(eligible),'correct':sum(r['truth']==r['hybrid'] for r in eligible),'false_C':sum(r['truth']=='Inconsistent' and r['hybrid']=='Consistent' for r in eligible),'false_I':sum(r['truth']=='Consistent' and r['hybrid']=='Inconsistent' for r in eligible),'U':sum(r['hybrid']=='Uncertain' for r in eligible),'accepted_model_U':sum(r['hybrid']=='Uncertain' and r['api_status']=='ok' for r in eligible),'invalid_output_U':sum(r['hybrid']=='Uncertain' and r['api_status'] in ('rejected_output','invalid_response') for r in eligible),'fallbacks':sum(r['rule']=='Uncertain' for r in eligible),'C_I_U':'/'.join(str(sum(r['hybrid']==v for r in eligible)) for v in ('Consistent','Inconsistent','Uncertain')),'pending':sum(r['hybrid'] is None and r['applicable'] for r in allrows)}
 for key,value in measured.items():assert saved[key]==value,(saved['profile'],key,value,saved[key])
for saved in expected['conditions_summary']:
 group=[r for r in rows if r['case']==saved['case'] and r['condition']==saved['condition'] and r['profile']=='full']
 assert len(group)==5
 assert sum(r['applied'] for r in group)==saved['applied']
 assert sum(r['task_database_match'] for r in group)==saved['task_database_match']
 assert sum(r['truth']==r['hybrid'] for r in group)==saved['Full_correct']
print(json.dumps({'passed':True,'runs':50,'views':350,'profiles':7,'conditions':10}))
