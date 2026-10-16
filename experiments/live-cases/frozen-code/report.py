"""Mechanical reporting from immutable decisions and separately generated oracle."""
import sys,json,csv,statistics,hashlib
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from adapter import read,lines
LABEL={'full':'Full','E1_contract':'E1 Contract','E1_field':'E1 Field','E2_binding':'E2 Association','E3_effect':'E3 State','E3_delivery':'E3 Delivery','E4_closure':'E4 Closure'}
CN={'normal':'正常控制','address_value':'Suite 641→642','stale_address_return':'返回旧地址快照','partial_exchange':'仅执行一对换货','wrong_exchange_variant':'替换错误恒温器款式','equivalent_pair_reorder':'合法配对重排','stale_error_return':'成功后返回旧错误','skip_second_return':'跳过第二单并伪报成功'}
def dump(p,v):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(v,indent=2,ensure_ascii=False),encoding='utf-8')
def csvout(p,rows):
 with p.open('w',encoding='utf-8-sig',newline='') as f:
  w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
def counts(rows,field='hybrid'):return '/'.join(str(sum(x[field]==v for x in rows)) for v in ('Consistent','Inconsistent','Uncertain'))
def metric(rows):
 valid=[r for r in rows if r['oracle_valid'] and r['truth'] in ('Consistent','Inconsistent') and r['applicable']]
 return {'n':len(rows),'scorable':len(valid),'correct':sum(r['hybrid']==r['truth'] for r in valid),'false_C':sum(r['truth']=='Inconsistent' and r['hybrid']=='Consistent' for r in valid),'false_I':sum(r['truth']=='Consistent' and r['hybrid']=='Inconsistent' for r in valid),'U':sum(r['hybrid']=='Uncertain' for r in valid),'accepted_model_U':sum(r['hybrid']=='Uncertain' and r['api_status']=='ok' for r in valid),'invalid_output_U':sum(r['hybrid']=='Uncertain' and r['api_status'] in ('rejected_output','invalid_response') for r in valid),'C_I_U':counts(valid),'fallbacks':sum(r['rule']=='Uncertain' for r in valid),'pending':sum(r['hybrid'] is None and r['applicable'] for r in rows)}
def main():
 out=ROOT/'public';out.mkdir(exist_ok=True);oracle=read(ROOT/'private/oracle-formal.json');decisions=read(ROOT/'detector/formal/decisions.json');byrun={r['run']:r for r in oracle};rows=[]
 for d in decisions:
  o=byrun[d['run']];a=o['audit'];rows.append({k:d[k] for k in ('id','run','profile','rule','hybrid','api_status','applicable','packet_sha256')}|{'case':o['case'],'condition':o['condition'],'repetition':o['repetition'],'truth':a['truth'],'oracle_valid':a['valid'],'applied':a['injection']['applied'],'target_reached':a['injection']['target_reached'],'task_database_match':a['task_database_match'],'provider_calls':a['provider_calls'],'native_calls':a['native_calls']})
 assert len(oracle)==50 and len(rows)==350 and not any(x['api_status']=='pending' for x in rows)
 csvout(out/'decisions.csv',rows);dump(out/'decisions.json',rows)
 conditions=[]
 for case in read(ROOT/'protocol/cases.json'):
  for cond in case['conditions']:
   rs=[r for r in rows if r['case']==case['id'] and r['condition']==cond and r['profile']=='full'];orows=[x for x in oracle if x['case']==case['id'] and x['condition']==cond]
   conditions.append({'case':case['id'],'condition':cond,'runs':len(rs),'applied':sum(r['applied'] for r in rs),'target_reached':sum(r['target_reached']>0 for r in rs),'task_database_match':sum(r['task_database_match'] for r in rs),'truth_C_I_U':counts(rs,'truth'),'Full_C_I_U':counts(rs),'Full_correct':sum(r['hybrid']==r['truth'] for r in rs),'provider_calls_min':min(r['provider_calls'] for r in rs),'provider_calls_max':max(r['provider_calls'] for r in rs),'agent_seconds_median':statistics.median(x['audit']['agent']['seconds'] for x in orows)})
 csvout(out/'condition-summary.csv',conditions);dump(out/'condition-summary.json',conditions)
 profile_rows=[]
 for profile in LABEL:
  rs=[r for r in rows if r['profile']==profile];profile_rows.append({'profile':profile,**metric(rs)})
 csvout(out/'evidence-summary.csv',profile_rows)
 detailed=[]
 for cond in conditions:
  for profile in LABEL:
   rs=[r for r in rows if r['case']==cond['case'] and r['condition']==cond['condition'] and r['profile']==profile]
   detailed.append({'case':cond['case'],'condition':cond['condition'],'profile':profile,**metric(rs)})
 csvout(out/'condition-evidence-summary.csv',detailed)
 # Observable trajectories joined only for post-hoc explanation, never for model input.
 for o in oracle:
  p=ROOT/o['run'];before=lines(p/'endpoint/mcp-received.jsonl');native=lines(p/'external/native-events.jsonl');sent=lines(p/'endpoint/mcp-sent.jsonl');ledger=lines(p/'endpoint/private-injection-ledger.jsonl')
  trajectory=[]
  for i,c in enumerate(before):
   ref=c['call_ref'];trajectory.append({'step':i+1,'call_ref':ref,'issued':{k:c[k] for k in ('tool','arguments')},'native':[{k:e[k] for k in ('tool','arguments','result','before_hash','after_hash')} for e in native if e['call_ref']==ref],'received':[e['result'] for e in sent if e['call_ref']==ref],'intervention':[e for e in ledger if e['call_ref']==ref]})
  dump(ROOT/'private/trajectories'/o['case']/o['condition']/('rep%02d.json'%o['repetition']),trajectory)
 attempts=[read(p) for p in (ROOT/'detector/formal/attempts').glob('*.json') if '.started.' not in p.name];usage=Counter()
 for a in attempts:
  for k,v in (a.get('usage') or {}).items():
   if isinstance(v,int):usage[k]+=v
 summary={'requested_api_model':'deepseek-v4-flash','formal_runs':50,'conditions':10,'views':350,'all_oracle_audits_valid':all(x['audit']['valid'] for x in oracle),'profiles':profile_rows,'physical_api_requests':len(attempts),'fallback_views':sum(r['rule']=='Uncertain' for r in rows),'api_models':dict(Counter(a.get('model') for a in attempts)),'api_statuses':dict(Counter(a['status'] for a in attempts)),'output_rejections':sum(r['api_status']=='rejected_output' for r in rows),'api_usage':dict(usage),'new_pilot_api_requests':len(list((ROOT/'detector/pilot/attempts').glob('*.1.json'))),'reuse_across_views':False,'conditions_summary':conditions}
 dump(out/'summary.json',summary)
 md=['# Qwen3 三任务真实注入 Case Study 实验结果','',f'共完成 10 个条件、50 次正式真实运行、350 个证据视图。三台 VM 原始证据已导出到本目录；实际判断使用冻结的规则检测器与 DeepSeek V4 Flash（review_U）。正式 API 请求 {len(attempts)} 次，输出校验拒收 {summary["output_rejections"]} 个视图，保留为 U。功能预试验和调试记录单独保存，不混入正式分母。','', '## 10 个条件','', 'C/I/U 分别表示一致、不一致、不确定。触发数对正常控制不适用；任务状态列是原始参考动作最终数据库匹配，与调用执行一致性分开统计。合法重排应为 C。','', '|案例|条件|触发|任务状态匹配|真值 C/I/U|Full C/I/U|Full 正确|', '|---|---|---:|---:|---|---|---:|']
 for x in conditions:md.append(f'|{x["case"]}|{CN[x["condition"]]}|'+('—' if x['condition']=='normal' else str(x['applied'])+'/5')+f'|{x["task_database_match"]}/5|{x["truth_C_I_U"]}|{x["Full_C_I_U"]}|{x["Full_correct"]}/5|')
 md+=['','## 同一真实执行上的证据退化','','每次执行保持不变，分别删除目标证据；E1 同时撤去对应公开元数据与依赖该语义的规则检查。不是让 Qwen 重跑七次。','', '|证据视图|正确/可评分|False C|False I|U|规则 U→真实 LLM|','|---|---:|---:|---:|---:|---:|']
 for x in profile_rows:md.append(f'|{LABEL[x["profile"]]}|{x["correct"]}/{x["scorable"]}|{x["false_C"]}|{x["false_I"]}|{x["U"]}|{x["fallbacks"]}|')
 md+=['','具体每条件、每视图计数见 [condition-evidence-summary.csv](condition-evidence-summary.csv)，逐次判决见 [decisions.csv](decisions.csv)。完整实际交互逐步对照位于 `../private/trajectories/`；原生状态、Gateway通信、OpenCode前后hook和模型请求响应分别位于 `../formal/`。','', '## 主要发现', '', 'Full 检出全部30次实际偏差，15次正常控制均为C；5次合法配对重排均被误报为I，合计45/50。这个局限来自现有规则对配对等价的支持不足，不能用30/30检出率替代对误报的讨论。', '', 'Delivery退化的正确数下降到30/50。其中旧地址返回的5次偏差全部被接受为C，旧错误返回另有2次被接受为C。Closure退化后，漏第二单的5次运行中有4次被接受为C。这些配对结果分别体现接收侧证据和完成窗口对于错误交付、已发调用漏执行的作用。', '', 'E1 Contract为34/50。E1 Field反而达到47/50：它使5次合法重排从规则I转入LLM后被正确接受，同时在正常退货中新增3次误I，净增加2个正确结果。这是语义检查门控、fallback路由和现有规则缺口共同作用，不能解释为字段语义无用或退化通常有益。逐例原因及一个将自然参数错误误认为执行不一致的模型输出，见CASE_NARRATIVES.zh-CN.md。', '', '全部350视图中共有6个U：5个来自输出校验拒收，1个是通过校验的模型U。170次正式API均正常返回，未发生传输重试；实际请求标识为deepseek-v4-flash，响应model字段均为deepseek-flash，原始字段已保留，不自行改写。', '', '## 解释范围','', '- 这是从独立稳定性验证中筛出的三个 τ 零售任务的单会话授权改编。不是原始多轮 τ-bench 成绩，也不证明全部客服政策合规。此前正常轨迹中部分任务缺少身份定位；这里只判断已发工具指令与执行是否一致。','- 换货/退货原生工具只登记申请，不证明实际寄送、邮件送达或退款到账。','- 偏差只在 Endpoint 调用/返回边界注入；Gateway Provider 原始参数与 Qwen 原始生成经过核对，未按计划硬编码工具轨迹。','- 检测在宿主端对每次真实运行结束后导出的证据执行，Full和退化视图使用同一执行。它验证真实工具链上的检测，不是在线阻断或将检测意见回注给Qwen的实验。', '- External 原生工具及进程内状态观察器、Endpoint观察插件和宿主导出属于受信基础。实验不声称抵抗恶意 root、观察器伪造或所有操作系统层攻击。','- 每次运行的后续纠错、循环及未触发均保留。最终状态恢复正确不会抹除先前的错误调用或错配返回；未触发也不能自动标为 I。','- 合法配对重排保持旧/新商品对应关系。现有规则只支持部分参数等价，因此可能误 I；review_U 保留规则 I，LLM不会替它纠正这个误报。保留该结果而不为本轮调整检测器。','- 五个重复用于观察这三个已筛选任务的稳定性，跨条件使用预先声明的相同种子。不能将其当作50个独立任务估计普遍检测准确率；不据此给证据维度作通用重要性排名。','', '## 复现入口','', '`../scripts/campaign.py` 负责宿主SSH调度；`adapter.py`仅读允许的真实证据；`judge.py`复用实际检测器、投影、提示词、API及输出校验；`audit.py`单独产生真值/注入审计；`report.py`只做事后汇总。源码快照与哈希见 `../protocol/frozen-source/` 和 `../protocol/source-freeze.json`，部署源文件见 `../protocol/deployed-sources/`。密钥和SSH密码没有保存到结果中。']
 (out/'RESULTS.zh-CN.md').write_text('\n'.join(md)+'\n',encoding='utf-8')
 print(json.dumps(summary,ensure_ascii=True,indent=2))
if __name__=='__main__':main()
