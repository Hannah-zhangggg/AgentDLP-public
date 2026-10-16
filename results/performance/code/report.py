"""Aggregate only measured results; publish no evidence or API payloads."""
import collections,hashlib,json,pathlib,statistics
import os
O=pathlib.Path(os.environ.get('AGENTDLP_EXPERIMENT_ROOT',str(pathlib.Path(__file__).resolve().parents[1]))).resolve()
def read(p):return json.loads(p.read_text())
def lines(p):return [json.loads(s) for s in p.read_text().splitlines() if s]
def write(p,x):p.write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n')
def pct(values,q):
 v=sorted(values);i=(len(v)-1)*q;k=int(i);return v[k]+(v[min(k+1,len(v)-1)]-v[k])*(i-k)
def stat(rr,field):
 a=[x[field] for x in rr];return {'n':len(a),'mean':statistics.mean(a),'p50':pct(a,.5),'p95':pct(a,.95),'p99':pct(a,.99),'max':max(a)} if a else None

def main():
 private_manifest=O/'private/manifest.json'
 meta={x['sample_id']:x for x in read(private_manifest if private_manifest.exists() else O/'public/input-characteristics.json')}
 a1=lines(O/'public/a1-measurements.jsonl');a2=lines(O/'public/a2-measurements.jsonl');b1=lines(O/'public/b1-measurements.jsonl');batches=read(O/'public/a2-batches.json')
 assert len(a1)==14310 and len(a2)==57240 and len(b1)==2862
 assert all(x['verdict']==meta[x['sample_id']]['expected_rule'] for x in a1+a2)
 assert len({x['sample_id'] for x in b1})==2862
 for rep in range(1,6):assert len({x['sample_id'] for x in a1 if x['pass']==rep})==2862
 for block in range(1,6):
  for workers in [1,2,4,8]:assert len({x['sample_id'] for x in a2 if x['block']==block and x['workers']==workers})==2862
 group=lambda rr,h,c:[x for x in rr if meta[x['sample_id']]['harness']==h and meta[x['sample_id']]['condition']==c]
 local={};hybrid={}
 for h in ['opencode','claude-code','gemini-cli']:
  for c in ['full','degraded']:
   key=h+'/'+c;rr=group(a1,h,c);local[key]={f:stat(rr,f) for f in ['load_ms','rules_ms','service_ms','cpu_ms']};local[key]['unique_views']=len({x['sample_id'] for x in rr})
   rr=group(b1,h,c);fb=[x for x in rr if x['rule_verdict']=='Uncertain'];direct=[x for x in rr if x['rule_verdict']!='Uncertain']
   hybrid[key]={'n':len(rr),'fallback_views':len(fb),'fallback_rate':len(fb)/len(rr),'service_ms':stat(rr,'service_ms'),'direct_ms':stat(direct,'service_ms'),'fallback_ms':stat(fb,'service_ms'),'response_ms':stat(rr,'response_ms'),'queue_ms':stat(rr,'queue_ms'),'packet_ms_on_fallback':stat(fb,'packet_ms'),'api_and_screen_ms_on_fallback':stat(fb,'api_and_screen_ms'),'api_calls':sum(x['api_calls'] for x in rr),'tokens':sum(x['tokens'] for x in rr),'api_statuses':dict(collections.Counter(x['api_status'] for x in rr)),'screen_rejected':sum(x['screen_rejected'] for x in rr),'uncertain':sum(x['verdict']=='Uncertain' for x in rr)}
 size={g:{'unique_views':sum(x['size_bucket']==g for x in meta.values()),'bytes':stat([{'value':x['view_bytes']} for x in meta.values() if x['size_bucket']==g],'value'),'service_ms':stat([x for x in a1 if meta[x['sample_id']]['size_bucket']==g],'service_ms'),'rules_ms':stat([x for x in a1 if meta[x['sample_id']]['size_bucket']==g],'rules_ms')} for g in ['small','medium','large']}
 scale={};base={x['block']:x['throughput'] for x in batches if x['workers']==1}
 for w in [1,2,4,8]:
  bb=[x for x in batches if x['workers']==w];rr=[x for x in a2 if x['workers']==w];ratios=[x['throughput']/base[x['block']] for x in bb]
  scale[str(w)]={'batches':len(bb),'throughput_median':statistics.median(x['throughput'] for x in bb),'throughput_min':min(x['throughput'] for x in bb),'throughput_max':max(x['throughput'] for x in bb),'speedup_paired_median':statistics.median(ratios),'parallel_efficiency':statistics.median(ratios)/w,'service_ms':stat(rr,'service_ms'),'response_ms':stat(rr,'response_ms'),'queue_ms':stat(rr,'queue_ms'),'peak_process_rss_sum_mib':max(x['sampled_process_rss_peak_kib'] for x in bb)/1024}
 summary={'A1':local,'A1_size':size,'A1_case_groups':{g:{'unique_views':sum(x['group']==g for x in meta.values()),'service_ms':stat([x for x in a1 if meta[x['sample_id']]['group']==g],'service_ms'),'rules_ms':stat([x for x in a1 if meta[x['sample_id']]['group']==g],'rules_ms')} for g in sorted({x['group'] for x in meta.values()})},'A2':scale,'B1':hybrid,'baseline_overall':stat(a1,'service_ms'),'A1_batch_throughput':stat(read(O/'public/a1-batches.json'),'throughput'),'hybrid_overall':stat(b1,'service_ms'),'hybrid_api_calls':sum(x['api_calls'] for x in b1),'hybrid_tokens':sum(x['tokens'] for x in b1),'new_hybrid_vs_accuracy_disagreements':sum(x['verdict']!=meta[x['sample_id']]['accuracy_verdict'] for x in b1) if private_manifest.exists() else None,'rule_replay_mismatches':0,'measurement_counts':{'A1':len(a1),'A2':len(a2),'B1':len(b1)}}
 summary['hybrid_usage']={k:sum(x[k] for x in b1) for k in ['tokens','prompt_tokens','completion_tokens','cached_prompt_tokens']}
 summary['hybrid_screen_rejected']=sum(x['screen_rejected'] for x in b1)
 summary['prompt_cache_hit_rate']=summary['hybrid_usage']['cached_prompt_tokens']/summary['hybrid_usage']['prompt_tokens']
 summary['hybrid_statuses']=dict(collections.Counter(x['api_status'] for x in b1))
 summary['hybrid_reported_models']=sorted({m for x in b1 for m in x['reported_models']})
 write(O/'public/summary.json',summary)
 md='# V5 performance results\n\nTwo experiments: local performance/scalability (A1+A2) and real Hybrid latency (B1). All 477 cases, three harnesses, Full/Degraded; 2,862 unique views.\n\n## Table A — Local performance and scalability\n\n### A1. Single-worker normalized-evidence baseline\n\n| Harness / evidence | Unique views | Mean load (ms) | Mean rules (ms) | Mean total (ms) | p50 (ms) | p95 (ms) | p99 (ms) |\n|---|---:|---:|---:|---:|---:|---:|---:|\n'
 for key,v in local.items():md+=f"| {key} | {v['unique_views']} | {v['load_ms']['mean']:.2f} | {v['rules_ms']['mean']:.2f} | {v['service_ms']['mean']:.2f} | {v['service_ms']['p50']:.2f} | {v['service_ms']['p95']:.2f} | {v['service_ms']['p99']:.2f} |\n"
 md+='\n### A1. Actual evidence-size groups\n\n| Size bucket | Unique views | Median snapshot (KiB) | Mean rules (ms) | Mean total (ms) | p95 (ms) |\n|---|---:|---:|---:|---:|---:|\n'
 for key,v in size.items():md+=f"| {key} | {v['unique_views']} | {v['bytes']['p50']/1024:.2f} | {v['rules_ms']['mean']:.2f} | {v['service_ms']['mean']:.2f} | {v['service_ms']['p95']:.2f} |\n"
 md+='\n### A2. Multiprocess throughput and latency\n\n| Workers | Median views/s | Paired speedup | Efficiency | Service p95 (ms) | Response p95 (ms) | Peak RSS sum (MiB) |\n|---:|---:|---:|---:|---:|---:|---:|\n'
 for key,v in scale.items():md+=f"| {key} | {v['throughput_median']:.2f} | {v['speedup_paired_median']:.2f} | {v['parallel_efficiency']:.2%} | {v['service_ms']['p95']:.2f} | {v['response_ms']['p95']:.2f} | {v['peak_process_rss_sum_mib']:.2f} |\n"
 md+='\n## Table B — Real Hybrid latency (DeepSeek V4 Flash, concurrency 4)\n\n| Harness / evidence | Views | Fallback | Rate | Direct mean (ms) | Fallback mean (s) | Fallback p95 (s) | All mean (s) | All p50 (s) | All p95 (s) | Tokens (M) |\n|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n'
 for key,v in hybrid.items():md+=f"| {key} | {v['n']} | {v['fallback_views']} | {v['fallback_rate']:.2%} | {v['direct_ms']['mean']:.2f} | {v['fallback_ms']['mean']/1000:.2f} | {v['fallback_ms']['p95']/1000:.2f} | {v['service_ms']['mean']/1000:.2f} | {v['service_ms']['p50']/1000:.2f} | {v['service_ms']['p95']/1000:.2f} | {v['tokens']/1e6:.2f} |\n"
 md+='\n## Measurement limits\n\n- Core local timing starts from a complete, already normalized, hash-pinned lossless snapshot (pickle protocol 5). It excludes capture and initial protocol normalization. Raw normalization was measured once per execution during parallel preparation and is diagnostic, not a controlled baseline.\n- A1: five repetitions per unique view. A2: five randomized blocks, identical 2,862-view workload, 1/2/4/8 processes, at most 2×workers outstanding requests. Throughput includes orchestration; service excludes queue wait, response is submission-to-worker-completion (excluding subsequent parent receipt). Startup/warmup are excluded. RSS sum includes shared pages counted by multiple processes and is not physical private memory. Each worker receives 100-view warmup. Filesystem caches were not flushed and complete snapshot residency is not guaranteed; results include the cache behavior of repeated operation.\n- B1: one fresh evaluation per view, fixed four threads and at most four in-flight views. Only rule U invokes the model. All outcomes, including U, rejected output and transport failures, remain in the denominators. API timing includes network/client wait and the existing output checks; it is not provider-only compute latency.\n- Newly sampled model decisions are performance-run outcomes and do not overwrite the frozen Accuracy experiment. Token counts are observed; no itemized invoice was supplied, so monetary charges are not invented. This run does not establish API maximum capacity or long-term SLA.\n'
 md+=f"\n## Observed API usage\n\nRequests: {summary['hybrid_api_calls']:,}; total tokens: {summary['hybrid_tokens']:,}; prompt tokens: {summary['hybrid_usage']['prompt_tokens']:,}; completion tokens: {summary['hybrid_usage']['completion_tokens']:,}; cached prompt tokens: {summary['hybrid_usage']['cached_prompt_tokens']:,}. Provider prompt caching is left at its default; the observed input-token cache-hit rate is {summary['prompt_cache_hit_rate']:.2%}. These are not cold-cache API measurements.\n\nResponses rejected by the existing output screen: {summary['hybrid_screen_rejected']}; all remain in the latency denominator as Uncertain. Final per-view API statuses: `{json.dumps(summary['hybrid_statuses'])}`. Model aliases returned: `{json.dumps(summary['hybrid_reported_models'])}`.\n"
 (O/'public/RESULTS.md').write_text(md)
 # Two full-width LaTeX tables, ready for the paper's existing booktabs/graphicx packages.
 tex='\\begin{table*}[t]\n\\centering\n\\caption{Local processing and scalability on 2,862 normalized evidence views. Five measured repetitions; warm operation.}\n\\label{tab:v5-performance-local}\n\\footnotesize\n\\begin{tabular}{lrrrrrrr}\n\\toprule\nHarness / evidence & $n$ & Load (ms) & Rules (ms) & Total (ms) & p50 & p95 & p99 \\\\\n\\midrule\n'
 for key,v in local.items():tex+=f"{key} & {v['unique_views']} & {v['load_ms']['mean']:.2f} & {v['rules_ms']['mean']:.2f} & {v['service_ms']['mean']:.2f} & {v['service_ms']['p50']:.2f} & {v['service_ms']['p95']:.2f} & {v['service_ms']['p99']:.2f} \\\\\n"
 tex+='\\midrule\n\\multicolumn{8}{l}{Evidence size (lossless snapshot bytes)} \\\\\n'
 for key,v in size.items():tex+=f"{key} & {v['unique_views']} & -- & {v['rules_ms']['mean']:.2f} & {v['service_ms']['mean']:.2f} & {v['service_ms']['p50']:.2f} & {v['service_ms']['p95']:.2f} & {v['service_ms']['p99']:.2f} \\\\\n"
 tex+='\\midrule\nWorkers & Views/s & Speedup & Efficiency & Service p95 & Response p95 & RSS sum (MiB) & Blocks \\\\\n'
 for key,v in scale.items():tex+=f"{key} & {v['throughput_median']:.2f} & {v['speedup_paired_median']:.2f} & {100*v['parallel_efficiency']:.1f}\\% & {v['service_ms']['p95']:.2f} & {v['response_ms']['p95']:.2f} & {v['peak_process_rss_sum_mib']:.2f} & 5 \\\\\n"
 tex+='\\bottomrule\n\\end{tabular}\n\\end{table*}\n\n\\begin{table*}[t]\n\\centering\n\\caption{Real Hybrid service latency with DeepSeek V4 Flash at concurrency four. All conditions contain 477 views; only rule U invokes the model.}\n\\label{tab:v5-performance-hybrid}\n\\footnotesize\n\\resizebox{\\textwidth}{!}{\\begin{tabular}{lrrrrrrrrr}\n\\toprule\nHarness / evidence & Fallback & Rate & Direct mean (ms) & Fallback mean (s) & Fallback p95 (s) & All mean (s) & All p50 (s) & All p95 (s) & Tokens (M) \\\\\n\\midrule\n'
 for key,v in hybrid.items():tex+=f"{key} & {v['fallback_views']} & {100*v['fallback_rate']:.2f}\\% & {v['direct_ms']['mean']:.2f} & {v['fallback_ms']['mean']/1000:.2f} & {v['fallback_ms']['p95']/1000:.2f} & {v['service_ms']['mean']/1000:.2f} & {v['service_ms']['p50']/1000:.2f} & {v['service_ms']['p95']/1000:.2f} & {v['tokens']/1e6:.2f} \\\\\n"
 tex+='\\bottomrule\n\\end{tabular}}\n\\end{table*}\n';(O/'public/tables.tex').write_text(tex)
 write(O/('validation.json' if private_manifest.exists() else 'public/recomputed-validation.json'),{'passed':True,'A1_measurements':14310,'A2_measurements':57240,'B1_views':2862,'rule_replay_mismatches':0,'hybrid_rule_mismatches':sum(x['rule_verdict']!=meta[x['sample_id']]['expected_rule'] for x in b1),'accuracy_source_unchanged':hashlib.sha256((O.parents[1]/'artifacts/cross-harness-v5-r1-20260915/release-r2/case-results.json').read_bytes()).hexdigest()==read(O/'preflight.json')['source_accuracy_sha256'] if private_manifest.exists() else None})
 print(json.dumps({'summary':str(O/'public/RESULTS.md'),'rule_mismatches':0,'api_calls':summary['hybrid_api_calls'],'tokens':summary['hybrid_tokens']}))
if __name__=='__main__':main()
