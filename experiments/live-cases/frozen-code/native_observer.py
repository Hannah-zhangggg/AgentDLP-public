"""Trusted External state/receipt observer, independent of Endpoint interventions."""
from copy import deepcopy
from cs_collectors import Journal,tau_snapshot,object_diff,sha
from consistency.dataset_v5_formal.backend import Backend
class ObservedBackend(Backend):
 def __init__(self,plan,run):
  super().__init__(plan,run);self.journal=Journal(run/'observer-v1');self.previous=None;self.occurrence=0
  self.journal.append('observer_started',version=1,source=self.source,serial=True,environment_clock=None,os_trace_backend='not_installed_for_this_backend',grants=['native_call','native_result','state'],trust='trusted External in-process state reader, isolated from Endpoint fault operators')
  self.record('initial',None);self.journal.flush()
 def record(self,phase,ref):
  s=tau_snapshot(self.data);obj=s.pop('objects')
  if self.previous is None:self.journal.append('state_initial',phase=phase,call_ref=ref,objects=obj,state_sha256=sha(obj),**s)
  else:self.journal.append('state_delta',phase=phase,call_ref=ref,before_sha256=sha(self.previous),state_sha256=sha(obj),changes=object_diff(self.previous,obj),**s)
  self.previous=obj
 def invoke(self,tool,arguments,ref):
  n=self.occurrence;self.occurrence+=1
  self.journal.append('service_accepted',call_ref=ref,tool=tool,arguments=deepcopy(arguments))
  self.record('native_before',ref);self.journal.append('native_received',call_ref=ref,occurrence=n,tool=tool,arguments=deepcopy(arguments))
  try:
   result=super().invoke(tool,arguments,ref)
   self.journal.append('native_returned',call_ref=ref,occurrence=n,result=deepcopy(result));self.journal.append('service_delivered',call_ref=ref,result=deepcopy(result));return result
  finally:self.record('native_after',ref);self.journal.flush()
 def finish(self):
  self.record('final',None);self.journal.close(True,());return super().finish()
