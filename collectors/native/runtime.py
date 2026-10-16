"""New observer deployment around frozen, real public-tool execution.

No change to published Provider content or injection operators. The observer
reads actual storage/state. Its allowed receipts never contain fault metadata,
private program-api-intent, task expected results or evaluator decisions.
"""
from copy import deepcopy
import contextvars
import inspect
import json
from pathlib import Path
import sys
import time
from .collectors import FileSidecar, Journal, AppStateReader, tau_snapshot, object_diff, sha
from .os_trace import trace_native_mcp
from consistency.dataset_v5_formal import public433_intervention_runtime as frozen
from consistency.dataset_v5_formal import backend, chain

CURRENT_API = contextvars.ContextVar('observed_api_scope', default=None)
CURRENT_PARENT = contextvars.ContextVar('observed_program_scope', default=None)
OriginalNative = frozen.BaseBackend
OriginalObserved = frozen.ObservedBackend


class NativeWithObserver(OriginalNative):
    def __init__(self, plan, run):
        super().__init__(plan, run)
        self.observer_owner = None
        if self.source != 'AppWorld': return
        original = self.world.requester.request
        def received(_app_name, _api_name, **kwargs):
            owner = self.observer_owner
            arguments = {'_app_name':_app_name, '_api_name':_api_name,
                         'data':{k:v for k,v in kwargs.items() if k not in ('raise_on_failure','show','track','client')},
                         'raise_on_failure':kwargs.get('raise_on_failure')}
            ref = CURRENT_API.get()
            ordinal = owner.api_native_count
            owner.api_native_count += 1
            owner.record_state('api_before', ref, owner.app_reader.snapshot())
            owner.journal.append('api_received', call_ref=ref, parent_call_ref=CURRENT_PARENT.get(),
                                 occurrence=ordinal, tool=_app_name + '.' + _api_name, arguments=deepcopy(arguments))
            try:
                result = original(_app_name, _api_name, **kwargs)
                owner.journal.append('api_returned', call_ref=ref, occurrence=ordinal, result=deepcopy(result))
                return result
            except Exception as exc:
                owner.journal.append('api_returned', call_ref=ref, occurrence=ordinal,
                                     exception=type(exc).__name__, exception_message=str(exc))
                raise
            finally:
                owner.record_state('api_after', ref, owner.app_reader.snapshot())
        self.world.requester.request = received


class ObservedBackend(OriginalObserved):
    def __init__(self, plan, run, spec):
        self.journal = Journal(run / 'observer-v1')
        self.latest_state = None
        self.api_native_count, self.api_delivered_count = 0, 0
        self.observer_issues, self.sidecar = [], None
        with trace_native_mcp(run) as os_trace_enabled:
            super().__init__(plan, run, spec)
        if self.source == 'MCPMark':
            self.sidecar = FileSidecar(self.native.workspace)
        elif self.source == 'AppWorld':
            self.native.observer_owner = self
            self.app_reader = AppStateReader(self.native.world)
            actual = self.native.world.requester.request
            def delivered(_app_name, _api_name, **kwargs):
                ref = CURRENT_PARENT.get() + '/api-' + str(self.api_delivered_count)
                self.api_delivered_count += 1
                token = CURRENT_API.set(ref)
                try:
                    result = actual(_app_name, _api_name, **kwargs)
                    self.journal.append('api_delivered', call_ref=ref, result=deepcopy(result))
                    return result
                except Exception as exc:
                    self.journal.append('api_delivered', call_ref=ref, exception=type(exc).__name__, exception_message=str(exc))
                    raise
                finally: CURRENT_API.reset(token)
            self.native.world.requester.request = delivered
        clock = None
        if self.source == 'AppWorld':
            # The environment's actual frozen clock, not a reference program or
            # answer. DateTime.now in supplied code is resolved from this fact.
            from appworld.common.datetime import DateTime
            clock = DateTime.now().isoformat()
        self.journal.append('observer_started', version=1, source=self.source,
            os_trace_backend='ptrace-child-x86_64' if os_trace_enabled and self.source=='MCPMark' else 'not_installed_for_this_backend',
            environment_clock=clock, serial=True, native_pid=getattr(getattr(self.native, 'client', None), 'process', None).pid
            if self.source == 'MCPMark' else None,
            grants=['native_call','native_result','state','child_api','child_return'],
            trust='host-pinned observer; service/host trusted; not hostile-root resistant')
        self.record_state('initial', None, self.snapshot())
        self.journal.flush()

    def snapshot(self):
        if self.source == 'MCPMark': return self.sidecar.snapshot()
        if self.source == 'tau-bench': return tau_snapshot(self.native.data)
        return self.app_reader.snapshot()

    def record_state(self, phase, ref, snapshot):
        objects = snapshot['objects']
        meta = {k:v for k,v in snapshot.items() if k != 'objects'}
        if not snapshot['complete']: self.observer_issues.extend(snapshot['issues'])
        if self.latest_state is None:
            self.journal.append('state_initial', call_ref=ref, phase=phase, objects=objects,
                                state_sha256=sha(objects), **meta)
        else:
            self.journal.append('state_delta', call_ref=ref, phase=phase,
                before_sha256=sha(self.latest_state), state_sha256=sha(objects),
                changes=object_diff(self.latest_state, objects), **meta)
        # Readers return immutable snapshots, replacing changed rows/tables.
        self.latest_state = objects

    def observe(self, tool, arguments, ref):
        self.record_state('native_before', ref, self.snapshot())
        occurrence = len(self.events)
        self.journal.append('native_received', call_ref=ref, occurrence=occurrence,
                            tool=tool, arguments=deepcopy(arguments))
        token = CURRENT_PARENT.set(ref)
        try:
            result = super().observe(tool, arguments, ref)
            self.journal.append('native_returned', call_ref=ref, occurrence=occurrence, result=deepcopy(result))
            return result
        except Exception as exc:
            self.journal.append('native_returned', call_ref=ref, occurrence=occurrence,
                                exception=type(exc).__name__, exception_message=str(exc))
            raise
        finally:
            CURRENT_PARENT.reset(token)
            snapshot=self.app_reader.snapshot(force=True) if self.source=='AppWorld' else self.snapshot()
            self.record_state('native_after', ref, snapshot)
            self.journal.flush()

    def invoke(self, tool, arguments, ref):
        # A real service acceptance event, distinct from whether native invoked.
        self.journal.append('service_accepted', call_ref=ref, tool=tool, arguments=deepcopy(arguments))
        try:
            result = super().invoke(tool, arguments, ref)
            self.journal.append('service_delivered', call_ref=ref, result=deepcopy(result))
            return result
        finally: self.journal.flush()

    def finish(self):
        try:
            self.record_state('final', None, self.snapshot())
            # Close public evidence before running the private task evaluator.
            self.journal.close(not self.observer_issues, self.observer_issues)
            return super().finish()
        finally:
            if self.sidecar: self.sidecar.close()


def main():
    frozen.BaseBackend = NativeWithObserver
    frozen.ObservedBackend = ObservedBackend
    frozen.main()


if __name__ == '__main__': main()
