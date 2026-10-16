"""Optional child-only ptrace trace for the native filesystem MCP process.

Used where no host eBPF file/process collector is deployed. Does not replace the
existing Endpoint eBPF network collector and is reported as a distinct backend.
"""
from contextlib import contextmanager
import os
from pathlib import Path
import subprocess


@contextmanager
def trace_native_mcp(run):
    original=subprocess.Popen
    binary=Path(__file__).with_name('syscall-observer')
    enabled=binary.is_file() and os.access(binary,os.X_OK)
    def popen(args,*rest,**kwargs):
        if enabled and isinstance(args,(list,tuple)) and len(args)==3 and str(args[1]).endswith('/@modelcontextprotocol/server-filesystem/dist/index.js'):
            args=[str(binary),str(Path(run)/'os-runtime-events.jsonl'),'--',*map(str,args)]
        return original(args,*rest,**kwargs)
    subprocess.Popen=popen
    try:yield enabled
    finally:subprocess.Popen=original
