"""Fact-only observers. No detector, fault plan, task verifier or oracle imports.

Filesystem scans run in a distinct process; dictionary/ORM scans require a
trusted service observer. Neither is a claim of resilience to host compromise.
"""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False)


def sha(value): return hashlib.sha256(canonical(value).encode()).hexdigest()


def filesystem_snapshot(root, max_files=20000, max_bytes=256 * 1024**2):
    """No symlink traversal. Read regular objects through O_NOFOLLOW dir fds.

    Quiescent serial call boundary only; unstable/racy objects invalidate the
    snapshot instead of pretending a concurrent tree scan is atomic.
    """
    root = Path(root).resolve(strict=True)
    started = time.monotonic_ns()
    rows, issues, total = {}, [], 0
    def visit(fd, prefix):
        nonlocal total
        for name in sorted(os.listdir(fd)):
            key = prefix + name
            if len(rows) >= max_files:
                raise ValueError('file_count_budget')
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            row = {'dev': info.st_dev, 'inode': info.st_ino, 'mode': stat.S_IMODE(info.st_mode),
                   'mtime_ns':info.st_mtime_ns, 'ctime_ns':info.st_ctime_ns}
            rows[key] = row
            if stat.S_ISLNK(info.st_mode):
                row.update(kind='symlink', target=os.readlink(name, dir_fd=fd))
                continue
            if stat.S_ISDIR(info.st_mode):
                row['kind'] = 'directory'
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try: visit(child, key + '/')
                finally: os.close(child)
            elif stat.S_ISREG(info.st_mode):
                total += info.st_size
                if total > max_bytes: raise ValueError('byte_budget')
                child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                try:
                    begin = os.fstat(child)
                    if not stat.S_ISREG(begin.st_mode) or (info.st_dev, info.st_ino) != (begin.st_dev, begin.st_ino):
                        raise ValueError('object_replaced')
                    h, count, chunks = hashlib.sha256(), 0, []
                    while True:
                        data = os.read(child, 1024 * 1024)
                        if not data: break
                        count += len(data)
                        if count > max_bytes: raise ValueError('growing_file_budget')
                        h.update(data)
                        if count <= 256 * 1024: chunks.append(data)
                    end = os.fstat(child)
                    if (begin.st_size, begin.st_mtime_ns, begin.st_ctime_ns) != (end.st_size, end.st_mtime_ns, end.st_ctime_ns):
                        raise ValueError('object_changed_during_scan')
                    row.update(kind='file', bytes=count, sha256=h.hexdigest())
                    if count <= 256 * 1024:
                        try: row['text'] = b''.join(chunks).decode('utf-8')
                        except UnicodeDecodeError: pass
                finally: os.close(child)
            else:
                row['kind'] = 'special'
                issues.append('unsupported_object:' + key)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try: visit(fd, '')
        except (OSError, ValueError) as exc: issues.append(type(exc).__name__ + ':' + str(exc))
    finally: os.close(fd)
    return {'objects':rows, 'complete':not issues, 'issues':issues,
            'started_ns':started, 'ended_ns':time.monotonic_ns(), 'observer_pid':os.getpid(),
            'observer':'external-filesystem-sidecar-v1', 'scope':'serial_quiescent_workspace',
            'bytes_read':total}


def durable_content(row):
    # Content visible after an operation, NOT a power-loss durability claim.
    if row is None: return None
    return {k:row[k] for k in ('kind','sha256','bytes','target') if k in row}


def object_diff(before, after):
    return [{'object':key, 'before':deepcopy(before.get(key)), 'after':deepcopy(after.get(key))}
            for key in sorted(set(before) | set(after)) if before.get(key) != after.get(key)]


def semantic_fs_diff(before, after):
    return [key for key in sorted(set(before) | set(after))
            if durable_content(before.get(key)) != durable_content(after.get(key))]


class FileSidecar:
    def __init__(self, workspace):
        env = dict(os.environ)
        # No inherited injection hooks or Python startup hooks in the observer.
        for key in ('NODE_OPTIONS', 'AGENTDLP_SHORT_WRITE_DIR', 'PYTHONSTARTUP'):
            env.pop(key, None)
        self.process = subprocess.Popen([sys.executable, '-B', '-m',
            'consistency.evidence_baseline_v1.collectors', str(Path(workspace).resolve())],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=env, bufsize=1)
        self.sequence = 0

    def snapshot(self):
        import select
        self.process.stdin.write(json.dumps({'sequence':self.sequence}) + '\n')
        self.process.stdin.flush()
        ready, _, _ = select.select([self.process.stdout], [], [], 60)
        if not ready: raise TimeoutError('filesystem_observer_timeout')
        raw = self.process.stdout.readline()
        if not raw: raise RuntimeError('filesystem_observer_stopped')
        value = json.loads(raw)
        if value.pop('sequence') != self.sequence: raise ValueError('sidecar_sequence')
        self.sequence += 1
        return value

    def close(self):
        self.process.stdin.close()
        try: self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.terminate(); self.process.wait(timeout=5)
        self.process.stdout.close(); self.process.stderr.close()


def tau_snapshot(data):
    return {'objects':{table + '/' + str(key):deepcopy(value) for table, values in data.items()
                       for key, value in values.items()}, 'complete':True, 'issues':[],
            'observer':'trusted-native-state-reader-v1', 'scope':'original_tau_in_memory_state',
            'time_ns':time.monotonic_ns()}


def app_snapshot(world):
    """Read actual SQLite rows through trusted live connections.

    Stream row hashes to bound observer RAM; retain table/column shape. These
    prove which records changed, not the semantics of every business effect.
    No ORM materialization of the entire multi-app database on every API call.
    """
    objects, issues = {}, []
    try:
        for app, models in world.models.items():
            connection=models.SQLModel.db.connection
            for name in models.SQLModel.model_names():
                model = models[name]
                table=str(model.__tablename__)
                quoted='"'+table.replace('"','""')+'"'
                cursor=connection.execute('SELECT * FROM '+quoted)
                columns=[d[0] for d in cursor.description]
                id_index=columns.index('id')
                for row in cursor:
                    values=[{'blob_sha256':hashlib.sha256(v).hexdigest()} if isinstance(v,bytes) else v for v in row]
                    objects[app + '.' + name + '/' + str(row[id_index])]={'sha256':sha(values),'columns':columns}
    except Exception as exc:
        issues.append('orm_read_failed:' + type(exc).__name__ + ':' + str(exc)[:200])
    return {'objects':objects, 'complete':not issues, 'issues':issues,
            'observer':'trusted-appworld-orm-reader-v1', 'scope':'current_database_rows',
            'time_ns':time.monotonic_ns()}


class AppStateReader:
    """Cache immutable per-table row hashes, refresh databases on SQLite writes.

    total_changes observes writes through the native connections; force=True
    re-reads all tables at program closure to detect bypassed connection writes.
    Serial native API scope, not a concurrent distributed-database snapshot.
    """
    def __init__(self,world):
        self.world=world;self.cache={};self.counters={};self.sequence=0

    def snapshot(self,force=False):
        issues=[];objects=dict(self.cache)
        try:
            for app,models in self.world.models.items():
                conn=models.SQLModel.db.connection;counter=conn.total_changes
                if not force and self.counters.get(app)==counter:continue
                for name in models.SQLModel.model_names():
                    model=models[name];table=str(model.__tablename__)
                    cursor=conn.execute('SELECT * FROM "'+table.replace('"','""')+'" ORDER BY id')
                    columns=[c[0] for c in cursor.description];id_index=columns.index('id');rows={}
                    for row in cursor:
                        values=[{'blob_sha256':hashlib.sha256(v).hexdigest()} if isinstance(v,bytes) else v for v in row]
                        rows[str(row[id_index])]=sha(values)
                    objects[app+'.'+name]={'row_hashes':rows,'columns':columns,'row_count':len(rows)}
                self.counters[app]=counter
        except Exception as exc:issues.append('sqlite_read_failed:'+type(exc).__name__+':'+str(exc)[:160])
        self.cache=objects;self.sequence+=1
        return {'objects':objects,'complete':not issues,'issues':issues,'observer':'trusted-sqlite-state-reader-v1',
                'scope':'native_connection_changes_with_full_closure_scan','time_ns':time.monotonic_ns(),'scan_sequence':self.sequence}


class Journal:
    """Buffered outside AppWorld's execution sandbox; sequence/hash continuity.

    Hash chaining detects corruption after trusted retrieval, not malicious
    rewriting by the same uid. Deployment authority comes from the host loader.
    """
    def __init__(self, directory):
        self.directory = Path(directory).resolve()
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.rows, self.previous = [], '0' * 64

    def append(self, kind, **fields):
        row = dict(fields, kind=kind, sequence=len(self.rows), previous=self.previous,
                   monotonic_ns=time.monotonic_ns())
        self.previous = sha(row)
        row['sha256'] = self.previous
        self.rows.append(row)
        return row

    def flush(self):
        # Mechanical serialization of generated evidence, never authored files.
        path = self.directory / 'receipts.jsonl'
        with path.open('w', encoding='utf-8') as stream:
            for row in self.rows: stream.write(canonical(row) + '\n')

    def close(self, complete, issues=()):
        self.append('observer_closed', complete=bool(complete), issues=list(issues))
        self.flush()


def main():
    workspace = Path(sys.argv[1]).resolve(strict=True)
    for line in sys.stdin:
        request = json.loads(line)
        if set(request) != {'sequence'}: raise ValueError('sidecar_request')
        value = filesystem_snapshot(workspace)
        print(canonical(dict(value, sequence=request['sequence'])), flush=True)


if __name__ == '__main__': main()
