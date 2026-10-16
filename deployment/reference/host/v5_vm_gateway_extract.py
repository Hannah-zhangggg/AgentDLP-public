"""Run in the existing proxy container; extract only this run's fresh flows."""
import json
import sys
from mitmproxy import io

offset, run_id = int(sys.argv[1]), sys.argv[2]
with open('/artifacts/flows/three-vm-smoke-001.flow', 'rb') as handle:
    handle.seek(offset)
    rows = []
    for flow in io.FlowReader(handle).stream():
        if flow.request.headers.get('X-AgentDLP-V5-Run') == run_id:
            rows.append({'flow_id': flow.id, 'request_url': flow.request.pretty_url,
                         'request': json.loads(flow.request.get_text()),
                         'status': flow.response.status_code if flow.response else None,
                         'response': json.loads(flow.response.get_text()) if flow.response else None,
                         'client_peer': list(flow.client_conn.peername),
                         'server_peer': list(flow.server_conn.peername) if flow.server_conn.peername else None,
                         'request_start': flow.request.timestamp_start,
                         'response_end': flow.response.timestamp_end if flow.response else None})
    print(json.dumps({'run_id': run_id, 'flows': rows, 'start_offset': offset, 'end_offset': handle.tell()}))
