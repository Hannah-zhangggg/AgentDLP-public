from mitmproxy import http, io

from normalization.core.models import CanonicalHTTPFlow, CanonicalRequest


def canonical_request(flow: http.HTTPFlow, run_id: str, harness_id: str) -> CanonicalRequest:
    headers = {name.lower(): value for name, value in flow.request.headers.items()}
    return CanonicalRequest(
        run_id=run_id,
        flow_id=flow.id,
        harness_id=harness_id,
        proxy_principal=flow.metadata.get("agentdlp_proxy_principal"),
        timestamp=flow.request.timestamp_start,
        method=flow.request.method,
        scheme=flow.request.scheme,
        host=flow.request.host,
        port=flow.request.port,
        path=flow.request.path,
        headers=headers,
        body=flow.request.content or b"",
    )


def _address(value):
    if value is None:
        return None
    if isinstance(value, tuple) and len(value) >= 2:
        return (str(value[0]), int(value[1]))
    try:
        return (str(value[0]), int(value[1]))
    except (TypeError, ValueError, IndexError):
        return None


def canonical_http_flow(
    flow: http.HTTPFlow,
    run_id: str,
    harness_id: str,
    *,
    workload_id: str | None = None,
    session_id: str | None = None,
) -> CanonicalHTTPFlow:
    request = canonical_request(flow, run_id, harness_id)
    inferred_session = session_id
    if inferred_session is None:
        for name in ("x-agentdlp-session-id", "x-session-affinity", "x-session-id"):
            if request.headers.get(name):
                inferred_session = request.headers[name]
                break
    response = flow.response
    response_headers = (
        {name.lower(): value for name, value in response.headers.items()}
        if response is not None else {}
    )
    return CanonicalHTTPFlow(
        run_id=run_id,
        flow_id=flow.id,
        harness_id=harness_id,
        workload_id=workload_id or harness_id,
        proxy_principal=request.proxy_principal,
        session_id=inferred_session,
        timestamp_start=request.timestamp,
        timestamp_end=response.timestamp_end if response is not None else None,
        transport_protocol="tcp",
        client_address=_address(flow.client_conn.address),
        server_address=_address(
            getattr(flow.server_conn, "peername", None) or flow.server_conn.address
        ),
        request=request,
        response_status=response.status_code if response is not None else None,
        response_headers=response_headers,
        response_body=(response.raw_content or b"") if response is not None else b"",
        error=str(flow.error) if flow.error is not None else None,
    )


def iter_http_requests(source, run_id: str, harness_id: str):
    for flow in io.FlowReader(source).stream():
        if isinstance(flow, http.HTTPFlow) and flow.request is not None:
            yield canonical_request(flow, run_id, harness_id)


def iter_http_flows(
    source,
    run_id: str,
    harness_id: str,
    *,
    workload_id: str | None = None,
    session_id: str | None = None,
):
    for flow in io.FlowReader(source).stream():
        if isinstance(flow, http.HTTPFlow) and flow.request is not None:
            yield canonical_http_flow(
                flow,
                run_id,
                harness_id,
                workload_id=workload_id,
                session_id=session_id,
            )
