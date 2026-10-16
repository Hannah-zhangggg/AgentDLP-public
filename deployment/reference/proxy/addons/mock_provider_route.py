import os

from mitmproxy import http


ENABLED = False


def load(loader):
    global ENABLED
    ENABLED = os.environ.get("AGENTDLP_MOCK_PROVIDER_ROUTE", "false").lower() == "true"


def requestheaders(flow: http.HTTPFlow):
    if not ENABLED:
        return
    route_host = os.environ.get("AGENTDLP_MOCK_ROUTE_HOST", "mock-provider")
    try:
        route_port = int(os.environ.get("AGENTDLP_MOCK_ROUTE_PORT", "8000"))
    except ValueError:
        route_port = 8000
    if flow.request.scheme != "https" or flow.request.host != route_host or flow.request.port != route_port:
        return
    flow.metadata["agentdlp_original_scheme"] = flow.request.scheme
    flow.metadata["agentdlp_mock_route"] = True
    flow.request.scheme = "http"
