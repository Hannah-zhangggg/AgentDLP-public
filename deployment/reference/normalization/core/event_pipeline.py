from __future__ import annotations

from normalization.adapters.generic import GenericHTTPAdapter
from normalization.adapters.model_api.events import ModelAPIEventAdapter
from normalization.adapters.tool_protocol import MCPJSONRPCAdapter
from normalization.core.event_schema import content_evidence, make_http_event
from normalization.core.models import CanonicalHTTPFlow


class EventAdapterRegistry:
    """Ordered, structure-aware selection with Generic HTTP as final fallback."""

    def __init__(self, adapters=None):
        self.adapters = list(adapters or [
            ModelAPIEventAdapter(),
            MCPJSONRPCAdapter(),
            GenericHTTPAdapter(),
        ])

    def select(self, flow: CanonicalHTTPFlow):
        for adapter in self.adapters:
            try:
                if adapter.matches(flow):
                    return adapter
            except Exception:
                # A broken matcher must not prevent the generic adapter from seeing the flow.
                continue
        return GenericHTTPAdapter()


class UnifiedEventPipeline:
    def __init__(self, registry=None):
        self.registry = registry or EventAdapterRegistry()
        self.fallback = GenericHTTPAdapter()

    def normalize(self, flow: CanonicalHTTPFlow):
        adapter = self.registry.select(flow)
        try:
            events = adapter.adapt(flow)
            if events:
                return events
            raise ValueError("adapter returned no events")
        except Exception as exc:
            try:
                return self.fallback.adapt_error(flow, getattr(adapter, "name", type(adapter).__name__), exc)
            except Exception as fallback_exc:
                # Last-resort record contains no parsed application semantics but preserves identity/evidence.
                return [make_http_event(
                    flow,
                    event_type="generic_traffic",
                    direction="request",
                    application_protocol="http",
                    semantic_type="pipeline_fallback_failure",
                    adapter_name="event_pipeline",
                    parse_status="failed",
                    content=content_evidence(flow.request.body),
                    content_type=flow.request.headers.get("content-type"),
                    error={
                        "code": "fallback_exception",
                        "adapter_error": f"{type(exc).__name__}: {exc}",
                        "fallback_error": f"{type(fallback_exc).__name__}: {fallback_exc}",
                    },
                )]
