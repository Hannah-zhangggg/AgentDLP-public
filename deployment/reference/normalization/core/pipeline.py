from normalization.core.models import CanonicalRequest
from normalization.core.registry import AdapterRegistry


class NormalizationPipeline:
    def __init__(self, registry=None):
        self.registry = registry or AdapterRegistry()

    def normalize(self, request: CanonicalRequest):
        adapter = self.registry.select(request)
        if adapter is None:
            return []
        try:
            return adapter.adapt(request)
        except (UnicodeDecodeError, ValueError) as exc:
            units = []
            adapter._diagnostic(
                units,
                request,
                model=adapter.diagnostic_model(request),
                session_id=adapter.request_session_id(request),
                json_path="$",
                code="malformed_request",
                parse_status="failed",
                observed_type=type(exc).__name__,
            )
            return units
