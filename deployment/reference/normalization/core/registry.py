from normalization.adapters.model_api import (
    AnthropicMessagesAdapter,
    GeminiGenerateContentAdapter,
    OpenAIChatAdapter,
)
from normalization.core.models import CanonicalRequest


class AdapterRegistry:
    def __init__(self, adapters=None):
        self.adapters = list(adapters or [
            OpenAIChatAdapter(),
            AnthropicMessagesAdapter(),
            GeminiGenerateContentAdapter(),
        ])

    def select(self, request: CanonicalRequest):
        for adapter in self.adapters:
            if adapter.matches(request):
                return adapter
        return None
