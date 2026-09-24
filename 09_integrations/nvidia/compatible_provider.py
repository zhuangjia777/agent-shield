"""Private endpoint transport for the official SkillSpector provider extension."""
import httpx
from langchain_openai import ChatOpenAI
from pydantic import SecretStr
from skillspector.providers.openai_compatible.provider import OpenAICompatibleProvider


class AgentShieldCompatibleProvider(OpenAICompatibleProvider):
    def __init__(self, config, callbacks=None):
        self.config = config
        self.callbacks = callbacks or []
        self.sync_clients = []

    def get_context_length(self, model):
        # Conservative request budget, not the server's actual capacity.
        return 8192

    def get_max_output_tokens(self, model):
        return min(4096, max(512, int(self.config.get("max_tokens", 2500))))

    def create_chat_model(self, model, *, max_tokens, timeout=120):
        credentials = self.resolve_credentials()
        if credentials is None:
            return None
        key, base_url = credentials
        # Upstream graph nodes can use separate asyncio.run loops. Do not use
        # LangChain's process-cached HTTP clients or retain loop-bound sockets.
        limits = httpx.Limits(max_connections=4, max_keepalive_connections=0)
        sync_client = httpx.Client(trust_env=False, limits=limits)
        async_client = httpx.AsyncClient(trust_env=False, limits=limits)
        self.sync_clients.append(sync_client)
        return ChatOpenAI(
            model=model, base_url=base_url, api_key=SecretStr(key), temperature=0,
            max_completion_tokens=min(max_tokens, self.get_max_output_tokens(model)),
            timeout=min(timeout or 60, 60), http_client=sync_client,
            http_async_client=async_client, callbacks=self.callbacks,
            extra_body={"chat_template_kwargs": {"enable_thinking": False}}
            if model.lower().startswith("qwen") else None,
        )

    def close(self):
        # Async requests close their sockets within their originating loop
        # because keepalive is disabled; the worker itself is short-lived.
        for client in self.sync_clients:
            client.close()
