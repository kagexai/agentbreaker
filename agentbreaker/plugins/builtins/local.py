from ..api import PluginAPI, ProviderPlugin


def register(api: PluginAPI) -> None:
    api.register_provider(
        ProviderPlugin(
            id="local",
            label="Local OpenAI-compatible",
            api="openai-compatible",
            api_key_env=None,
            endpoint="http://localhost:11434/v1",
            default_model="llama3.1",
            models=("llama3.1", "qwen2.5", "mistral"),
            aliases=("ollama",),
            order=50,
        )
    )
