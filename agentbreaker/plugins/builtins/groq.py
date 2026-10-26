from ..api import PluginAPI, ProviderPlugin


def register(api: PluginAPI) -> None:
    api.register_provider(
        ProviderPlugin(
            id="groq",
            label="Groq",
            api="openai-compatible",
            api_key_env="GROQ_API_KEY",
            endpoint="https://api.groq.com/openai/v1",
            default_model="llama-3.3-70b-versatile",
            models=("llama-3.3-70b-versatile", "llama-3.1-8b-instant"),
            order=40,
        )
    )
