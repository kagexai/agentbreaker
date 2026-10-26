from ..api import PluginAPI, ProviderPlugin


def register(api: PluginAPI) -> None:
    api.register_provider(
        ProviderPlugin(
            id="openrouter",
            label="OpenRouter",
            api="openai-compatible",
            api_key_env="OPENROUTER_API_KEY",
            endpoint="https://openrouter.ai/api/v1",
            default_model="openai/gpt-5.6-sol",
            models=(
                "openai/gpt-5.6-sol",
                "openai/gpt-5.6-terra",
                "anthropic/claude-opus-5.5",
                "anthropic/claude-sonnet-5.5",
                "google/gemini-3.1-pro-preview",
                "google/gemini-2.5-pro",
                "x-ai/grok-4.7",
            ),
            order=45,
        )
    )
