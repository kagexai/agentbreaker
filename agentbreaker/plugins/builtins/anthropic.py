from ..api import PluginAPI, ProviderPlugin


def register(api: PluginAPI) -> None:
    api.register_provider(
        ProviderPlugin(
            id="anthropic",
            label="Anthropic",
            api="anthropic",
            api_key_env="ANTHROPIC_API_KEY",
            endpoint=None,
            default_model="claude-sonnet-4-5",
            models=("claude-sonnet-4-5", "claude-opus-4-5", "claude-haiku-4-5"),
            order=20,
        )
    )
