from ..api import PluginAPI, ProviderPlugin


def register(api: PluginAPI) -> None:
    api.register_provider(
        ProviderPlugin(
            id="openai",
            label="OpenAI",
            api="openai",
            api_key_env="OPENAI_API_KEY",
            endpoint=None,
            default_model="gpt-5.4",
            models=("gpt-5.4", "gpt-5.2", "gpt-5.1", "gpt-4o", "gpt-4o-mini"),
            order=10,
        )
    )
