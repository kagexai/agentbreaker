from ..api import PluginAPI, ProviderPlugin


def register(api: PluginAPI) -> None:
    api.register_provider(
        ProviderPlugin(
            id="custom",
            label="Custom API",
            api="openai-compatible",
            api_key_env="CUSTOM_API_KEY",
            endpoint="",
            default_model="custom-model",
            models=("custom-model",),
            order=90,
        )
    )
