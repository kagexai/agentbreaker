from ..api import PluginAPI, ProviderPlugin


def register(api: PluginAPI) -> None:
    api.register_provider(
        ProviderPlugin(
            id="google",
            label="Google Gemini",
            api="openai-compatible",
            api_key_env="GOOGLE_API_KEY",
            endpoint="https://generativelanguage.googleapis.com/v1beta/openai",
            default_model="gemini-2.5-pro",
            models=("gemini-2.5-pro", "gemini-2.5-flash"),
            aliases=("gemini",),
            order=30,
        )
    )
