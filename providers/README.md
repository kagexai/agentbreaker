# providers/

Custom Python scripts for the `script` and `browser` provider types.

## Script Provider Interface

Scripts receive a JSON payload on stdin and must print a JSON result to stdout.

**Input (stdin)**:
```json
{
  "attack_id": "ATK-00042",
  "text": "...",
  "messages": [],
  "modality": "text",
  "media": [],
  "metadata": {}
}
```

**Output (stdout)**:
```json
{
  "text": "target's response text",
  "breach": false,
  "metadata": {"tool_calls": [], "latency_ms": 450},
  "error": null
}
```

**Healthcheck**: When `{"healthcheck": true}` is received on stdin, return `{"ok": true}` and exit 0.

## Browser Provider Interface

Browser scripts use the same stdin/stdout JSON interface. Use Playwright to
interact with web UIs. See `browser_chatbot.py.example` for a skeleton.

## Files

- `agent_target.py.example` -- skeleton for attacking an agent system
- `browser_chatbot.py.example` -- skeleton for attacking a web chat UI

Copy and rename these (remove `.example`) to create real providers.
