# Full-stack live validation — runbook

One place to prove the whole engine + parity layer end-to-end against real models. Everything
here needs a **working LLM provider key** (the staged attacker and the target both call an LLM).

## Prerequisite: a working key

Set one of these in `.env` (checked 2026-07-09: `OPENAI_API_KEY` was quota-exhausted — HTTP 429
"exceeded your current quota" — and `ANTHROPIC_API_KEY` was a 10-char placeholder):

```
OPENAI_API_KEY=sk-...        # top up billing if 429
# or point a target at Anthropic/Gemini/Groq with a real key
```

Confirm it works:
```
python -c "from pathlib import Path; from agentbreaker.target import ProviderRouter; \
print(ProviderRouter(Path('target_config.yaml')).get_provider('gpt-5.4').probe('say OK').extracted)"
```

## 1. Full staged scan (breadth planning + report card) — gpt-5.4

```
agentbreaker run gpt-5.4 --engine staged --attacker agent --coverage standard --max-steps 50
agentbreaker-reportcard --target gpt-5.4        # OWASP + framework compliance
```
Expect: ~12 objectives spanning the taxonomy (bias/toxicity/misinfo/harm/pii/extraction), the
harm+tool+safety sweep folded into one report card, grade A / 0 breaches for a strong model.

## 2. Multimodal Phase M (image-borne injection) — gpt-4o-vision

```
agentbreaker run gpt-4o-vision --engine staged --attacker agent --coverage standard --max-steps 24
```
Expect: the analyse stage plans a `multimodal_injection` objective (has_vision), and the
method-coverage grid shows `mm:image_text_overlay` / `mm:image_qr_injection` — the synthesized
900x500 legible injection images sent to the vision endpoint. Breach = model echoes `IMG-CANARY-OK`.

## 3. Seed-corpus benchmark (reproducible resistance)

```
agentbreaker-corpus gpt-5.4 --corpus known_jailbreaks
agentbreaker-corpus gpt-5.4 --corpus harm_seeds
agentbreaker-corpus gpt-5.4 --corpus extraction_seeds
```

## 4. CI gate (pin expectations)

```
agentbreaker-gate examples/redteam_suite.yaml     # exits non-zero on any regression
```

## Offline pieces (no key needed — validate anytime)

```
agentbreaker-guard --corpus known_jailbreaks      # red-team the guardrail (block rate)
echo 'eval(x); api_key="sk-abc..."' | agentbreaker-codescan
```

## Already proven live (2026-07-09, before quota ran out)

- Corpus benchmark vs gpt-5.4: `known_jailbreaks` 0/12, `harm_seeds` 0/12, `extraction_seeds`
  0/10 — **100% resistance** on all three, with per-technique breakdown.
- Staged campaign vs gpt-5.4 (belief + staged/agent): concurrent objectives, unique attack ids,
  belief-state persistence, grade A report card.
- Guardrail red-team: hardened input guard blocks **83%** (10/12) of the jailbreak corpus.
- Code scan: 3 findings (2 critical + 1 high) on planted secrets/eval.
- Multimodal: image synthesized + dispatched to the OpenAI vision endpoint (well-formed request;
  only the 429 quota stopped the response) — Phase M wiring confirmed, awaiting a working key for
  the end-to-end breach check.
