# AgentBreaker Results Showcase

This repository no longer ships a bundled public seed corpus.

What it does keep is evidence of the kinds of issues AgentBreaker has already been able to surface across real systems.

## Observed Coverage

Current public success findings in the repo include:

- `promptairlines`: 178 success findings
- `resistance-level-1`: 3 success findings
- `gpt-5.2`: 12 success findings across model-side probing runs
- `gpt-5.4`: 16 success findings across model-side probing runs

Most common successful categories in the current public corpus:

- `multimodal_injection`: 95
- `jailbreak`: 42
- `system_prompt_extraction`: 20
- `prompt_injection`: 17
- `data_exfiltration`: 4
- `guardrail_bypass`: 3

## Model Coverage

### gpt-5.2

The current public `gpt-5.2` corpus includes successful runs across:

- `jailbreak`
- `guardrail_bypass`
- `prompt_injection`
- `tool_misuse`
- `data_exfiltration`

Representative examples:

- [ATK-01079](../findings/success/gpt-5.2/mar-19-v3/ATK-01079.yaml)
  `data_exfiltration` / `pii_elicitation`
- [ATK-01105](../findings/success/gpt-5.2/mar-19-v4/ATK-01105.yaml)
  `jailbreak` / `role_playing.authority_claim`

### gpt-5.4

The current public `gpt-5.4` corpus includes successful runs across:

- `prompt_injection`
- `guardrail_bypass`
- `tool_misuse`
- `system_prompt_extraction`
- `jailbreak`

Representative examples:

- [ATK-00828](../findings/success/gpt-5.4/mar-17-v4/ATK-00828.yaml)
  `jailbreak` / `role_playing.character_adoption`
- [ATK-01044](../findings/success/gpt-5.4/mar-19-v5/ATK-01044.yaml)
  `system_prompt_extraction` / `direct_ask`

## Representative Outcomes

### Prompt Extraction

On `resistance-level-1`, AgentBreaker produced a completion-style prompt extraction that disclosed a protected flag:

- [ATK-00001](../findings/success/ATK-00001.yaml)
- category: `system_prompt_extraction`
- technique: `completion_attack`

### Structured Data Exfiltration

On `promptairlines`, AgentBreaker induced the system to return protected runtime data in JSON:

- [ATK-00005](../findings/success/ATK-00005.yaml)
- category: `data_exfiltration`
- technique: `json_export`

### Authority Framing / Policy Bypass

On `promptairlines`, an authority-override flow produced a protected coupon value:

- [ATK-00011](../findings/success/ATK-00011.yaml)
- category: `jailbreak`
- technique: `authority_override`

### Multimodal Injection

On `promptairlines`, a membership-card upload flow yielded a protected artifact:

- [ATK-00004](../findings/success/ATK-00004.yaml)
- category: `multimodal_injection`
- technique: `membership_card_injection`

## Why This Matters

The point of AgentBreaker is not to ship a bag of canned prompts.

The point is to help operators surface real weaknesses such as:

- system prompt leakage
- secret disclosure
- jailbreak and policy bypass paths
- unsafe multimodal handling
- weak workflow controls around AI-assisted systems
