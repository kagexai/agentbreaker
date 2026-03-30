export async function getJson<T = unknown>(path: string): Promise<T> {
  const res = await fetch(path)
  if (!res.ok) throw new Error(`GET ${path} failed: ${res.status} ${res.statusText}`)
  return res.json() as Promise<T>
}

export async function postJson<T = unknown>(path: string, payload: unknown): Promise<T> {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) {
    let msg = `POST ${path} failed: ${res.status}`
    try {
      const body = await res.json() as { error?: string; message?: string }
      msg = body.error ?? body.message ?? msg
    } catch { /* ignore */ }
    throw new Error(msg)
  }
  return res.json() as Promise<T>
}

// ── Type shapes (top-level keys from existing API) ──────────────────────────

export interface OverviewStats {
  high_risk_targets: number
  total_attacks: number
  total_kept: number
  keep_rate: number
  total_success_findings: number
  total_partial_findings: number
  total_validation_issues: number
}

export interface TargetSummary {
  target_id: string
  peak_composite: number
  attack_count: number
  keep_count: number
  keep_rate: number
  top_categories: string[]
  top_owasp_refs: string[]
  top_mitre_atlas: string[]
  findings: Record<string, number>
  validation_issue_count: number
  unique_category_count: number
  provider?: string
  tags?: string[]
  deployment_type?: string
  persona_name?: string
  model_family?: string
  capabilities?: Record<string, unknown>
  ctf?: {
    present: boolean
    current_challenge: { id?: string; title?: string }
    flag_count: number
    submitted_flag_count: number
  }
  // extra fields passed through from overview
  [key: string]: unknown
}

export interface OverviewPayload {
  generated_at: string
  target_count: number
  targets: TargetSummary[]
  stats: OverviewStats
}

export interface CoverageRow {
  target_id: string
  category: string
  status: string
  max_composite: number
  attempts: number
  keep_count: number
}

export interface CoverageSummaryRow {
  target_id: string
  tested_categories: number
  validated_categories: number
  peak_composite: number
  attack_count: number
}

export interface CoveragePayload {
  generated_at: string
  matrix: CoverageRow[]
  summary: CoverageSummaryRow[]
}

export interface AtlasTechnique {
  id: string
  name: string
  tactic: string
  severity: string
  target_count: number
  evidence_count: number
  max_composite: number
}

export interface AtlasPayload {
  generated_at: string
  techniques: AtlasTechnique[]
}

export interface OwaspItem {
  owasp_ref: string
  severity: string
  target_count: number
  keep_count: number
  max_composite: number
  attempts: number
}

export interface OwaspPayload {
  generated_at: string
  items: OwaspItem[]
}

export interface RegressionEntry {
  target_id: string
  attack_id: string
  tier: string
  category: string
  technique: string
  composite: number
  asr: number
  breach_detected: boolean
  payload_preview: string
  response_excerpt: string
  owasp_ref: string
  benchmark_ref: string
  path: string
}

export interface RegressionsPayload {
  generated_at: string
  entries: RegressionEntry[]
}

export interface OpsJob {
  job_id: string
  target_id: string
  status: string
  command: string
  started_at?: string
  finished_at?: string
  exit_code?: number
  error?: string
}

export interface OpsTarget {
  target_id: string
  provider: string
  url?: string
  model?: string
  authorized_by?: string
  tags?: string[]
}

export interface OpsEngineState {
  role: string
  api: string
  model: string
  api_key_env?: string
  endpoint?: string
  configured: boolean
  api_key_present: boolean
  api_key_masked: string
}

export interface OpsProviderPreset {
  key: string
  label: string
  default_model: string
  api: string
  api_key_env: string
  endpoint?: string
}

export interface OpsApiConfig {
  generated_at?: string
  env_file?: string
  providers?: OpsProviderPreset[]
  judge?: OpsEngineState
  generator?: OpsEngineState
  planner?: { use_judge_config: boolean }
}

export interface OpsPayload {
  generated_at: string
  targets: OpsTarget[]
  jobs: OpsJob[]
  stats: Record<string, unknown>
  api_config: OpsApiConfig
}

export interface TrendPoint {
  index: number
  attack_id: string
  composite_score: number
  asr: number
  category?: string
  technique?: string
  status?: string
}

export interface GraphNode {
  id: string
  label: string
  type: string
  severity?: string
}

export interface GraphEdge {
  source: string
  target: string
}

export interface TargetReport {
  generated_at: string
  target_id: string
  overview: Record<string, unknown>
  profile: Record<string, unknown>
  findings: Record<string, unknown>[]
  evaluations: Record<string, unknown>[]
  campaigns: Record<string, unknown>[]
  vulnerabilities: Record<string, unknown>[]
  trends: TrendPoint[]
  missions: Record<string, unknown>[]
  graph: { nodes: GraphNode[]; edges: GraphEdge[] }
  regressions: Record<string, unknown>[]
  coverage: CoverageRow[]
  owasp: OwaspItem[]
  mitre_atlas: AtlasTechnique[]
  decision_signals: Record<string, unknown>
}

// ── Taxonomy types ───────────────────────────────────────────────────────────

export interface TaxonomySubcategory {
  id: string
  description: string
  strategies: string[]
  arc_techniques: string[]
  arc_evasions: string[]
  seed_count: number
  seed_paths: string[]
  requires: string | null
}

export interface TaxonomyCategory {
  id: string
  owasp: string[]
  difficulty: [number, number]
  benchmarks: string[]
  description: string
  requires: string | null
  subcategory_count: number
  subcategories: TaxonomySubcategory[]
}

export interface StrategyIndexEntry {
  id: string
  primary_category: string
  categories: string[]
}

export interface TaxonomyPayload {
  generated_at: string
  category_count: number
  strategy_count: number
  arc_dimension_counts: Record<string, number>
  arc_dimensions: string[]
  categories: TaxonomyCategory[]
  strategy_index: StrategyIndexEntry[]
}

export interface ArcEntry {
  id: string
  title: string
  description: string
  dimension: string
  ideas: string[]
}

export interface ArcDimensionPayload {
  generated_at: string
  dimension: string | null
  count: number
  entries: ArcEntry[]
}

export interface SeedEntry {
  name: string
  path: string
  category: string
  strategy: string
  tier: 'community' | 'enterprise'
  owasp: string
  difficulty: string
  notes: string
  preview: string
}

export interface SeedListingPayload {
  generated_at: string
  category: string | null
  strategy: string | null
  count: number
  seeds: SeedEntry[]
}

export interface ProfileStoryPayload {
  generated_at: string
  target_id: string
  overview: Record<string, unknown>
  profile: Record<string, unknown>
  profile_story: {
    headline: string
    identity: Record<string, unknown>
    capability_signals: { name: string; state: string }[]
    guardrail_clues: {
      hard_refusals: string[]
      soft_refusals: string[]
      refusal_phrases: string[]
    }
    priority_surface: { priority: string; category: string; reason: string; suggested_angles: string[] }[]
    domain_angles: { name: string; category: string; tailored_to: string; description: string }[]
    multimodal_surface: Record<string, unknown>
    summary_cards?: Record<string, number>
  }
}

// ── Live attack stream types ──────────────────────────────────────────────────

export interface LivePlanEvent {
  type: 'plan'
  attack_id: string
  strategy_id: string
  target_field: string
  framing: string
  variant_index: number
}

export interface LiveJudgeEvent {
  type: 'judge'
  attack_id: string
  trial: number
  composite: number
  asr: number
  vulnerability: number
  reliability: number
  failure_mode: string
  response_cluster: string
  breach_hint: boolean
  recommended_next_family?: string
  partial_leak_detected?: boolean
  judge_reasoning?: string
  payload_text?: string
  response_text?: string
}

export interface LiveLogEvent {
  type: 'log'
  line: string
  subtype?: 'attack_start' | 'result' | 'planner_detail'
  attack_id?: string
  strategy_id?: string
  category?: string
  variant_index?: number
  target_field?: string
  framing?: string
  status?: string
  composite?: number
}

export interface LiveResultEvent {
  type: 'result'
  attack_id: string
  status: string
  composite: number
}

export type LiveEvent =
  | LivePlanEvent
  | LiveJudgeEvent
  | LiveLogEvent
  | LiveResultEvent
  | { type: 'heartbeat'; status: string }
  | { type: 'done'; status: string }
