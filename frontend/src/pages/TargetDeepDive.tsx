import { useParams } from 'react-router-dom'
import { useState, useCallback } from 'react'
import { useTargetReport, useTargetProfile, useTargetAiSummary } from '@/hooks/useApi'
import { DataAge } from '@/components/DataAge'
import { PageHeaderRow } from '@/components/layout/PageHeaderRow'
import { SectionNav } from '@/components/layout/SectionNav'
import { SectionBlock } from '@/components/SectionBlock'
import { StatCards } from '@/components/StatCards'
import { TrendChart } from '@/components/charts/TrendChart'
import { RadarChart } from '@/components/charts/RadarChart'
import { RiskBadge } from '@/components/RiskBadge'
import { Skeleton } from '@/components/ui/skeleton'
import { Card, CardContent, CardHeader } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { Input } from '@/components/ui/input'
import { ChevronDown, Flag, Bot, Globe, Monitor, Eye, MessageSquare, Wrench, FileText, Volume2, X, Copy, Check } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { fmt, cn } from '@/lib/utils'
import { statusVariant } from '@/components/RiskBadge'

// ── Helpers ─────────────────────────────────────────────────────────────────────

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

function renderBold(s: string): string {
  return escapeHtml(s).replace(/\*\*(.+?)\*\*/g, '<strong class="text-foreground font-medium">$1</strong>')
}

// ── Copy button ────────────────────────────────────────────────────────────────

function CopyBtn({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  const handle = useCallback(() => {
    navigator.clipboard.writeText(text).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500) })
  }, [text])
  return (
    <button onClick={handle} className="shrink-0 p-1 rounded hover:bg-muted transition-colors text-muted-foreground/50 hover:text-muted-foreground" title="Copy">
      {copied ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
    </button>
  )
}

// ── Attack detail modal ────────────────────────────────────────────────────────

interface AttackDetail {
  attack_id: string
  technique?: string
  category?: string
  composite?: number
  asr?: number
  status?: string
  payload_text?: string
  response_text?: string
  modality?: string
}

function AttackModal({ detail, onClose }: { detail: AttackDetail; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" onClick={onClose}>
      <div className="absolute inset-0 bg-black/50" />
      <div className="relative bg-background border border-border rounded-xl shadow-xl max-w-3xl w-full max-h-[85vh] overflow-hidden flex flex-col"
        onClick={e => e.stopPropagation()}>
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-border bg-muted/30">
          <div className="flex items-center gap-3">
            <code className="font-mono text-sm font-semibold">{detail.attack_id}</code>
            {detail.technique && <span className="text-xs text-muted-foreground">{detail.technique.replace(/_/g, ' ')}</span>}
            {detail.status && (
              <Badge variant="outline" className={cn('text-[10px]',
                detail.status === 'keep' ? 'bg-red-500/10 text-red-600 border-red-500/20'
                : detail.status === 'partial' ? 'bg-amber-500/10 text-amber-600 border-amber-500/20'
                : 'text-muted-foreground',
              )}>{detail.status}</Badge>
            )}
            {detail.composite !== undefined && (
              <span className={cn('text-sm font-bold tabular-nums',
                detail.composite >= 7 ? 'text-red-500' : detail.composite >= 4 ? 'text-amber-500' : 'text-muted-foreground',
              )}>{detail.composite.toFixed(1)}</span>
            )}
          </div>
          <Button variant="ghost" size="sm" className="h-7 w-7 p-0" onClick={onClose}><X className="w-4 h-4" /></Button>
        </div>
        {/* Body */}
        <div className="flex-1 overflow-y-auto p-4 grid gap-4">
          {detail.payload_text ? (
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <p className="text-[10px] uppercase tracking-wider font-semibold text-blue-600 dark:text-blue-400">Attack Payload</p>
                <CopyBtn text={detail.payload_text} />
              </div>
              <pre className="text-xs font-mono p-3 rounded-lg border border-blue-500/20 bg-blue-500/5 whitespace-pre-wrap max-h-[300px] overflow-y-auto leading-relaxed">{detail.payload_text}</pre>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No payload data available for this attack.</p>
          )}
          {detail.response_text ? (
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <p className="text-[10px] uppercase tracking-wider font-semibold text-amber-600 dark:text-amber-400">Model Response</p>
                <CopyBtn text={detail.response_text} />
              </div>
              <pre className="text-xs font-mono p-3 rounded-lg border border-amber-500/20 bg-amber-500/5 whitespace-pre-wrap max-h-[300px] overflow-y-auto leading-relaxed text-foreground">{detail.response_text}</pre>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No response data available for this attack.</p>
          )}
          {/* Metadata row */}
          <div className="flex flex-wrap gap-4 text-xs text-muted-foreground">
            {detail.category && <span>Category: <strong className="text-foreground">{detail.category.replace(/_/g, ' ')}</strong></span>}
            {detail.modality && <span>Modality: <strong className="text-foreground">{detail.modality}</strong></span>}
            {detail.asr !== undefined && detail.asr > 0 && <span>ASR: <strong className="text-red-500">{detail.asr.toFixed(2)}</strong></span>}
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Target type helpers ──────────────────────────────────────────────────────

type TargetKind = 'ctf' | 'llm' | 'http' | 'browser' | 'unknown'

function detectKind(overview: Record<string, unknown>): TargetKind {
  const tags = (overview.tags as string[]) ?? []
  if (tags.includes('ctf')) return 'ctf'
  const provider = String(overview.provider ?? '')
  if (provider === 'llm') return 'llm'
  if (provider === 'http') return 'http'
  if (provider === 'browser') return 'browser'
  return 'unknown'
}

const KIND_STYLE: Record<TargetKind, { label: string; color: string; icon: typeof Bot }> = {
  ctf:     { label: 'CTF',     color: 'bg-violet-500/15 text-violet-600 dark:text-violet-400 border-violet-500/30', icon: Flag },
  llm:     { label: 'LLM',     color: 'bg-blue-500/15 text-blue-600 dark:text-blue-400 border-blue-500/30',         icon: Bot },
  http:    { label: 'HTTP',    color: 'bg-slate-500/15 text-slate-600 dark:text-slate-400 border-slate-500/30',     icon: Globe },
  browser: { label: 'Browser', color: 'bg-teal-500/15 text-teal-600 dark:text-teal-400 border-teal-500/30',        icon: Monitor },
  unknown: { label: 'Target',  color: 'bg-muted text-muted-foreground border-border',                               icon: Globe },
}

const CAP_ICONS: Record<string, { label: string; icon: typeof Eye }> = {
  has_vision:     { label: 'Vision',     icon: Eye },
  has_multi_turn: { label: 'Multi-turn', icon: MessageSquare },
  has_tools:      { label: 'Tools',      icon: Wrench },
  has_document:   { label: 'Document',   icon: FileText },
  has_audio:      { label: 'Audio',      icon: Volume2 },
}

const SECTIONS = [
  { id: 'summary', label: 'Summary' },
  { id: 'analysis', label: 'Analysis' },
  { id: 'evidence', label: 'Evidence' },
  { id: 'artifacts', label: 'Artifacts' },
]

function CollapsibleCard({ title, subtitle, children, defaultOpen = true }: {
  title: string; subtitle?: string; children: React.ReactNode; defaultOpen?: boolean
}) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <Collapsible open={open} onOpenChange={setOpen}>
      <Card>
        <CollapsibleTrigger className="w-full text-left" asChild>
          <CardHeader className="pb-2 cursor-pointer hover:bg-muted/30 transition-colors rounded-t-lg flex flex-row items-start justify-between gap-2">
            <div>
              <h3 className="font-semibold text-sm">{title}</h3>
              {subtitle && <p className="text-xs text-muted-foreground mt-0.5">{subtitle}</p>}
            </div>
            <ChevronDown className={cn('w-4 h-4 text-muted-foreground shrink-0 transition-transform mt-0.5', open && 'rotate-180')} />
          </CardHeader>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <CardContent className="pt-0">{children}</CardContent>
        </CollapsibleContent>
      </Card>
    </Collapsible>
  )
}

export function TargetDeepDive() {
  const { targetId = '' } = useParams()
  const { data, isLoading, error, refetch, isFetching } = useTargetReport(targetId)
  const profileData = useTargetProfile(targetId)
  const aiSummary = useTargetAiSummary(targetId)
  const [evalSearch, setEvalSearch] = useState('')
  const [evalFilter, setEvalFilter] = useState<'all' | 'signal'>('signal')
  const [evalPage, setEvalPage] = useState(0)
  const EVAL_PAGE_SIZE = 25
  const [inspectedAttack, setInspectedAttack] = useState<AttackDetail | null>(null)

  if (isLoading) return <div className="grid gap-4"><Skeleton className="h-12" /><Skeleton className="h-24" /><Skeleton className="h-64" /></div>
  if (error) return <p className="text-destructive">Failed to load: {error.message}</p>
  if (!data) return null

  const overview = data.overview as Record<string, unknown>
  const kind = detectKind(overview)
  const kindCfg = KIND_STYLE[kind]
  const KindIcon = kindCfg.icon
  const capabilities = (overview.capabilities as Record<string, unknown>) ?? {}
  const activeCaps = Object.entries(CAP_ICONS).filter(([key]) => capabilities[key] === true)
  const ctf = overview.ctf as { present: boolean; current_challenge: { id?: string; title?: string }; flag_count: number; submitted_flag_count: number } | undefined

  const summaryCards = [
    { label: 'Peak Composite', value: fmt(Number(overview.peak_composite ?? 0)) },
    { label: 'Evaluations', value: Number(overview.attack_count ?? 0) },
    { label: 'Keep Rate', value: fmt(Number(overview.keep_rate ?? 0) * 100, 1) + '%' },
    { label: 'Findings', value: Number((overview.findings as Record<string, number>)?.success ?? 0) },
    { label: 'High Signal', value: Number(overview.high_signal_count ?? 0) },
    { label: 'Breach-like', value: Number(overview.breach_like_count ?? 0) },
    { label: 'Multi-turn', value: Number(overview.multi_turn_attack_count ?? 0) },
    { label: 'Campaigns', value: data.campaigns.length },
  ]

  // Profile story data (may still be loading)
  const story = profileData.data?.profile_story
  const identity = (story?.identity ?? {}) as Record<string, string>
  const guardrails = story?.guardrail_clues
  const domainAngles = story?.domain_angles ?? []

  // Evaluations filtered by search and signal filter
  const evals = data.evaluations as Record<string, unknown>[]
  const filteredEvals = evals.filter(e => {
    if (evalFilter === 'signal') {
      const comp = Number(e.composite_score ?? e.composite ?? 0)
      const status = String(e.status ?? '')
      if (comp < 1.0 && status !== 'keep' && status !== 'partial') return false
    }
    if (evalSearch) {
      return JSON.stringify(e).toLowerCase().includes(evalSearch.toLowerCase())
    }
    return true
  })
  const evalPageCount = Math.ceil(filteredEvals.length / EVAL_PAGE_SIZE)
  const pagedEvals = filteredEvals.slice(evalPage * EVAL_PAGE_SIZE, (evalPage + 1) * EVAL_PAGE_SIZE)

  // Coverage grouped by category
  const coverageCells = data.coverage

  return (
    <div className="grid gap-6">
      <div className="flex items-start justify-between gap-4">
        <PageHeaderRow
          crumbs={[
            { label: 'Targets', to: '/targets' },
            { label: targetId },
          ]}
          actions={[
            { label: 'Report API', href: `/api/targets/${encodeURIComponent(targetId)}`, external: true },
          ]}
        />
        <DataAge generatedAt={data.generated_at} onRefresh={() => refetch()} isRefetching={isFetching} />
      </div>

      {/* Type badge + capabilities bar */}
      <div className="flex items-center gap-2 flex-wrap">
        <span className={cn('inline-flex items-center gap-1 text-xs font-semibold px-2 py-1 rounded border', kindCfg.color)}>
          <KindIcon className="w-3.5 h-3.5" />
          {kindCfg.label}
        </span>
        {(() => { const v = String(overview.model_family ?? ''); return v && v !== 'unknown' ? <Badge variant="outline" className="text-xs">{v}</Badge> : null })()}
        {(() => { const v = String(overview.persona_name ?? ''); return v && v !== 'unknown' ? <span className="text-xs text-muted-foreground">{v}</span> : null })()}
        {activeCaps.map(([key, { label, icon: Icon }]) => (
          <span key={key} className="inline-flex items-center gap-0.5 text-[10px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground">
            <Icon className="w-3 h-3" />
            {label}
          </span>
        ))}
      </div>

      <SectionNav sections={SECTIONS} />

      {/* ── Summary ── */}
      <SectionBlock id="summary" kicker="Executive Summary" title="Target Snapshot"
        description="Stats, AI intelligence, identity, and defensive posture — everything you need at a glance.">
        <StatCards cards={summaryCards} />

        {/* CTF progression — only for CTF targets */}
        {kind === 'ctf' && ctf?.present && (
          <Card className="border-violet-500/30 bg-violet-500/5">
            <CardContent className="p-4 flex flex-col gap-2">
              <div className="flex items-center gap-2">
                <Flag className="w-4 h-4 text-violet-500" />
                <span className="text-sm font-semibold">CTF Progression</span>
              </div>
              <div className="grid sm:grid-cols-3 gap-4 text-sm">
                {ctf.current_challenge?.title && (
                  <div>
                    <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Current Challenge</p>
                    <p className="font-medium">{ctf.current_challenge.title}</p>
                    {ctf.current_challenge.id && (
                      <p className="text-xs text-muted-foreground">{ctf.current_challenge.id}</p>
                    )}
                  </div>
                )}
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Flags Found</p>
                  <p className="font-medium text-lg tabular-nums">{ctf.flag_count}</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Flags Submitted</p>
                  <p className="font-medium text-lg tabular-nums text-emerald-600 dark:text-emerald-400">{ctf.submitted_flag_count}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* AI Summary */}
        <Card>
          <CardHeader className="pb-2">
            <h3 className="font-semibold text-sm">AI Campaign Summary</h3>
          </CardHeader>
          <CardContent>
            {aiSummary.isLoading ? (
              <Skeleton className="h-16" />
            ) : aiSummary.data ? (
              <div className="text-sm leading-relaxed space-y-3 prose-sm">
                {String(aiSummary.data.summary ?? JSON.stringify(aiSummary.data, null, 2))
                  .split(/\n\n+/)
                  .map((block, i) => {
                    const trimmed = block.trim()
                    if (!trimmed) return null
                    // Numbered list block
                    if (/^\d+\.\s/.test(trimmed)) {
                      const items = trimmed.split(/\n/).filter(l => l.trim())
                      return (
                        <ol key={i} className="list-decimal list-inside space-y-1 pl-1">
                          {items.map((item, j) => (
                            <li key={j} className="text-muted-foreground"
                              dangerouslySetInnerHTML={{ __html: renderBold(item.replace(/^\d+\.\s*/, '')) }}
                            />
                          ))}
                        </ol>
                      )
                    }
                    // Regular paragraph — render **bold**
                    return (
                      <p key={i} className="text-muted-foreground"
                        dangerouslySetInnerHTML={{ __html: renderBold(trimmed) }}
                      />
                    )
                  })}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">Run a campaign to generate an AI summary.</p>
            )}
          </CardContent>
        </Card>

        {/* Identity + Guardrails side by side */}
        <div className="grid lg:grid-cols-2 gap-4">
          {/* Target Identity */}
          {Object.values(identity).some(v => v) && (
            <Card>
              <CardHeader className="pb-2">
                <h3 className="font-semibold text-sm">Target Identity</h3>
                <p className="text-xs text-muted-foreground">Inferred from probe responses.</p>
              </CardHeader>
              <CardContent>
                {story?.headline && <p className="text-sm font-medium mb-2">{story.headline}</p>}
                <div className="grid grid-cols-2 gap-2">
                  {Object.entries(identity).filter(([, v]) => v).map(([k, v]) => (
                    <div key={k}>
                      <span className="text-[10px] text-muted-foreground uppercase tracking-wider block">{k.replace(/_/g, ' ')}</span>
                      <span className="text-sm font-medium">{v}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Guardrails */}
          {guardrails && (guardrails.hard_refusals.length > 0 || guardrails.soft_refusals.length > 0 || guardrails.refusal_phrases.length > 0) && (
            <Card>
              <CardHeader className="pb-2">
                <h3 className="font-semibold text-sm">Guardrail Patterns</h3>
                <p className="text-xs text-muted-foreground">Observed refusal behavior during probing and attacks.</p>
              </CardHeader>
              <CardContent className="grid gap-3">
                {guardrails.hard_refusals.length > 0 && (
                  <div>
                    <p className="text-[10px] font-semibold uppercase tracking-wider text-destructive mb-1">Hard Refusals</p>
                    <div className="flex flex-wrap gap-1">{guardrails.hard_refusals.map((r, i) =>
                      <Badge key={i} className="bg-destructive/10 text-destructive text-xs border border-destructive/20">{r}</Badge>
                    )}</div>
                  </div>
                )}
                {guardrails.soft_refusals.length > 0 && (
                  <div>
                    <p className="text-[10px] font-semibold uppercase tracking-wider text-amber-600 dark:text-amber-400 mb-1">Soft Refusals</p>
                    <div className="flex flex-wrap gap-1">{guardrails.soft_refusals.map((r, i) =>
                      <Badge key={i} className="bg-amber-500/10 text-amber-600 dark:text-amber-400 text-xs border border-amber-500/20">{r}</Badge>
                    )}</div>
                  </div>
                )}
                {guardrails.refusal_phrases.length > 0 && (
                  <div>
                    <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-1">Phrases</p>
                    <div className="flex flex-wrap gap-1">{guardrails.refusal_phrases.map((r, i) =>
                      <Badge key={i} variant="outline" className="text-xs font-mono">{r}</Badge>
                    )}</div>
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </div>

        {/* Domain angles — only show if we have them */}
        {domainAngles.length > 0 && (
          <CollapsibleCard title="Attack Angles" subtitle="Domain-tailored strategies specific to this target." defaultOpen={false}>
            <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-2">
              {domainAngles.map((s, i) => (
                <div key={i} className="p-2.5 rounded-lg bg-muted/30 border border-border/50">
                  <span className="text-sm font-medium">{s.name || s.category}</span>
                  {s.description && <p className="text-xs text-muted-foreground mt-0.5">{s.description}</p>}
                </div>
              ))}
            </div>
          </CollapsibleCard>
        )}

        {data.missions.length > 0 && (
          <CollapsibleCard title="Security Missions" subtitle="Gap analysis — what needs testing." defaultOpen={false}>
            <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {(data.missions as Record<string, unknown>[]).map((m, i) => (
                <div key={i} className="p-3 rounded-lg border border-border">
                  <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">{String(m.category ?? '')}</div>
                  <div className="mt-1 font-medium text-sm">{String(m.mission ?? m.name ?? '')}</div>
                  {m.composite != null && (
                    <div className="text-xs text-muted-foreground mt-1">Composite {fmt(Number(m.composite))}</div>
                  )}
                </div>
              ))}
            </div>
          </CollapsibleCard>
        )}
      </SectionBlock>

      {/* ── Analysis ── */}
      <SectionBlock id="analysis" kicker="Risk Analysis" title="Behavior, Trend, and Vulnerability Readout"
        description="How the target behaves over time, which mission areas are covered, and where the strongest vulnerability signal sits.">

        {/* Trend + Radar side by side */}
        <div className="grid lg:grid-cols-2 gap-4">
          <CollapsibleCard title="Evaluation Trend" subtitle="Composite score and ASR across all evaluations.">
            <TrendChart data={data.trends} />
          </CollapsibleCard>

          <CollapsibleCard title="Risk by Category" subtitle="Peak composite score across each attack category.">
            {(() => {
              const vulns = data.vulnerabilities as Record<string, unknown>[]
              const radarData = vulns.map(v => ({
                category: String(v.category ?? '').replace(/_/g, ' '),
                value: Number(v.max_composite ?? 0),
              }))
              return <RadarChart data={radarData} height={260} />
            })()}
          </CollapsibleCard>
        </div>

        {/* Decision signals */}
        {(() => {
          const ds = data.decision_signals as Record<string, {failure_mode?: string; response_cluster?: string; family?: string; count: number}[]> | undefined
          if (!ds) return null
          const failureModes = ds.top_failure_modes ?? []
          const clusters = ds.top_response_clusters ?? []
          const nextFamilies = ds.recommended_next_families ?? []
          if (!failureModes.length && !clusters.length && !nextFamilies.length) return null
          return (
            <CollapsibleCard title="Decision Signals" subtitle="Dominant failure patterns, response clusters, and recommended next attack families.">
              <div className="grid sm:grid-cols-3 gap-6">
                {failureModes.length > 0 && (
                  <div>
                    <p className="text-xs uppercase tracking-wider text-muted-foreground mb-2">Failure Modes</p>
                    <ul className="grid gap-1.5">
                      {failureModes.map((m, i) => (
                        <li key={i} className="flex items-center justify-between text-sm">
                          <span className="text-muted-foreground">{m.failure_mode}</span>
                          <Badge variant="outline" className="text-xs tabular-nums">{m.count}</Badge>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {clusters.length > 0 && (
                  <div>
                    <p className="text-xs uppercase tracking-wider text-muted-foreground mb-2">Response Clusters</p>
                    <ul className="grid gap-1.5">
                      {clusters.map((c, i) => (
                        <li key={i} className="flex items-center justify-between text-sm">
                          <span className="text-muted-foreground">{c.response_cluster}</span>
                          <Badge variant="outline" className="text-xs tabular-nums">{c.count}</Badge>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {nextFamilies.length > 0 && (
                  <div>
                    <p className="text-xs uppercase tracking-wider text-muted-foreground mb-2">Recommended Next</p>
                    <ul className="grid gap-1.5">
                      {nextFamilies.map((f, i) => (
                        <li key={i} className="flex items-center justify-between text-sm">
                          <span className="text-muted-foreground">{f.family}</span>
                          <Badge variant="secondary" className="text-xs tabular-nums">{f.count}</Badge>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </CollapsibleCard>
          )
        })()}

        {/* Vulnerability story */}
        <CollapsibleCard title="Vulnerability Summary" subtitle="Attack categories ranked by severity and signal strength.">
          {(data.vulnerabilities as Record<string, unknown>[]).length === 0
            ? <p className="text-sm text-muted-foreground">No vulnerability data yet.</p>
            : <div className="overflow-auto">
                <table className="w-full text-xs border-collapse">
                  <thead>
                    <tr className="bg-muted/50 text-left border-b border-border">
                      <th className="px-3 py-2 font-medium">Severity</th>
                      <th className="px-3 py-2 font-medium">Category</th>
                      <th className="px-3 py-2 font-medium">Top Techniques</th>
                      <th className="px-3 py-2 text-right font-medium">Composite</th>
                      <th className="px-3 py-2 text-right font-medium">ASR</th>
                      <th className="px-3 py-2 text-right font-medium">Kept</th>
                      <th className="px-3 py-2 text-right font-medium">Attempts</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(data.vulnerabilities as Record<string, unknown>[]).map((v, i) => {
                      const sev = String(v.severity ?? 'low')
                      const cat = String(v.category ?? '').replace(/_/g, ' ')
                      const composite = Number(v.max_composite ?? 0)
                      const asr = Number(v.peak_asr ?? 0)
                      const kept = Number(v.keep_count ?? 0)
                      const attempts = Number(v.attempts ?? 0)
                      const techniques = (v.top_techniques as string[] | undefined) ?? []
                      return (
                        <tr key={i} className={cn(
                          'border-b border-border hover:bg-muted/20 transition-colors',
                          sev === 'high' && 'bg-destructive/[0.02]',
                        )}>
                          <td className="px-3 py-2.5"><RiskBadge level={sev} className="shrink-0" /></td>
                          <td className="px-3 py-2.5 font-medium capitalize">{cat}</td>
                          <td className="px-3 py-2.5">
                            <div className="flex flex-wrap gap-1">
                              {techniques.slice(0, 3).map(t => (
                                <span key={t} className="text-[10px] bg-muted px-1.5 py-0.5 rounded font-mono">{t.replace(/_/g, ' ').replace(/\..+/, '')}</span>
                              ))}
                            </div>
                          </td>
                          <td className={cn(
                            'px-3 py-2.5 text-right font-mono tabular-nums font-semibold',
                            composite >= 7 ? 'text-red-500' : composite >= 4 ? 'text-amber-500' : '',
                          )}>{composite.toFixed(1)}</td>
                          <td className={cn(
                            'px-3 py-2.5 text-right font-mono tabular-nums',
                            asr > 0 && 'text-red-500 font-semibold',
                          )}>{asr.toFixed(2)}</td>
                          <td className="px-3 py-2.5 text-right tabular-nums">{kept}</td>
                          <td className="px-3 py-2.5 text-right tabular-nums text-muted-foreground">{attempts}</td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
          }
        </CollapsibleCard>

        {/* Campaigns */}
        <CollapsibleCard title="Campaign History" subtitle="All evaluation campaigns run against this target." defaultOpen={false}>
          {data.campaigns.length === 0
            ? <p className="text-sm text-muted-foreground">No campaigns recorded.</p>
            : <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
                {(data.campaigns as Record<string, unknown>[]).map((c, i) => {
                  const tag = String(c.campaign_tag ?? `Campaign ${i+1}`)
                  const attacks = Number(c.attack_count ?? 0)
                  const kept = Number(c.keep_count ?? 0)
                  const breaches = Number(c.breach_like_count ?? 0)
                  const highSignal = Number(c.high_signal_count ?? 0)
                  return (
                    <div key={i} className="rounded-lg border border-border p-3 grid gap-1.5">
                      <div className="font-mono text-sm font-semibold">{tag}</div>
                      <div className="grid grid-cols-2 gap-x-3 gap-y-1 text-xs text-muted-foreground">
                        <span>Attacks <strong className="text-foreground">{attacks}</strong></span>
                        <span>Kept <strong className="text-foreground">{kept}</strong></span>
                        {highSignal > 0 && <span>High signal <strong className="text-foreground">{highSignal}</strong></span>}
                        {breaches > 0 && <span className="text-destructive">Breaches <strong>{breaches}</strong></span>}
                      </div>
                    </div>
                  )
                })}
              </div>
          }
        </CollapsibleCard>
      </SectionBlock>

      {/* ── Evidence ── */}
      <SectionBlock id="evidence" kicker="Evidence & Coverage" title="What Was Actually Run"
        description="Category coverage, per-evaluation detail, and request/response inspection.">
        <CollapsibleCard title="Coverage" subtitle="Category coverage matrix for this target.">
          <div className="flex gap-3 text-xs mb-3 flex-wrap">
            {(['validated', 'tested', 'coverage_gap'] as const).map(s => (
              <span key={s} className="flex items-center gap-1">
                <span className={cn('inline-block w-2.5 h-2.5 rounded-sm', statusVariant(s))} />{s.replace('_', ' ')}
              </span>
            ))}
          </div>
          {coverageCells.length === 0
            ? <p className="text-sm text-muted-foreground">No coverage data yet.</p>
            : <div className="overflow-auto">
                <table className="text-xs border-collapse w-full">
                  <thead>
                    <tr className="bg-muted/50">
                      <th className="p-2 text-left border-b border-border">Category</th>
                      <th className="p-2 text-center border-b border-border">Status</th>
                      <th className="p-2 text-right border-b border-border">Composite</th>
                      <th className="p-2 text-right border-b border-border">Attempts</th>
                    </tr>
                  </thead>
                  <tbody>
                    {coverageCells.map((row, i) => (
                      <tr key={i} className="hover:bg-muted/30">
                        <td className="p-2 border-b border-border">{row.category}</td>
                        <td className="p-2 text-center border-b border-border">
                          <Badge className={cn('text-xs', statusVariant(row.status))}>{row.status.replace('_', ' ')}</Badge>
                        </td>
                        <td className="p-2 text-right font-mono border-b border-border">{fmt(row.max_composite)}</td>
                        <td className="p-2 text-right border-b border-border">{row.attempts}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
          }
        </CollapsibleCard>

        <CollapsibleCard title="Evaluation Details" subtitle="Per-attack results. Defaults to signal-only (composite >= 1.0 or kept).">
          <div className="flex items-center gap-3 mb-3 flex-wrap">
            <div className="flex gap-1 p-0.5 rounded bg-muted">
              <Button variant="ghost" size="sm" className={cn('h-7 px-3 text-xs', evalFilter === 'signal' && 'bg-background shadow-sm')}
                onClick={() => { setEvalFilter('signal'); setEvalPage(0) }}>Signal only</Button>
              <Button variant="ghost" size="sm" className={cn('h-7 px-3 text-xs', evalFilter === 'all' && 'bg-background shadow-sm')}
                onClick={() => { setEvalFilter('all'); setEvalPage(0) }}>All {evals.length}</Button>
            </div>
            <Input
              placeholder="Search…"
              value={evalSearch}
              onChange={e => { setEvalSearch(e.target.value); setEvalPage(0) }}
              className="max-w-[200px] h-8 text-xs"
            />
            <span className="text-xs text-muted-foreground">{filteredEvals.length} evaluations</span>
          </div>
          {filteredEvals.length === 0
            ? <p className="text-sm text-muted-foreground">No evaluations match. {evalFilter === 'signal' && 'Try switching to "All".'}</p>
            : <>
                <div className="overflow-auto">
                  <table className="w-full text-xs border-collapse">
                    <thead>
                      <tr className="bg-muted/50 text-left border-b border-border">
                        <th className="px-3 py-2 font-medium">Status</th>
                        <th className="px-3 py-2 font-medium">Attack</th>
                        <th className="px-3 py-2 font-medium">Technique</th>
                        <th className="px-3 py-2 font-medium">Category</th>
                        <th className="px-3 py-2 text-right font-medium">Composite</th>
                        <th className="px-3 py-2 text-right font-medium">Vuln</th>
                        <th className="px-3 py-2 text-right font-medium">ASR</th>
                        <th className="px-3 py-2 font-medium">Modality</th>
                      </tr>
                    </thead>
                    <tbody>
                      {pagedEvals.map((e, i) => {
                        const comp = Number(e.composite_score ?? e.composite ?? 0)
                        const vuln = Number(e.vulnerability_score ?? 0)
                        const asr = Number(e.asr ?? 0)
                        const status = String(e.status ?? 'discard')
                        return (
                          <tr key={i} className={cn(
                            'border-b border-border hover:bg-muted/20 transition-colors',
                            status === 'keep' && 'bg-red-500/[0.03]',
                            status === 'partial' && 'bg-amber-500/[0.03]',
                          )}>
                            <td className="px-3 py-2">
                              <Badge variant="outline" className={cn('text-[10px]',
                                status === 'keep' ? 'bg-red-500/10 text-red-600 border-red-500/20'
                                : status === 'partial' ? 'bg-amber-500/10 text-amber-600 border-amber-500/20'
                                : 'text-muted-foreground',
                              )}>{status}</Badge>
                            </td>
                            <td className="px-3 py-2">
                              <button
                                className="font-mono text-primary hover:underline"
                                onClick={() => setInspectedAttack({
                                  attack_id: String(e.attack_id ?? ''),
                                  technique: String(e.technique ?? ''),
                                  category: String(e.category ?? ''),
                                  composite: comp,
                                  asr,
                                  status,
                                  payload_text: String(e.payload_text ?? ''),
                                  response_text: String(e.response_text ?? e.response_excerpt ?? ''),
                                  modality: String(e.modality ?? 'text'),
                                })}
                              >{String(e.attack_id ?? '')}</button>
                            </td>
                            <td className="px-3 py-2 max-w-[160px] truncate font-medium" title={String(e.technique ?? '')}>{String(e.technique ?? '').replace(/_/g, ' ')}</td>
                            <td className="px-3 py-2 text-muted-foreground">{String(e.category ?? '').replace(/_/g, ' ')}</td>
                            <td className={cn(
                              'px-3 py-2 text-right font-mono tabular-nums',
                              comp >= 7 ? 'text-red-500 font-semibold' : comp >= 4 ? 'text-amber-500 font-semibold' : '',
                            )}>{comp.toFixed(1)}</td>
                            <td className={cn(
                              'px-3 py-2 text-right font-mono tabular-nums',
                              vuln >= 7 ? 'text-red-500' : vuln >= 4 ? 'text-amber-500' : 'text-muted-foreground',
                            )}>{vuln.toFixed(1)}</td>
                            <td className={cn(
                              'px-3 py-2 text-right font-mono tabular-nums',
                              asr > 0 ? 'text-red-500 font-semibold' : 'text-muted-foreground',
                            )}>{asr.toFixed(2)}</td>
                            <td className="px-3 py-2 text-muted-foreground">{String(e.modality ?? 'text')}</td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
                {evalPageCount > 1 && (
                  <div className="flex items-center justify-between mt-3 text-xs text-muted-foreground">
                    <span>{evalPage * EVAL_PAGE_SIZE + 1}–{Math.min((evalPage + 1) * EVAL_PAGE_SIZE, filteredEvals.length)} of {filteredEvals.length}</span>
                    <div className="flex gap-1">
                      <Button variant="outline" size="sm" className="h-7 px-2 text-xs"
                        disabled={evalPage === 0} onClick={() => setEvalPage(0)}>«</Button>
                      <Button variant="outline" size="sm" className="h-7 px-2 text-xs"
                        disabled={evalPage === 0} onClick={() => setEvalPage(p => p - 1)}>‹</Button>
                      <span className="flex items-center px-2">{evalPage + 1} / {evalPageCount}</span>
                      <Button variant="outline" size="sm" className="h-7 px-2 text-xs"
                        disabled={evalPage >= evalPageCount - 1} onClick={() => setEvalPage(p => p + 1)}>›</Button>
                      <Button variant="outline" size="sm" className="h-7 px-2 text-xs"
                        disabled={evalPage >= evalPageCount - 1} onClick={() => setEvalPage(evalPageCount - 1)}>»</Button>
                    </div>
                  </div>
                )}
              </>
          }
        </CollapsibleCard>
      </SectionBlock>

      {/* ── Artifacts ── */}
      <SectionBlock id="artifacts" kicker="Artifacts" title="Saved Findings"
        description="Confirmed breaches and high-signal attacks. Click any ID to view full evidence in the Regression Library.">
        {data.regressions.length === 0
          ? <Card><CardContent className="p-6"><p className="text-sm text-muted-foreground">No findings yet for this target.</p></CardContent></Card>
          : <Card>
              <CardContent className="p-4">
                <div className="flex flex-wrap gap-2">
                  {(data.regressions as Record<string, unknown>[]).map((r, i) => {
                    const tier = String(r.tier ?? 'keep')
                    const comp = Number(r.composite ?? 0)
                    const attackId = String(r.attack_id ?? '')
                    return (
                      <a key={i} href={`/regressions?search=${encodeURIComponent(attackId)}`}
                        className={cn(
                          'inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md border text-xs font-mono transition-colors hover:bg-muted/50',
                          tier === 'success' ? 'border-red-500/30 bg-red-500/5 text-red-600 dark:text-red-400'
                          : tier === 'partial' ? 'border-amber-500/30 bg-amber-500/5 text-amber-600 dark:text-amber-400'
                          : 'border-border text-muted-foreground',
                        )}
                        title={`${String(r.technique ?? '').replace(/_/g, ' ')} · composite ${comp.toFixed(1)}`}
                      >
                        {attackId}
                        <span className={cn('text-[10px] tabular-nums',
                          comp >= 7 ? 'text-red-500' : comp >= 4 ? 'text-amber-500' : 'text-muted-foreground/60',
                        )}>{comp.toFixed(1)}</span>
                      </a>
                    )
                  })}
                </div>
                <div className="mt-3 pt-2 border-t border-border">
                  <a href={`/regressions?target=${encodeURIComponent(targetId)}`}
                    className="text-xs text-primary hover:underline">
                    View all in Regression Library →
                  </a>
                </div>
              </CardContent>
            </Card>
        }
      </SectionBlock>

      {/* Attack detail modal */}
      {inspectedAttack && (
        <AttackModal detail={inspectedAttack} onClose={() => setInspectedAttack(null)} />
      )}
    </div>
  )
}
