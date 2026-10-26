import { useState, useMemo } from 'react'
import { Link } from 'react-router-dom'
import { useWorkspace } from '@/hooks/useApi'
import type { WorkspaceTarget } from '@/lib/api'
import { StatCards } from '@/components/StatCards'
import { HorizBarChart } from '@/components/charts/HorizBarChart'
import { DataAge } from '@/components/DataAge'
import { RiskBadge } from '@/components/RiskBadge'
import { Skeleton } from '@/components/ui/skeleton'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { cn, fmt } from '@/lib/utils'
import { Flag, Bot, Globe, Monitor, Eye, MessageSquare, Wrench, FileText, Volume2 } from 'lucide-react'

// ── Type helpers ─────────────────────────────────────────────────────────────

type TargetKind = 'ctf' | 'llm' | 'http' | 'browser' | 'unknown'

function targetKind(t: WorkspaceTarget): TargetKind {
  if (t.tags?.includes('ctf')) return 'ctf'
  if (t.provider === 'llm') return 'llm'
  if (t.provider === 'http') return 'http'
  if (t.provider === 'browser') return 'browser'
  return 'unknown'
}

const KIND_CONFIG: Record<TargetKind, { label: string; color: string; icon: typeof Bot }> = {
  ctf:     { label: 'CTF',     color: 'bg-violet-500/15 text-violet-600 dark:text-violet-400 border-violet-500/30', icon: Flag },
  llm:     { label: 'LLM',     color: 'bg-blue-500/15 text-blue-600 dark:text-blue-400 border-blue-500/30',         icon: Bot },
  http:    { label: 'HTTP',    color: 'bg-slate-500/15 text-slate-600 dark:text-slate-400 border-slate-500/30',     icon: Globe },
  browser: { label: 'Browser', color: 'bg-teal-500/15 text-teal-600 dark:text-teal-400 border-teal-500/30',        icon: Monitor },
  unknown: { label: 'Target',  color: 'bg-muted text-muted-foreground border-border',                               icon: Globe },
}

function TypeBadge({ kind }: { kind: TargetKind }) {
  const cfg = KIND_CONFIG[kind]
  const Icon = cfg.icon
  return (
    <span className={cn('inline-flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5 rounded border', cfg.color)}>
      <Icon className="w-3 h-3" />
      {cfg.label}
    </span>
  )
}

// ── Capability pills ─────────────────────────────────────────────────────────

const CAP_ICONS: Record<string, { label: string; icon: typeof Eye }> = {
  has_vision:     { label: 'Vision',     icon: Eye },
  has_multi_turn: { label: 'Multi-turn', icon: MessageSquare },
  has_tools:      { label: 'Tools',      icon: Wrench },
  has_document:   { label: 'Document',   icon: FileText },
  has_audio:      { label: 'Audio',      icon: Volume2 },
}

function CapabilityPills({ capabilities }: { capabilities?: Record<string, unknown> }) {
  if (!capabilities) return null
  const active = Object.entries(CAP_ICONS).filter(([key]) => capabilities[key] === true)
  if (active.length === 0) return null
  return (
    <div className="flex flex-wrap gap-1">
      {active.map(([key, { label, icon: Icon }]) => (
        <span key={key} className="inline-flex items-center gap-0.5 text-[9px] px-1 py-0.5 rounded bg-muted text-muted-foreground">
          <Icon className="w-2.5 h-2.5" />
          {label}
        </span>
      ))}
    </div>
  )
}

// ── Risk helper ──────────────────────────────────────────────────────────────

function riskLevel(composite: number): 'high' | 'medium' | 'low' {
  if (composite >= 7) return 'high'
  if (composite >= 4) return 'medium'
  return 'low'
}

// ── Target card ──────────────────────────────────────────────────────────────

function TargetCard({ t }: { t: WorkspaceTarget }) {
  const kind = targetKind(t)

  return (
    <Link to={`/targets/${encodeURIComponent(t.target_id)}`} className="block">
      <Card className="h-full hover:border-primary/30 hover:bg-primary/3 transition-colors">
        <CardContent className="p-4 flex flex-col gap-2 h-full">
          {/* Row 1: risk badge + type badge + target name */}
          <div className="flex items-center gap-2">
            <RiskBadge level={riskLevel(t.peak_composite)} className="shrink-0" />
            <TypeBadge kind={kind} />
            <span className="font-semibold truncate">{t.target_id}</span>
          </div>

          <p className="text-[11px] text-muted-foreground">
            {t.status === 'tested' && 'Campaign results on disk'}
            {t.status === 'findings' && 'Findings saved'}
            {t.status === 'configured' && 'Waiting for a scan'}
            {t.model ? ` · ${t.model}` : ''}
          </p>

          {/* Row 3: stats */}
          <div className="flex gap-3 text-xs text-muted-foreground">
            <span>Composite <strong className="text-foreground">{fmt(t.peak_composite)}</strong></span>
            <span>Attacks <strong className="text-foreground">{t.attack_count}</strong></span>
            <span>Findings <strong className="text-foreground">{t.findings.success}</strong></span>
          </div>

          {/* Row 4: capabilities */}
          <CapabilityPills capabilities={t.capabilities} />

          {/* Row 5: categories */}
          {(t.top_categories?.length ?? 0) > 0 && (
            <div className="flex flex-wrap gap-1 mt-auto pt-1">
              {t.top_categories.slice(0, 4).map((c) => (
                <Badge key={c} variant="secondary" className="text-xs">{c}</Badge>
              ))}
              {t.top_categories.length > 4 && (
                <Badge variant="outline" className="text-xs">+{t.top_categories.length - 4}</Badge>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </Link>
  )
}

// ── Main page ────────────────────────────────────────────────────────────────

export function Targets() {
  const { data, isLoading, error, refetch, isFetching } = useWorkspace()
  const [search, setSearch] = useState('')
  const [filterKind, setFilterKind] = useState<TargetKind | 'all'>('all')

  const filteredTargets = useMemo(() => {
    if (!data) return []
    const q = search.toLowerCase()
    return data.targets
      .filter(t => !q || t.target_id.toLowerCase().includes(q))
      .filter(t => filterKind === 'all' || targetKind(t) === filterKind)
  }, [data, search, filterKind])

  // Count by kind for filter tabs
  const kindCounts = useMemo(() => {
    if (!data) return {} as Record<string, number>
    const counts: Record<string, number> = { all: data.targets.length }
    for (const t of data.targets) {
      const k = targetKind(t)
      counts[k] = (counts[k] ?? 0) + 1
    }
    return counts
  }, [data])

  if (isLoading) return <div className="grid gap-4"><Skeleton className="h-24" /><Skeleton className="h-64" /></div>
  if (error) return <p className="text-destructive">Failed to load: {error.message}</p>
  if (!data) return null

  const counts = data.counts
  const cards = [
    { label: 'Targets', value: counts.configured },
    { label: 'With findings', value: counts.with_findings },
    { label: 'Campaign attacks', value: counts.attacks.toLocaleString() },
    { label: 'Waiting', value: counts.configured - counts.with_findings },
    { label: 'Findings', value: counts.success_findings },
    { label: 'Partial', value: counts.partial_findings },
  ]

  const chartData = data.targets
    .filter((t) => t.peak_composite > 0)
    .sort((a, b) => b.peak_composite - a.peak_composite)
    .map((t) => ({ label: t.target_id, value: t.peak_composite }))

  return (
    <div className="grid gap-8">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-xs uppercase tracking-widest text-muted-foreground mb-1">Targets</p>
          <h1 className="text-3xl font-bold mb-1">Configured targets</h1>
          <p className="text-muted-foreground text-sm">Every system in the config, including ones still waiting for a scan. Finding counts come from saved finding files.</p>
        </div>
        <DataAge generatedAt={data.generated_at} onRefresh={() => refetch()} isRefetching={isFetching} />
      </div>

      <StatCards cards={cards} />

      {chartData.length > 0 && (
        <div>
          <h2 className="text-lg font-semibold mb-3">Risk by Target (Peak Composite)</h2>
          <Card>
            <CardContent className="pt-4">
              <HorizBarChart data={chartData} maxValue={10} formatValue={(v) => v.toFixed(2)} />
            </CardContent>
          </Card>
        </div>
      )}

      {/* Search + kind filter */}
      <div className="flex items-center gap-3 flex-wrap">
        <Input
          placeholder="Search targets…"
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="max-w-xs"
        />
        <div className="flex items-center gap-1 bg-muted/40 p-0.5 rounded-md border border-border/50">
          {(['all', 'llm', 'ctf', 'http'] as const).map(k => {
            const count = kindCounts[k] ?? 0
            if (k !== 'all' && count === 0) return null
            const label = k === 'all' ? 'All' : k.toUpperCase()
            return (
              <button
                key={k}
                onClick={() => setFilterKind(k)}
                className={cn(
                  'text-[11px] px-2.5 py-1 rounded-sm font-medium transition-colors',
                  filterKind === k
                    ? 'bg-background shadow-sm text-foreground'
                    : 'text-muted-foreground hover:text-foreground',
                )}
              >
                {label} <span className="text-muted-foreground/60 tabular-nums">{count}</span>
              </button>
            )
          })}
        </div>
        {search && (
          <span className="text-xs text-muted-foreground">
            {filteredTargets.length} result{filteredTargets.length !== 1 ? 's' : ''}
          </span>
        )}
      </div>

      {filteredTargets.length > 0 ? (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredTargets.map((t) => <TargetCard key={t.target_id} t={t} />)}
        </div>
      ) : (
        <p className="text-sm text-muted-foreground">No targets match this filter.</p>
      )}
    </div>
  )
}
