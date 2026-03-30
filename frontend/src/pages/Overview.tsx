import { useState, useMemo } from 'react'
import { useOverview } from '@/hooks/useApi'
import type { TargetSummary } from '@/lib/api'
import { StatCards } from '@/components/StatCards'
import { DataAge } from '@/components/DataAge'
import { Skeleton } from '@/components/ui/skeleton'
import { Card, CardHeader, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { ChevronDown } from 'lucide-react'
import { fmt, cn } from '@/lib/utils'

const OWASP_LABELS: Record<string, string> = {
  LLM01: 'Prompt Injection',
  LLM02: 'Insecure Output Handling',
  LLM03: 'Training Data Poisoning',
  LLM04: 'Model Denial of Service',
  LLM05: 'Supply Chain Vulnerabilities',
  LLM06: 'Sensitive Information Disclosure',
  LLM07: 'Insecure Plugin Design',
  LLM08: 'Excessive Agency',
  LLM09: 'Overreliance',
  LLM10: 'Model Theft',
}

function targetKindLabel(t: TargetSummary): { label: string; color: string } {
  if (t.tags?.includes('ctf')) return { label: 'CTF', color: 'bg-violet-500/15 text-violet-600 dark:text-violet-400' }
  if (t.provider === 'llm') return { label: 'LLM', color: 'bg-blue-500/15 text-blue-600 dark:text-blue-400' }
  if (t.provider === 'http') return { label: 'HTTP', color: 'bg-slate-500/15 text-slate-600 dark:text-slate-400' }
  return { label: '', color: '' }
}

export function Overview() {
  const { data, isLoading, error, refetch, isFetching } = useOverview()
  const [showInfo, setShowInfo] = useState(false)

  // Aggregate OWASP and ATLAS refs across all targets
  const { owaspCounts, atlasCounts } = useMemo(() => {
    const ow: Record<string, number> = {}
    const at: Record<string, number> = {}
    for (const t of data?.targets ?? []) {
      for (const o of t.top_owasp_refs ?? []) ow[o] = (ow[o] ?? 0) + 1
      for (const a of t.top_mitre_atlas ?? []) at[a] = (at[a] ?? 0) + 1
    }
    return { owaspCounts: ow, atlasCounts: at }
  }, [data?.targets])

  if (isLoading) return <div className="grid gap-4"><Skeleton className="h-24" /><Skeleton className="h-64" /></div>
  if (error) return <p className="text-destructive">Failed to load: {error.message}</p>
  if (!data) return null

  const s = data.stats
  const activeTargets = data.targets.filter(t => t.attack_count > 0)
  const owaspSorted = Object.entries(owaspCounts).sort((a, b) => b[1] - a[1])
  const atlasSorted = Object.entries(atlasCounts).sort((a, b) => b[1] - a[1])
  const cards = [
    { label: 'Total Attacks', value: s.total_attacks.toLocaleString() },
    { label: 'Targets', value: `${activeTargets.length} / ${data.target_count}` },
    { label: 'Keep Rate', value: fmt(s.keep_rate * 100, 1) + '%' },
    { label: 'Confirmed Findings', value: s.total_success_findings },
    { label: 'OWASP Refs', value: `${owaspSorted.length} / 10` },
    { label: 'ATLAS Techniques', value: atlasSorted.length },
  ]

  return (
    <div className="grid gap-8">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-xs uppercase tracking-widest text-muted-foreground mb-1">AgentBreaker</p>
          <h1 className="text-3xl font-bold mb-1">Control Plane</h1>
          <p className="text-muted-foreground text-sm">AI security evaluation platform — targets, coverage, findings, and regression corpus.</p>
        </div>
        <DataAge generatedAt={data.generated_at} onRefresh={() => refetch()} isRefetching={isFetching} />
      </div>

      <StatCards cards={cards} />

      {/* Collapsible info cards */}
      <div>
        <button
          onClick={() => setShowInfo(v => !v)}
          className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors mb-3"
        >
          <ChevronDown className={cn('w-3.5 h-3.5 transition-transform', showInfo && 'rotate-180')} />
          {showInfo ? 'Hide' : 'Show'} platform guide
        </button>
        {showInfo && (
          <div className="grid md:grid-cols-3 gap-4">
            <Card>
              <CardHeader className="pb-2"><h3 className="font-semibold text-sm">What AgentBreaker Is</h3></CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                An agentic AI security evaluation tool that autonomously probes LLM-based applications for vulnerabilities across OWASP LLM Top 10 and MITRE ATLAS categories.
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2"><h3 className="font-semibold text-sm">Core Capabilities</h3></CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Profile-based attack generation, autonomous campaign planning, composite scoring, regression corpus building, and real-time evaluation tracking.
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2"><h3 className="font-semibold text-sm">Where To Go</h3></CardHeader>
              <CardContent className="text-sm text-muted-foreground space-y-1">
                <p><strong>Targets</strong> — per-target deep dives and posture</p>
                <p><strong>Coverage & Frameworks</strong> — matrix, MITRE ATLAS, OWASP</p>
                <p><strong>Regressions</strong> — saved high-signal findings</p>
                <p><strong>Operations</strong> — launch scans, manage targets</p>
              </CardContent>
            </Card>
          </div>
        )}
      </div>

      {/* OWASP LLM Top 10 + MITRE ATLAS coverage */}
      {(owaspSorted.length > 0 || atlasSorted.length > 0) && (
        <div className="grid md:grid-cols-2 gap-4">
          {owaspSorted.length > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <h3 className="font-semibold text-sm">OWASP LLM Top 10</h3>
              </CardHeader>
              <CardContent className="space-y-2">
                {owaspSorted.map(([ref, count]) => {
                  const maxCount = owaspSorted[0][1]
                  const pct = (count / maxCount) * 100
                  return (
                    <div key={ref} className="flex items-center gap-3">
                      <span className="text-xs font-mono w-12 shrink-0 text-primary">{ref}</span>
                      <div className="flex-1">
                        <div className="flex items-center justify-between mb-0.5">
                          <span className="text-xs text-muted-foreground">{OWASP_LABELS[ref] ?? ref}</span>
                          <span className="text-[10px] tabular-nums text-muted-foreground/60">{count} target{count > 1 ? 's' : ''}</span>
                        </div>
                        <div className="w-full h-1.5 bg-muted rounded-full overflow-hidden">
                          <div className="h-full rounded-full bg-red-500/60 transition-all" style={{ width: `${pct}%` }} />
                        </div>
                      </div>
                    </div>
                  )
                })}
              </CardContent>
            </Card>
          )}
          {atlasSorted.length > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <h3 className="font-semibold text-sm">MITRE ATLAS</h3>
              </CardHeader>
              <CardContent className="space-y-2">
                {atlasSorted.map(([ref, count]) => {
                  const maxCount = atlasSorted[0][1]
                  const pct = (count / maxCount) * 100
                  return (
                    <div key={ref} className="flex items-center gap-3">
                      <div className="flex-1">
                        <div className="flex items-center justify-between mb-0.5">
                          <span className="text-xs text-muted-foreground">{ref}</span>
                          <span className="text-[10px] tabular-nums text-muted-foreground/60">{count} target{count > 1 ? 's' : ''}</span>
                        </div>
                        <div className="w-full h-1.5 bg-muted rounded-full overflow-hidden">
                          <div className="h-full rounded-full bg-amber-500/60 transition-all" style={{ width: `${pct}%` }} />
                        </div>
                      </div>
                    </div>
                  )
                })}
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {activeTargets.length > 0 && (
        <div>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-lg font-semibold">Active Targets</h2>
            {activeTargets.length > 6 && (
              <Button variant="ghost" size="sm" className="text-xs" asChild>
                <a href="/targets">See all {activeTargets.length} →</a>
              </Button>
            )}
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {activeTargets.slice(0, 6).map((t) => {
              const kl = targetKindLabel(t)
              return (
                <a key={t.target_id} href={`/targets/${encodeURIComponent(t.target_id)}`}
                  className="block p-4 rounded-lg border border-border bg-card hover:border-primary/30 hover:bg-primary/3 transition-colors">
                  <div className="flex items-center gap-2">
                    {kl.label && (
                      <span className={cn('text-[10px] font-semibold px-1.5 py-0.5 rounded', kl.color)}>{kl.label}</span>
                    )}
                    <span className="font-medium text-sm truncate">{t.target_id}</span>
                  </div>
                  <div className="text-xs text-muted-foreground mt-1">
                    Composite {fmt(t.peak_composite)} · {t.attack_count} attacks · {(t.findings as Record<string, number>)?.success ?? 0} findings
                  </div>
                </a>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
