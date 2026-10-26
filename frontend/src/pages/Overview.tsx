import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useWorkspace } from '@/hooks/useApi'
import type { WorkspaceEngine, WorkspaceTarget } from '@/lib/api'
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

const STATUS_LABEL: Record<string, string> = {
  tested: 'Campaign results',
  findings: 'Findings saved',
  configured: 'Waiting for a scan',
}

function targetKindLabel(t: WorkspaceTarget): { label: string; color: string } {
  if (t.tags?.includes('ctf')) return { label: 'CTF', color: 'bg-violet-500/15 text-violet-600 dark:text-violet-400' }
  if (t.provider === 'llm') return { label: 'LLM', color: 'bg-blue-500/15 text-blue-600 dark:text-blue-400' }
  if (t.provider === 'http') return { label: 'HTTP', color: 'bg-slate-500/15 text-slate-600 dark:text-slate-400' }
  if (t.provider === 'script') return { label: 'Script', color: 'bg-amber-500/15 text-amber-700 dark:text-amber-400' }
  return { label: '', color: '' }
}

function engineLine(engine: WorkspaceEngine): string {
  const model = engine.model || 'no model'
  const provider = engine.provider_id || engine.api || 'unset'
  const key = engine.api_key_present ? 'key ready' : `missing ${engine.api_key_env || 'key'}`
  return `${model} · ${provider} · ${key}`
}

export function Overview() {
  const { data, isLoading, error, refetch, isFetching } = useWorkspace()
  const [showInfo, setShowInfo] = useState(false)

  if (isLoading) return <div className="grid gap-4"><Skeleton className="h-24" /><Skeleton className="h-64" /></div>
  if (error) return <p className="text-destructive">Failed to load: {error.message}</p>
  if (!data) return null

  const counts = data.counts
  const owaspSorted = data.frameworks.owasp
  const primary = data.next_actions[0]
  const cards = [
    { label: 'Configured', value: counts.configured, meta: `${counts.tested} with campaign results` },
    { label: 'Findings saved', value: counts.with_findings, meta: `${counts.success_findings} confirmed` },
    { label: 'Confirmed findings', value: counts.success_findings },
    { label: 'Partial findings', value: counts.partial_findings },
    { label: 'Campaign attacks', value: counts.attacks.toLocaleString() },
    { label: 'OWASP refs', value: `${owaspSorted.length} / 10` },
  ]

  return (
    <div className="grid gap-8">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-xs uppercase tracking-widest text-muted-foreground mb-1">AgentBreaker</p>
          <h1 className="text-3xl font-bold mb-1">Workspace</h1>
          <p className="text-muted-foreground text-sm">{data.headline}</p>
        </div>
        <DataAge generatedAt={data.generated_at} onRefresh={() => refetch()} isRefetching={isFetching} />
      </div>

      <Card className={data.ready ? 'border-primary/30' : 'border-amber-500/40'}>
        <CardContent className="p-4 grid gap-3 md:grid-cols-[1fr_auto] md:items-center">
          <div className="grid gap-2">
            <p className="text-sm font-semibold">{data.ready ? 'Ready to scan' : 'Setup still blocks a scan'}</p>
            <p className="text-xs text-muted-foreground">Judge: {engineLine(data.engines.judge)}</p>
            <p className="text-xs text-muted-foreground">Generator: {engineLine(data.engines.generator)}</p>
            {data.blocking.length > 0 && (
              <ul className="text-xs text-muted-foreground list-disc pl-4">
                {data.blocking.map((item) => <li key={item}>{item}</li>)}
              </ul>
            )}
          </div>
          {primary && (
            <Button asChild>
              <Link to={primary.href}>{primary.title}</Link>
            </Button>
          )}
        </CardContent>
      </Card>

      <StatCards cards={cards} />

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
                An agentic AI security evaluation tool that probes authorized LLM applications across OWASP LLM Top 10 and MITRE ATLAS categories.
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2"><h3 className="font-semibold text-sm">What this page shows</h3></CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Every system in target_config.yaml, whether a campaign ledger exists, and saved findings. A system stays visible before its first scan.
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2"><h3 className="font-semibold text-sm">Where To Go</h3></CardHeader>
              <CardContent className="text-sm text-muted-foreground space-y-1">
                <p><strong>Operations</strong> — models, keys, and scans</p>
                <p><strong>Targets</strong> — per-target posture</p>
                <p><strong>Regressions</strong> — saved findings</p>
                <p><strong>Coverage & Frameworks</strong> — matrix, MITRE ATLAS, OWASP</p>
              </CardContent>
            </Card>
          </div>
        )}
      </div>

      {data.next_actions.length > 1 && (
        <div className="grid md:grid-cols-2 gap-3">
          {data.next_actions.slice(1).map((action) => (
            <Link key={action.id} to={action.href} className="block p-4 rounded-lg border border-border bg-card hover:border-primary/30">
              <p className="text-sm font-medium">{action.title}</p>
              <p className="text-xs text-muted-foreground mt-1">{action.detail}</p>
            </Link>
          ))}
        </div>
      )}

      {owaspSorted.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <h3 className="font-semibold text-sm">OWASP LLM Top 10 in saved findings</h3>
          </CardHeader>
          <CardContent className="space-y-2">
            {owaspSorted.map((item) => {
              const maxCount = owaspSorted[0].target_count || 1
              const pct = (item.target_count / maxCount) * 100
              return (
                <div key={item.ref} className="flex items-center gap-3">
                  <span className="text-xs font-mono w-12 shrink-0 text-primary">{item.ref}</span>
                  <div className="flex-1">
                    <div className="flex items-center justify-between mb-0.5">
                      <span className="text-xs text-muted-foreground">{OWASP_LABELS[item.ref] ?? item.ref}</span>
                      <span className="text-[10px] tabular-nums text-muted-foreground/60">{item.target_count} target{item.target_count > 1 ? 's' : ''}</span>
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

      <div>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-lg font-semibold">Configured targets</h2>
          <Button variant="ghost" size="sm" className="text-xs" asChild>
            <Link to="/targets">Open targets</Link>
          </Button>
        </div>
        {data.targets.length === 0 ? (
          <p className="text-sm text-muted-foreground">No targets are in the config yet.</p>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {data.targets.map((t) => {
              const kind = targetKindLabel(t)
              return (
                <Link key={t.target_id} to={`/targets/${encodeURIComponent(t.target_id)}`}
                  className="block p-4 rounded-lg border border-border bg-card hover:border-primary/30 transition-colors">
                  <div className="flex items-center gap-2">
                    {kind.label && (
                      <span className={cn('text-[10px] font-semibold px-1.5 py-0.5 rounded', kind.color)}>{kind.label}</span>
                    )}
                    <span className="font-medium text-sm truncate">{t.target_id}</span>
                  </div>
                  <div className="text-xs text-muted-foreground mt-1">
                    {STATUS_LABEL[t.status] ?? t.status}
                    {t.model ? ` · ${t.model}` : ''}
                  </div>
                  <div className="text-xs text-muted-foreground mt-1">
                    {t.findings.success} findings · {t.attack_count} attacks
                    {t.peak_composite > 0 ? ` · peak ${fmt(t.peak_composite)}` : ''}
                  </div>
                </Link>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}
