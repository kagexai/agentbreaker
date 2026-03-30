import { useState, useMemo, useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useRegressions } from '@/hooks/useApi'
import { StatCards } from '@/components/StatCards'
import { DataAge } from '@/components/DataAge'
import { Skeleton } from '@/components/ui/skeleton'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { ChevronDown, ChevronRight, LayoutList, Table2, Download, Copy, Check } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { RegressionEntry } from '@/lib/api'

function downloadCSV(entries: RegressionEntry[]) {
  const cols: (keyof RegressionEntry)[] = ['target_id', 'attack_id', 'tier', 'category', 'technique', 'composite', 'asr', 'breach_detected', 'owasp_ref', 'benchmark_ref', 'path']
  const header = cols.join(',')
  const rows = entries.map(e => cols.map(c => JSON.stringify(e[c] ?? '')).join(','))
  const csv = [header, ...rows].join('\n')
  const blob = new Blob([csv], { type: 'text/csv' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `regressions-${new Date().toISOString().slice(0, 10)}.csv`
  a.click()
  URL.revokeObjectURL(url)
}

// ── Types ─────────────────────────────────────────────────────────────────────

const TIERS = ['all', 'success', 'partial', 'keep'] as const
type TierFilter = typeof TIERS[number]
type SortKey = 'composite' | 'asr' | 'technique' | 'target' | 'category'
type ViewMode = 'cards' | 'table'

// ── Shared styling ─────────────────────────────────────────────────────────────

const tierStyle: Record<string, string> = {
  success: 'bg-destructive/15 text-destructive border-destructive/20',
  partial: 'bg-orange-500/15 text-orange-600 border-orange-500/20',
  keep:    'bg-muted text-muted-foreground border-border',
}

function TierBadge({ tier }: { tier: string }) {
  return (
    <Badge variant="outline" className={cn('text-xs font-semibold shrink-0', tierStyle[tier] ?? tierStyle.keep)}>
      {tier}
    </Badge>
  )
}

// ── Copy button ───────────────────────────────────────────────────────────────

function CopyBtn({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    })
  }, [text])
  return (
    <button
      onClick={handleCopy}
      className="shrink-0 p-1 rounded hover:bg-muted transition-colors text-muted-foreground/50 hover:text-muted-foreground"
      title="Copy to clipboard"
    >
      {copied ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
    </button>
  )
}

// ── Evidence block ────────────────────────────────────────────────────────────

function EvidenceBlock({ label, text, variant = 'default' }: {
  label: string
  text: string
  variant?: 'default' | 'payload' | 'response'
}) {
  const bgColor = variant === 'payload' ? 'bg-blue-500/5 border-blue-500/20'
    : variant === 'response' ? 'bg-amber-500/5 border-amber-500/20'
    : 'bg-background border-border'
  const labelColor = variant === 'payload' ? 'text-blue-600 dark:text-blue-400'
    : variant === 'response' ? 'text-amber-600 dark:text-amber-400'
    : 'text-muted-foreground'
  return (
    <div>
      <div className="flex items-center justify-between mb-1.5">
        <p className={cn('text-[10px] uppercase tracking-wider font-semibold', labelColor)}>{label}</p>
        <CopyBtn text={text} />
      </div>
      <pre className={cn(
        'text-xs p-3 rounded-lg border overflow-x-auto whitespace-pre-wrap max-h-[600px] overflow-y-auto leading-relaxed font-mono',
        bgColor,
        variant === 'response' ? 'text-foreground' : 'text-muted-foreground',
      )}>{text}</pre>
    </div>
  )
}

// ── Card view row ─────────────────────────────────────────────────────────────

function EntryCard({ entry, defaultOpen }: { entry: RegressionEntry; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen ?? false)
  const hasDetail = !!(entry.payload_preview || entry.response_excerpt)
  const isBreach = entry.breach_detected
  const isHighSignal = entry.composite >= 7

  return (
    <div className={cn(
      'border rounded-lg overflow-hidden transition-colors',
      isBreach ? 'border-destructive/30 bg-destructive/[0.02]'
        : isHighSignal ? 'border-orange-500/30 bg-orange-500/[0.02]'
        : 'border-border',
    )}>
      {/* Header */}
      <div className="p-4 grid gap-2">
        <div className="flex items-start justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-2 flex-wrap">
            <TierBadge tier={entry.tier} />
            {isBreach && <Badge className="text-xs bg-destructive text-destructive-foreground">Breach</Badge>}
            <span className="font-semibold text-sm">{(entry.technique || entry.category).replace(/_/g, ' ')}</span>
          </div>
          <div className="flex items-center gap-4 shrink-0">
            <div className="text-right">
              <span className={cn(
                'text-lg font-bold tabular-nums',
                entry.composite >= 7 ? 'text-red-500' : entry.composite >= 4 ? 'text-amber-500' : 'text-muted-foreground',
              )}>{entry.composite.toFixed(1)}</span>
              <span className="text-[10px] text-muted-foreground block">composite</span>
            </div>
            {entry.asr > 0 && (
              <div className="text-right">
                <span className="text-lg font-bold tabular-nums text-red-500">{entry.asr.toFixed(2)}</span>
                <span className="text-[10px] text-muted-foreground block">ASR</span>
              </div>
            )}
          </div>
        </div>
        <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
          <span>
            <span className="uppercase tracking-wide">Target </span>
            <a href={`/targets/${encodeURIComponent(entry.target_id)}`} className="text-primary hover:underline font-medium">{entry.target_id}</a>
          </span>
          {entry.category && entry.category !== entry.technique && (
            <span><span className="uppercase tracking-wide">Category </span>{entry.category.replace(/_/g, ' ')}</span>
          )}
          {entry.owasp_ref && <span className="font-mono">{entry.owasp_ref}</span>}
          {entry.benchmark_ref && <span className="font-mono">{entry.benchmark_ref}</span>}
          <span className="font-mono text-muted-foreground/50">{entry.attack_id}</span>
        </div>

        {/* Inline response preview (always visible for breaches/high-signal) */}
        {!open && entry.response_excerpt && (isBreach || isHighSignal) && (
          <div className="mt-1">
            <p className={cn(
              'text-xs font-mono line-clamp-3 leading-relaxed rounded-md px-2.5 py-1.5',
              isBreach ? 'bg-destructive/5 text-foreground' : 'bg-amber-500/5 text-foreground',
            )}>{entry.response_excerpt}</p>
          </div>
        )}
      </div>

      {/* Expand / collapse */}
      {hasDetail && (
        <>
          <div className="border-t border-border/50">
            <button onClick={() => setOpen(o => !o)}
              className="w-full flex items-center gap-1.5 px-4 py-2 text-xs text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-colors">
              {open ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
              {open ? 'Collapse' : 'Expand'} full evidence
            </button>
          </div>
          {open && (
            <div className="border-t border-border/50 bg-muted/10 p-4 grid gap-4">
              {entry.path && (
                <div className="flex items-center gap-2">
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold">File</p>
                  <code className="text-xs text-muted-foreground font-mono break-all">{entry.path}</code>
                </div>
              )}
              {entry.payload_preview && (
                <EvidenceBlock label="Attack Payload" text={entry.payload_preview} variant="payload" />
              )}
              {entry.response_excerpt && (
                <EvidenceBlock label="Model Response" text={entry.response_excerpt} variant="response" />
              )}
            </div>
          )}
        </>
      )}
    </div>
  )
}

// ── Table view row ─────────────────────────────────────────────────────────────

function EntryTableRow({ entry }: { entry: RegressionEntry }) {
  const [open, setOpen] = useState(false)
  const hasDetail = !!(entry.payload_preview || entry.response_excerpt)
  return (
    <>
      <tr className={cn(
        'hover:bg-muted/20 transition-colors border-b border-border text-sm cursor-pointer',
        entry.breach_detected && 'bg-destructive/[0.02]',
      )}
        onClick={() => hasDetail && setOpen(o => !o)}
      >
        <td className="px-3 py-2"><TierBadge tier={entry.tier} /></td>
        <td className="px-3 py-2">
          <div className="flex items-center gap-1.5">
            {entry.breach_detected && <span className="w-1.5 h-1.5 rounded-full bg-destructive shrink-0" title="Breach" />}
            <a href={`/targets/${encodeURIComponent(entry.target_id)}`} className="text-primary hover:underline text-xs"
              onClick={e => e.stopPropagation()}>{entry.target_id}</a>
          </div>
        </td>
        <td className="px-3 py-2 text-xs text-muted-foreground">{entry.category.replace(/_/g, ' ')}</td>
        <td className="px-3 py-2 max-w-[180px]">
          <span className="text-xs truncate block" title={entry.technique}>{entry.technique.replace(/_/g, ' ')}</span>
        </td>
        <td className={cn(
          'px-3 py-2 text-right font-mono text-xs tabular-nums font-semibold',
          entry.composite >= 7 ? 'text-red-500' : entry.composite >= 4 ? 'text-amber-500' : '',
        )}>{entry.composite.toFixed(2)}</td>
        <td className={cn(
          'px-3 py-2 text-right font-mono text-xs tabular-nums',
          entry.asr > 0 && 'text-red-500 font-semibold',
        )}>{entry.asr.toFixed(2)}</td>
        <td className="px-3 py-2 text-xs font-mono text-muted-foreground/60">{entry.owasp_ref}</td>
        <td className="px-3 py-2">
          {hasDetail && (
            <span className="text-xs text-primary whitespace-nowrap">
              {open ? '▾' : '▸'}
            </span>
          )}
        </td>
      </tr>
      {open && hasDetail && (
        <tr className="border-b border-border bg-muted/10">
          <td colSpan={8} className="p-4">
            <div className="grid gap-4">
              {entry.path && (
                <div className="flex items-center gap-2">
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold">File</p>
                  <code className="text-xs text-muted-foreground font-mono break-all">{entry.path}</code>
                </div>
              )}
              <div className="grid lg:grid-cols-2 gap-4">
                {entry.payload_preview && (
                  <EvidenceBlock label="Attack Payload" text={entry.payload_preview} variant="payload" />
                )}
                {entry.response_excerpt && (
                  <EvidenceBlock label="Model Response" text={entry.response_excerpt} variant="response" />
                )}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export function Regressions() {
  const [searchParams] = useSearchParams()
  const { data, isLoading, error, refetch, isFetching } = useRegressions()
  const [search, setSearch] = useState(searchParams.get('search') ?? '')
  const [tierFilter, setTierFilter] = useState<TierFilter>('all')
  const [categoryFilter, setCategoryFilter] = useState('all')
  const [targetFilter, setTargetFilter] = useState(searchParams.get('target') ?? 'all')
  const [sortKey, setSortKey] = useState<SortKey>('composite')
  const [sortDir, setSortDir] = useState<'desc' | 'asc'>('desc')
  const [dedupe, setDedupe] = useState(false)
  const [view, setView] = useState<ViewMode>('cards')

  const entries = useMemo(() => data?.entries ?? [], [data])
  const allCategories = useMemo(() => [...new Set(entries.map(e => e.category))].sort(), [entries])
  const allTargets = useMemo(() => [...new Set(entries.map(e => e.target_id))].sort(), [entries])

  const filtered = useMemo(() => {
    let result = entries.filter(e => {
      if (tierFilter !== 'all' && e.tier !== tierFilter) return false
      if (categoryFilter !== 'all' && e.category !== categoryFilter) return false
      if (targetFilter !== 'all' && e.target_id !== targetFilter) return false
      if (search) {
        const q = search.toLowerCase()
        return [e.attack_id, e.technique, e.category, e.owasp_ref, e.benchmark_ref, e.target_id,
          e.payload_preview, e.response_excerpt]
          .join(' ').toLowerCase().includes(q)
      }
      return true
    })

    if (dedupe) {
      const seen = new Set<string>()
      result = result.filter(e => {
        const key = `${e.target_id}::${e.category}::${e.technique}`
        if (seen.has(key)) return false
        seen.add(key)
        return true
      })
    }

    result = [...result].sort((a, b) => {
      let va: string | number, vb: string | number
      if (sortKey === 'composite') { va = a.composite; vb = b.composite }
      else if (sortKey === 'asr') { va = a.asr; vb = b.asr }
      else if (sortKey === 'technique') { va = a.technique; vb = b.technique }
      else if (sortKey === 'target') { va = a.target_id; vb = b.target_id }
      else { va = a.category; vb = b.category }
      if (typeof va === 'string') return sortDir === 'desc' ? vb.toString().localeCompare(va) : va.localeCompare(vb.toString())
      return sortDir === 'desc' ? (vb as number) - (va as number) : (va as number) - (vb as number)
    })

    return result
  }, [entries, tierFilter, categoryFilter, targetFilter, search, dedupe, sortKey, sortDir])

  if (isLoading) return <div className="grid gap-4"><Skeleton className="h-24" /><Skeleton className="h-96" /></div>
  if (error) return <p className="text-destructive">Failed to load: {error.message}</p>
  if (!data) return null

  const byTier = (t: string) => entries.filter(e => e.tier === t).length
  const breachCount = entries.filter(e => e.breach_detected).length
  const uniqueTargets = new Set(entries.map(e => e.target_id)).size
  const uniqueStrategies = new Set(entries.map(e => e.technique)).size

  const cards = [
    { label: 'Findings', value: entries.length },
    { label: 'Breaches', value: breachCount },
    { label: 'Confirmed', value: byTier('success') },
    { label: 'Partial', value: byTier('partial') },
    { label: 'Targets Hit', value: uniqueTargets },
    { label: 'Strategies', value: uniqueStrategies },
  ]

  function toggleSort(key: SortKey) {
    if (sortKey === key) setSortDir(d => d === 'desc' ? 'asc' : 'desc')
    else { setSortKey(key); setSortDir('desc') }
  }

  const SortBtn = ({ col, label }: { col: SortKey; label: string }) => (
    <button onClick={() => toggleSort(col)}
      className={cn('hover:text-foreground transition-colors', sortKey === col ? 'text-foreground font-semibold' : 'text-muted-foreground')}>
      {label}{sortKey === col ? (sortDir === 'desc' ? ' ↓' : ' ↑') : ''}
    </button>
  )

  return (
    <div className="grid gap-8">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-xs uppercase tracking-widest text-muted-foreground mb-1">Regressions</p>
          <h1 className="text-3xl font-bold mb-1">Regression Library</h1>
          <p className="text-muted-foreground text-sm">Confirmed findings and high-signal attack results across all targets and campaigns.</p>
        </div>
        <DataAge generatedAt={data.generated_at} onRefresh={() => refetch()} isRefetching={isFetching} />
      </div>

      <StatCards cards={cards} />

      {/* Filters row */}
      <div className="flex flex-wrap gap-2 items-center">
        {/* Tier tabs */}
        <div className="flex gap-1 p-1 rounded-lg bg-muted">
          {TIERS.map(t => (
            <Button key={t} variant="ghost" size="sm" onClick={() => setTierFilter(t)}
              className={cn('h-7 px-3 text-xs capitalize', tierFilter === t && 'bg-background shadow-sm text-foreground')}>
              {t}{t !== 'all' && <span className="ml-1 opacity-60">{byTier(t)}</span>}
            </Button>
          ))}
        </div>

        <Select value={categoryFilter} onValueChange={setCategoryFilter}>
          <SelectTrigger className="h-8 text-xs w-[160px]"><SelectValue placeholder="Category" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All categories</SelectItem>
            {allCategories.map(c => <SelectItem key={c} value={c}>{c.replace(/_/g, ' ')}</SelectItem>)}
          </SelectContent>
        </Select>

        <Select value={targetFilter} onValueChange={setTargetFilter}>
          <SelectTrigger className="h-8 text-xs w-[160px]"><SelectValue placeholder="Target" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All targets</SelectItem>
            {allTargets.map(t => <SelectItem key={t} value={t}>{t}</SelectItem>)}
          </SelectContent>
        </Select>

        <Input placeholder="Search payloads, responses, techniques…" value={search} onChange={e => setSearch(e.target.value)} className="h-8 max-w-[280px] text-xs" />

        <Button variant={dedupe ? 'default' : 'outline'} size="sm" className="h-8 text-xs"
          onClick={() => setDedupe(v => !v)}>
          {dedupe ? 'Unique only' : 'Show dupes'}
        </Button>

        <div className="ml-auto flex items-center gap-2">
          <span className="text-xs text-muted-foreground">{filtered.length} of {entries.length}</span>
          <Button variant="outline" size="sm" className="h-8 text-xs gap-1.5"
            onClick={() => downloadCSV(filtered)}>
            <Download className="w-3 h-3" />CSV
          </Button>
          <div className="flex gap-1 p-0.5 rounded bg-muted">
            <Button variant="ghost" size="sm" className={cn('h-6 w-6 p-0', view === 'cards' && 'bg-background shadow-sm')}
              onClick={() => setView('cards')}><LayoutList className="w-3.5 h-3.5" /></Button>
            <Button variant="ghost" size="sm" className={cn('h-6 w-6 p-0', view === 'table' && 'bg-background shadow-sm')}
              onClick={() => setView('table')}><Table2 className="w-3.5 h-3.5" /></Button>
          </div>
        </div>
      </div>

      {/* Content */}
      {filtered.length === 0 ? (
        <p className="text-sm text-muted-foreground py-12 text-center">No entries match your filters.</p>
      ) : view === 'table' ? (
        <div className="overflow-auto rounded-lg border border-border">
          <table className="w-full text-xs border-collapse">
            <thead>
              <tr className="bg-muted/50 text-left border-b border-border">
                <th className="px-3 py-2 font-medium">Tier</th>
                <th className="px-3 py-2 font-medium"><SortBtn col="target" label="Target" /></th>
                <th className="px-3 py-2 font-medium"><SortBtn col="category" label="Category" /></th>
                <th className="px-3 py-2 font-medium"><SortBtn col="technique" label="Technique" /></th>
                <th className="px-3 py-2 font-medium text-right"><SortBtn col="composite" label="Composite" /></th>
                <th className="px-3 py-2 font-medium text-right"><SortBtn col="asr" label="ASR" /></th>
                <th className="px-3 py-2 font-medium">OWASP</th>
                <th className="px-3 py-2 w-8" />
              </tr>
            </thead>
            <tbody>
              {filtered.map(entry => (
                <EntryTableRow key={`${entry.target_id}::${entry.attack_id}`} entry={entry} />
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="grid gap-3">
          {filtered.map(entry => (
            <EntryCard key={`${entry.target_id}::${entry.attack_id}`} entry={entry} />
          ))}
        </div>
      )}
    </div>
  )
}
