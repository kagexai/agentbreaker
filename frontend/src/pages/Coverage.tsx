import { useState, useMemo } from 'react'
import { useCoverage, useAtlas, useOwasp } from '@/hooks/useApi'
import { StatCards } from '@/components/StatCards'
import { HorizBarChart } from '@/components/charts/HorizBarChart'
import { DataAge } from '@/components/DataAge'
import { Skeleton } from '@/components/ui/skeleton'
import { Card, CardContent, CardHeader } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { RiskBadge } from '@/components/RiskBadge'
import { fmt, cn } from '@/lib/utils'
import { ArrowUpDown, ArrowUp, ArrowDown } from 'lucide-react'

// ── Coverage Matrix helpers ────────────────────────────────────────────────────

function scoreColorClass(composite: number): string {
  if (composite <= 0) return 'bg-emerald-500/15'
  if (composite < 3)  return 'bg-emerald-500/25'
  if (composite < 5)  return 'bg-amber-500/25'
  if (composite < 7)  return 'bg-orange-500/30'
  return 'bg-red-500/35'
}

function scoreTextClass(composite: number): string {
  if (composite <= 0) return 'text-emerald-700 dark:text-emerald-400'
  if (composite < 3)  return 'text-emerald-700 dark:text-emerald-300'
  if (composite < 5)  return 'text-amber-700 dark:text-amber-300'
  if (composite < 7)  return 'text-orange-700 dark:text-orange-300'
  return 'text-red-700 dark:text-red-300'
}

type StatusType = 'validated' | 'tested' | 'coverage_gap' | 'untested'

const STATUS_LABEL: Record<StatusType, string> = {
  validated: 'validated', tested: 'tested', coverage_gap: 'gap', untested: 'untested',
}

const STATUS_TEXT_CLASS: Record<StatusType, string> = {
  validated: 'text-emerald-600 dark:text-emerald-400',
  tested: 'text-blue-600 dark:text-blue-400',
  coverage_gap: 'text-orange-600 dark:text-orange-400',
  untested: 'text-muted-foreground/30',
}

// Used only by Legend
const STATUS_DOT_CLASS: Record<StatusType, string> = {
  validated: 'bg-emerald-500',
  tested: 'bg-blue-500',
  coverage_gap: 'bg-orange-500',
  untested: 'bg-muted-foreground/30',
}

interface CellData { status: string; max_composite: number; attempts: number; keep_count: number }

function matrixCellProps(cell: CellData | undefined): {
  tdClass?: string
  content: React.ReactNode
} {
  if (!cell) return { content: <span className="text-muted-foreground/20 text-xs select-none">—</span> }

  if (cell.max_composite > 0) {
    return {
      tdClass: scoreColorClass(cell.max_composite),
      content: (
        <span className={cn('font-mono font-semibold text-xs tabular-nums', scoreTextClass(cell.max_composite))}>
          {cell.max_composite.toFixed(1)}
        </span>
      ),
    }
  }

  const s = cell.status as StatusType
  if (s === 'untested') {
    return { content: <span className="text-muted-foreground/20 text-xs select-none">—</span> }
  }
  return {
    content: <span className={cn('text-xs font-medium', STATUS_TEXT_CLASS[s])}>{STATUS_LABEL[s]}</span>,
  }
}

type SortDir = 'asc' | 'desc'
interface SortState { col: string; dir: SortDir }

function SortIcon({ col, sort }: { col: string; sort: SortState | null }) {
  if (!sort || sort.col !== col) return <ArrowUpDown className="w-2.5 h-2.5 opacity-25 shrink-0" />
  return sort.dir === 'desc'
    ? <ArrowDown className="w-2.5 h-2.5 opacity-60 shrink-0" />
    : <ArrowUp className="w-2.5 h-2.5 opacity-60 shrink-0" />
}

function MatrixLegend() {
  return (
    <div className="flex flex-wrap items-center gap-4 text-xs text-muted-foreground">
      {(['validated', 'tested', 'coverage_gap'] as const).map(s => (
        <span key={s} className="flex items-center gap-1.5">
          <span className={cn('inline-block w-2 h-2 rounded-full', STATUS_DOT_CLASS[s])} />
          {STATUS_LABEL[s]}
        </span>
      ))}
      <span className="flex items-center gap-1.5">
        <span className="text-muted-foreground/30">—</span>
        untested / no data
      </span>
      <span className="flex items-center gap-1.5">
        <span className="inline-flex gap-px">
          {['bg-emerald-500/25', 'bg-amber-500/25', 'bg-orange-500/30', 'bg-red-500/35'].map((c, i) => (
            <span key={i} className={cn('inline-block w-4 h-3 rounded-sm', c)} />
          ))}
        </span>
        low → high composite
      </span>
    </div>
  )
}

// ── ATLAS / OWASP helpers ─────────────────────────────────────────────────────

const OWASP_NAMES: Record<string, string> = {
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

const SEV_ORDER: Record<string, number> = { high: 3, medium: 2, low: 1, unknown: 0 }

function useSortState<T extends string>(defaultCol: T, defaultDir: SortDir = 'desc') {
  const [col, setCol] = useState<T>(defaultCol)
  const [dir, setDir] = useState<SortDir>(defaultDir)
  function toggle(c: string) {
    if (col === c) setDir(d => d === 'desc' ? 'asc' : 'desc')
    else { setCol(c as T); setDir('desc') }
  }
  return { col, dir, toggle }
}

function SortTh({ label, col, sort, onToggle, className }: {
  label: string; col: string
  sort: { col: string; dir: SortDir }
  onToggle: (c: string) => void
  className?: string
}) {
  const active = sort.col === col
  return (
    <th className={cn('px-3 py-2 font-medium text-left', className)}>
      <button onClick={() => onToggle(col)}
        className={cn('hover:text-foreground transition-colors whitespace-nowrap', active ? 'text-foreground' : 'text-muted-foreground')}>
        {label}{active ? (sort.dir === 'desc' ? ' ↓' : ' ↑') : ''}
      </button>
    </th>
  )
}

function TacticChips({ tactic }: { tactic: string }) {
  const parts = tactic.split('/').map(t => t.trim()).filter(Boolean)
  return (
    <div className="flex flex-wrap gap-1">
      {parts.map(p => (
        <Badge key={p} variant="outline" className="text-xs font-normal">{p}</Badge>
      ))}
    </div>
  )
}

function MiniBar({ value, max, colorClass = 'bg-primary' }: { value: number; max: number; colorClass?: string }) {
  const pct = max > 0 ? Math.min((value / max) * 100, 100) : 0
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-16 rounded-full bg-muted overflow-hidden shrink-0">
        <div className={cn('h-full rounded-full', colorClass)} style={{ width: `${pct}%` }} />
      </div>
      <span className="tabular-nums">{value}</span>
    </div>
  )
}

// ── Matrix Tab ─────────────────────────────────────────────────────────────────

function MatrixTab() {
  const { data, isLoading, error, refetch, isFetching } = useCoverage()
  const [hideInactive, setHideInactive] = useState(true)
  const [hideEmpty, setHideEmpty] = useState(false)
  const [sort, setSort] = useState<SortState | null>({ col: '__avg__', dir: 'desc' })

  const rows = useMemo(() => data?.matrix ?? [], [data])
  const allTargets = useMemo(() => [...new Set(rows.map(r => r.target_id))], [rows])
  const allCategories = useMemo(() => [...new Set(rows.map(r => r.category))], [rows])
  const cellMap = useMemo(() => new Map(rows.map(r => [`${r.target_id}::${r.category}`, r])), [rows])

  const targetStats = useMemo(() => {
    return Object.fromEntries(allTargets.map(t => {
      const cells = allCategories.map(c => cellMap.get(`${t}::${c}`))
      const peak = Math.max(...cells.map(c => c?.max_composite ?? 0), 0)
      const testedCount = cells.filter(c => c && c.status !== 'untested').length
      const scoredCells = cells.filter(c => c && c.max_composite > 0)
      const avg = scoredCells.length > 0
        ? scoredCells.reduce((s, c) => s + (c?.max_composite ?? 0), 0) / scoredCells.length
        : 0
      return [t, { active: testedCount, peak, testedCount, avg }]
    }))
  }, [allTargets, allCategories, cellMap])

  const catHasActivity = useMemo(() => {
    return Object.fromEntries(allCategories.map(c => [
      c,
      allTargets.some(t => {
        const cell = cellMap.get(`${t}::${c}`)
        return cell && cell.status !== 'untested'
      })
    ]))
  }, [allCategories, allTargets, cellMap])

  if (isLoading) return <Skeleton className="h-96" />
  if (error) return <p className="text-destructive">Failed to load: {error.message}</p>
  if (!data) return null

  const categories = hideEmpty ? allCategories.filter(c => catHasActivity[c]) : allCategories

  let targets = hideInactive
    ? allTargets.filter(t => targetStats[t].active > 0)
    : allTargets

  if (sort) {
    targets = [...targets].sort((a, b) => {
      let va: number, vb: number
      if (sort.col === '__avg__') {
        va = targetStats[a].avg; vb = targetStats[b].avg
      } else if (sort.col === '__peak__') {
        va = targetStats[a].peak; vb = targetStats[b].peak
      } else if (sort.col === '__tested__') {
        va = targetStats[a].testedCount; vb = targetStats[b].testedCount
      } else {
        va = cellMap.get(`${a}::${sort.col}`)?.max_composite ?? -1
        vb = cellMap.get(`${b}::${sort.col}`)?.max_composite ?? -1
      }
      return sort.dir === 'desc' ? vb - va : va - vb
    })
  }

  function toggleSort(col: string) {
    setSort(prev =>
      prev?.col === col
        ? { col, dir: prev.dir === 'desc' ? 'asc' : 'desc' }
        : { col, dir: 'desc' }
    )
  }

  const validated = rows.filter(r => r.status === 'validated').length
  const tested = rows.filter(r => r.status === 'tested').length
  const gaps = rows.filter(r => r.status === 'coverage_gap').length

  const cards = [
    { label: 'Targets', value: allTargets.length },
    { label: 'Active', value: allTargets.filter(t => targetStats[t].active > 0).length },
    { label: 'Categories', value: allCategories.length },
    { label: 'Validated', value: validated },
    { label: 'Tested', value: tested },
    { label: 'Gaps', value: gaps },
  ]

  return (
    <div className="grid gap-6">
      <StatCards cards={cards} />
      <div className="flex justify-end -mt-4">
        <DataAge generatedAt={data.generated_at} onRefresh={() => refetch()} isRefetching={isFetching} />
      </div>

      <div className="flex flex-wrap items-center gap-4">
        <MatrixLegend />
        <div className="ml-auto flex gap-2">
          <Button variant={hideInactive ? 'default' : 'outline'} size="sm" className="h-7 text-xs"
            onClick={() => setHideInactive(v => !v)}>
            {hideInactive ? 'Active only' : 'All targets'}
          </Button>
          <Button variant={hideEmpty ? 'default' : 'outline'} size="sm" className="h-7 text-xs"
            onClick={() => setHideEmpty(v => !v)}>
            {hideEmpty ? 'Active categories' : 'All categories'}
          </Button>
        </div>
      </div>

      <p className="text-xs text-muted-foreground -mt-2">
        Showing {targets.length} of {allTargets.length} targets · {categories.length} categories
      </p>

      <TooltipProvider>
      <div className="overflow-auto rounded-lg border border-border">
        <table className="w-full text-xs border-collapse table-fixed" style={{ minWidth: `${180 + categories.length * 72 + 140}px` }}>
          <thead>
            <tr className="bg-muted/50">
              {/* Target column header */}
              <th className="sticky left-0 z-20 bg-muted/50 border-b border-border p-0 w-[180px]">
                <button className="flex items-center gap-1 w-full px-3 py-2 hover:bg-muted/80 transition-colors font-medium text-left"
                  onClick={() => toggleSort('__avg__')}>
                  Target
                  <SortIcon col="__avg__" sort={sort} />
                </button>
              </th>

              {/* Category headers — horizontal text */}
              {categories.map(c => (
                <th key={c} className="p-0 border-b border-border">
                  <button
                    onClick={() => toggleSort(c)}
                    className={cn(
                      'flex items-center gap-1 w-full px-2 py-2 hover:bg-muted/80 transition-colors justify-center',
                      sort?.col === c ? 'text-foreground' : 'text-muted-foreground'
                    )}
                    style={{ fontWeight: 500, fontSize: '11px', whiteSpace: 'nowrap' }}
                  >
                    {c.replace(/_/g, ' ')}
                    <SortIcon col={c} sort={sort} />
                  </button>
                </th>
              ))}

              {/* Avg + coverage header */}
              <th className="p-0 border-b border-border w-[140px]">
                <button className="flex items-center gap-1 w-full px-3 py-2 justify-end hover:bg-muted/80 transition-colors font-medium text-muted-foreground"
                  onClick={() => toggleSort('__tested__')}>
                  avg / coverage
                  <SortIcon col="__tested__" sort={sort} />
                </button>
              </th>
            </tr>
          </thead>
          <tbody>
            {targets.map((target) => {
              const stats = targetStats[target]
              const pct = categories.length > 0 ? (stats.testedCount / categories.length) * 100 : 0
              return (
                <tr key={target} className="group hover:bg-muted/10 transition-colors">
                  {/* Target name */}
                  <td className="sticky left-0 z-10 bg-background group-hover:bg-muted/10 px-3 py-3 font-medium border-b border-border transition-colors w-[180px]">
                    <a href={`/targets/${encodeURIComponent(target)}`} className="text-primary hover:underline text-sm">
                      {target}
                    </a>
                  </td>

                  {/* Category cells — wider, more readable */}
                  {categories.map(cat => {
                    const cell = cellMap.get(`${target}::${cat}`)
                    const { tdClass, content } = matrixCellProps(cell)
                    const td = (
                      <td key={cat}
                        className={cn('border-b border-border text-center transition-colors rounded-sm', tdClass)}
                        style={{ padding: '8px 4px' }}
                      >
                        {content}
                      </td>
                    )
                    if (!cell) return td
                    return (
                      <Tooltip key={cat}>
                        <TooltipTrigger asChild>{td}</TooltipTrigger>
                        <TooltipContent className="text-xs">
                          <div className="grid gap-0.5">
                            <div className="font-medium">{cat.replace(/_/g, ' ')}</div>
                            <div>Status: <span className="text-muted-foreground">{cell.status.replace('_', ' ')}</span></div>
                            <div>Attempts: <span className="text-muted-foreground">{cell.attempts}</span></div>
                            <div>Kept: <span className="text-muted-foreground">{cell.keep_count}</span></div>
                            {cell.max_composite > 0 && <div>Score: <span className="font-mono">{cell.max_composite.toFixed(1)}</span></div>}
                          </div>
                        </TooltipContent>
                      </Tooltip>
                    )
                  })}

                  {/* Avg score + coverage fraction */}
                  <td className="px-3 py-3 border-b border-border w-[140px]">
                    <div className="flex items-center justify-end gap-3">
                      {stats.avg > 0 ? (
                        <span className={cn('font-mono font-semibold text-sm tabular-nums', scoreTextClass(stats.avg))}>
                          {stats.avg.toFixed(1)}
                        </span>
                      ) : (
                        <span className="text-muted-foreground/40 text-xs">—</span>
                      )}
                      <div className="flex items-center gap-1.5">
                        <div className="w-12 h-1.5 bg-muted rounded-full overflow-hidden shrink-0">
                          <div
                            className={cn('h-full rounded-full transition-all',
                              stats.avg > 6 ? 'bg-red-500/60' : stats.avg > 3 ? 'bg-amber-500/60' : 'bg-primary/60'
                            )}
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                        <span className="text-muted-foreground/60 tabular-nums text-[10px]">
                          {stats.testedCount}/{categories.length}
                        </span>
                      </div>
                    </div>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      </TooltipProvider>
    </div>
  )
}

// ── ATLAS Tab ──────────────────────────────────────────────────────────────────

type AtlasSortCol = 'id' | 'name' | 'tactic' | 'severity' | 'max_composite' | 'target_count' | 'evidence_count'

function AtlasTab() {
  const { data, isLoading, error } = useAtlas()
  const sort = useSortState<AtlasSortCol>('max_composite')
  const [sevFilter, setSevFilter] = useState<'all' | 'high' | 'medium' | 'low'>('all')

  if (isLoading) return <Skeleton className="h-96" />
  if (error) return <p className="text-destructive">Failed to load: {error.message}</p>
  if (!data) return null

  const techniques = data.techniques
  const maxTargets = Math.max(...techniques.map(t => t.target_count), 1)
  const maxEvidence = Math.max(...techniques.map(t => t.evidence_count), 1)

  const cards = [
    { label: 'Techniques', value: techniques.length },
    { label: 'High Severity', value: techniques.filter(t => t.severity === 'high').length },
    { label: 'Max Composite', value: fmt(Math.max(...techniques.map(t => t.max_composite), 0)) },
    { label: 'Total Attempts', value: techniques.reduce((sum, t) => sum + t.evidence_count, 0).toLocaleString() },
  ]

  const chartData = [...techniques]
    .sort((a, b) => b.max_composite - a.max_composite)
    .slice(0, 12)
    .map(t => ({ label: t.name, value: t.max_composite, color: '#c2410c' }))

  const filtered = techniques
    .filter(t => sevFilter === 'all' || t.severity === sevFilter)
    .sort((a, b) => {
      const { col, dir } = sort
      let va: number | string, vb: number | string
      if (col === 'severity') { va = SEV_ORDER[a.severity] ?? 0; vb = SEV_ORDER[b.severity] ?? 0 }
      else if (col === 'id') { va = a.id; vb = b.id }
      else if (col === 'name') { va = a.name; vb = b.name }
      else if (col === 'tactic') { va = a.tactic; vb = b.tactic }
      else { va = a[col] as number; vb = b[col] as number }
      if (typeof va === 'string') return dir === 'desc' ? vb.toString().localeCompare(va) : va.localeCompare(vb.toString())
      return dir === 'desc' ? (vb as number) - (va as number) : (va as number) - (vb as number)
    })

  const thBase = 'border-b border-border bg-muted/50 text-xs'

  return (
    <div className="grid gap-6">
      <StatCards cards={cards} />

      <Card>
        <CardHeader className="pb-2"><h2 className="font-semibold text-sm">Top Techniques by Composite Score</h2></CardHeader>
        <CardContent><HorizBarChart data={chartData} maxValue={10} formatValue={v => v.toFixed(2)} /></CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2 flex flex-row items-center justify-between gap-4">
          <div>
            <h2 className="font-semibold">MITRE ATLAS Techniques</h2>
            <p className="text-xs text-muted-foreground mt-0.5">Click column headers to sort · filter by severity</p>
          </div>
          <div className="flex gap-1 p-1 rounded-lg bg-muted shrink-0">
            {(['all', 'high', 'medium', 'low'] as const).map(s => (
              <Button key={s} variant="ghost" size="sm"
                onClick={() => setSevFilter(s)}
                className={cn('h-7 px-2.5 text-xs capitalize', sevFilter === s && 'bg-background shadow-sm text-foreground')}>
                {s}
              </Button>
            ))}
          </div>
        </CardHeader>
        <CardContent className="p-0 overflow-auto">
          <table className="w-full text-xs border-collapse">
            <thead>
              <tr className={thBase}>
                <SortTh label="ID" col="id" sort={sort} onToggle={sort.toggle} className="px-3 py-2 min-w-[100px]" />
                <SortTh label="Technique" col="name" sort={sort} onToggle={sort.toggle} className="px-3 py-2" />
                <SortTh label="Tactic" col="tactic" sort={sort} onToggle={sort.toggle} className="px-3 py-2" />
                <SortTh label="Severity" col="severity" sort={sort} onToggle={sort.toggle} className="px-3 py-2" />
                <SortTh label="Composite" col="max_composite" sort={sort} onToggle={sort.toggle} className="px-3 py-2 text-right" />
                <SortTh label="Targets" col="target_count" sort={sort} onToggle={sort.toggle} className="px-3 py-2" />
                <SortTh label="Evidence" col="evidence_count" sort={sort} onToggle={sort.toggle} className="px-3 py-2" />
              </tr>
            </thead>
            <tbody>
              {filtered.map(t => (
                <tr key={t.id} className="border-b border-border hover:bg-muted/20 transition-colors">
                  <td className="px-3 py-2.5 font-mono text-xs text-muted-foreground">{t.id}</td>
                  <td className="px-3 py-2.5 font-medium text-sm">{t.name}</td>
                  <td className="px-3 py-2.5"><TacticChips tactic={t.tactic} /></td>
                  <td className="px-3 py-2.5"><RiskBadge level={t.severity} /></td>
                  <td className="px-3 py-2.5 text-right font-mono tabular-nums">{fmt(t.max_composite)}</td>
                  <td className="px-3 py-2.5"><MiniBar value={t.target_count} max={maxTargets} colorClass="bg-orange-500" /></td>
                  <td className="px-3 py-2.5"><MiniBar value={t.evidence_count} max={maxEvidence} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </CardContent>
      </Card>
    </div>
  )
}

// ── OWASP Tab ──────────────────────────────────────────────────────────────────

type OwaspSortCol = 'owasp_ref' | 'severity' | 'target_count' | 'keep_count' | 'max_composite' | 'attempts'

function OwaspTab() {
  const { data, isLoading, error } = useOwasp()
  const sort = useSortState<OwaspSortCol>('max_composite')

  if (isLoading) return <Skeleton className="h-96" />
  if (error) return <p className="text-destructive">Failed to load: {error.message}</p>
  if (!data) return null

  const items = data.items
  const maxTargets = Math.max(...items.map(t => t.target_count), 1)

  const cards = [
    { label: 'Categories', value: items.length },
    { label: 'High Risk', value: items.filter(i => i.severity === 'high').length },
    { label: 'Max Composite', value: fmt(Math.max(...items.map(i => i.max_composite), 0)) },
    { label: 'Total Attempts', value: items.reduce((s, i) => s + i.attempts, 0).toLocaleString() },
  ]

  const chartData = [...items]
    .sort((a, b) => b.max_composite - a.max_composite)
    .map(t => ({ label: `${t.owasp_ref}: ${OWASP_NAMES[t.owasp_ref] ?? t.owasp_ref}`, value: t.max_composite, color: '#2563eb' }))

  const sorted = [...items].sort((a, b) => {
    const { col, dir } = sort
    let va: number | string, vb: number | string
    if (col === 'severity') { va = SEV_ORDER[a.severity] ?? 0; vb = SEV_ORDER[b.severity] ?? 0 }
    else if (col === 'owasp_ref') { va = a.owasp_ref; vb = b.owasp_ref }
    else { va = a[col] as number; vb = b[col] as number }
    if (typeof va === 'string') return dir === 'desc' ? vb.toString().localeCompare(va) : va.localeCompare(vb.toString())
    return dir === 'desc' ? (vb as number) - (va as number) : (va as number) - (vb as number)
  })

  const thBase = 'border-b border-border bg-muted/50 text-xs'

  return (
    <div className="grid gap-6">
      <StatCards cards={cards} />

      <Card>
        <CardHeader className="pb-2"><h2 className="font-semibold text-sm">OWASP LLM Risk by Composite Score</h2></CardHeader>
        <CardContent><HorizBarChart data={chartData} maxValue={10} formatValue={v => v.toFixed(2)} /></CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <h2 className="font-semibold">OWASP LLM Top 10 Rollup</h2>
          <p className="text-xs text-muted-foreground mt-0.5">Click column headers to sort</p>
        </CardHeader>
        <CardContent className="p-0 overflow-auto">
          <table className="w-full text-xs border-collapse">
            <thead>
              <tr className={thBase}>
                <SortTh label="Ref" col="owasp_ref" sort={sort} onToggle={sort.toggle} className="px-3 py-2 min-w-[80px]" />
                <th className="px-3 py-2 text-left font-medium text-muted-foreground">Name</th>
                <SortTh label="Severity" col="severity" sort={sort} onToggle={sort.toggle} className="px-3 py-2" />
                <SortTh label="Targets" col="target_count" sort={sort} onToggle={sort.toggle} className="px-3 py-2" />
                <SortTh label="Attempts" col="attempts" sort={sort} onToggle={sort.toggle} className="px-3 py-2 text-right" />
                <SortTh label="Kept" col="keep_count" sort={sort} onToggle={sort.toggle} className="px-3 py-2 text-right" />
                <SortTh label="Composite" col="max_composite" sort={sort} onToggle={sort.toggle} className="px-3 py-2 text-right" />
              </tr>
            </thead>
            <tbody>
              {sorted.map(item => (
                <tr key={item.owasp_ref} className="border-b border-border hover:bg-muted/20 transition-colors">
                  <td className="px-3 py-2.5 font-mono font-semibold">{item.owasp_ref}</td>
                  <td className="px-3 py-2.5 text-sm">{OWASP_NAMES[item.owasp_ref] ?? '—'}</td>
                  <td className="px-3 py-2.5"><RiskBadge level={item.severity} /></td>
                  <td className="px-3 py-2.5"><MiniBar value={item.target_count} max={maxTargets} colorClass="bg-blue-500" /></td>
                  <td className="px-3 py-2.5 text-right tabular-nums">{item.attempts}</td>
                  <td className="px-3 py-2.5 text-right tabular-nums">{item.keep_count}</td>
                  <td className="px-3 py-2.5 text-right font-mono tabular-nums">{fmt(item.max_composite)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </CardContent>
      </Card>
    </div>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────────

export function Coverage() {
  return (
    <div className="grid gap-6">
      <div>
        <p className="text-xs uppercase tracking-widest text-muted-foreground mb-1">Analysis</p>
        <h1 className="text-3xl font-bold mb-1">Coverage & Frameworks</h1>
        <p className="text-muted-foreground text-sm">Attack coverage matrix, MITRE ATLAS technique rollup, and OWASP LLM Top 10 risk analysis.</p>
      </div>

      <Tabs defaultValue="matrix">
        <TabsList>
          <TabsTrigger value="matrix">Coverage Matrix</TabsTrigger>
          <TabsTrigger value="atlas">MITRE ATLAS</TabsTrigger>
          <TabsTrigger value="owasp">OWASP LLM Top 10</TabsTrigger>
        </TabsList>
        <TabsContent value="matrix" className="mt-6"><MatrixTab /></TabsContent>
        <TabsContent value="atlas" className="mt-6"><AtlasTab /></TabsContent>
        <TabsContent value="owasp" className="mt-6"><OwaspTab /></TabsContent>
      </Tabs>
    </div>
  )
}
