import { useState, useEffect, useRef, memo, useCallback, useMemo } from 'react'
import { useLiveAttackStream, type AttackState, type AttackStep, type StrategyBucket } from '@/hooks/useApi'
import { useRegressions } from '@/hooks/useApi'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { X, ChevronDown, ChevronUp, CheckCircle2, Circle, Loader2, Zap, History, BarChart3, AlertTriangle, Shield, Crosshair } from 'lucide-react'
import { LineChart, Line, ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar, XAxis, Tooltip } from 'recharts'

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Python None serialised as string "None" — treat as blank */
function validField(v: string | undefined): string | undefined {
  if (!v || v === 'None' || v === 'n/a') return undefined
  return v
}

function formatElapsed(ms: number): string {
  const s = Math.floor(ms / 1000)
  if (s < 60) return `${s}s`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ${s % 60}s`
  const h = Math.floor(m / 60)
  return `${h}h ${m % 60}m`
}

// ── Pipeline step definition ──────────────────────────────────────────────────

const PIPELINE_STEPS: { id: string; label: string }[] = [
  { id: 'plan',     label: 'Plan'     },
  { id: 'generate', label: 'Generate' },
  { id: 'judge',    label: 'Judge'    },
  { id: 'result',   label: 'Result'   },
]

function stepIndex(step: AttackStep): number {
  const map: Record<string, number> = { plan: 0, generate: 1, judge: 2, result: 3 }
  return map[step] ?? 0
}

// ── Progress ring (Improvement #6) ────────────────────────────────────────────

function ProgressRing({ ratio, size = 24, strokeWidth = 3 }: { ratio: number; size?: number; strokeWidth?: number }) {
  const r = (size - strokeWidth) / 2
  const circ = 2 * Math.PI * r
  const filled = circ * Math.min(1, Math.max(0, ratio))
  return (
    <svg width={size} height={size} className="shrink-0 -rotate-90">
      <circle cx={size / 2} cy={size / 2} r={r} fill="none"
        stroke="hsl(var(--muted))" strokeWidth={strokeWidth} />
      <circle cx={size / 2} cy={size / 2} r={r} fill="none"
        stroke="hsl(var(--primary))" strokeWidth={strokeWidth}
        strokeDasharray={`${filled} ${circ - filled}`}
        strokeLinecap="round"
        className="transition-all duration-700" />
    </svg>
  )
}

// ── Pipeline node ─────────────────────────────────────────────────────────────

function PipelineNode({ label, state }: {
  label: string
  state: 'pending' | 'active' | 'done'
}) {
  return (
    <div className="flex flex-col items-center gap-1.5 min-w-[52px]">
      <div className={cn(
        'w-8 h-8 rounded-full flex items-center justify-center transition-all duration-300',
        state === 'done'   && 'bg-primary text-primary-foreground',
        state === 'active' && 'bg-primary/20 text-primary ring-2 ring-primary ring-offset-1 ring-offset-background animate-pulse',
        state === 'pending' && 'border-2 border-muted-foreground/25 text-muted-foreground/30',
      )}>
        {state === 'done'   && <CheckCircle2 className="w-4 h-4" />}
        {state === 'active' && <Loader2 className="w-4 h-4 animate-spin" />}
        {state === 'pending' && <Circle className="w-4 h-4" />}
      </div>
      <span className={cn(
        'text-[10px] font-medium uppercase tracking-wide',
        state === 'done'   && 'text-primary',
        state === 'active' && 'text-primary',
        state === 'pending' && 'text-muted-foreground/40',
      )}>{label}</span>
    </div>
  )
}

// ── Pipeline connector ────────────────────────────────────────────────────────

function PipelineConnector({ state }: { state: 'pending' | 'active' | 'done' }) {
  return (
    <div className="relative flex-1 h-0.5 mx-1 mt-[-10px] overflow-hidden">
      <div className={cn(
        'absolute inset-0 rounded-full transition-all duration-500',
        state === 'done'   && 'bg-primary',
        state === 'active' && 'bg-primary/30',
        state === 'pending' && 'bg-muted-foreground/15',
      )} />
      {state === 'active' && (
        <div
          className="absolute top-0 h-full w-4 rounded-full bg-primary/70 animate-travel"
          style={{ position: 'absolute' }}
        />
      )}
    </div>
  )
}

// ── Score bar ─────────────────────────────────────────────────────────────────

function ScoreBar({ score, max = 10, label, displayValue }: { score: number; max?: number; label?: string; displayValue?: string }) {
  const pct = Math.min(100, Math.max(0, (score / max) * 100))
  const color = score >= (max * 0.7) ? 'bg-red-500' : score >= (max * 0.4) ? 'bg-amber-500' : 'bg-emerald-500'
  return (
    <div className="flex items-center gap-2">
      {label && <span className="text-[10px] text-muted-foreground w-14 shrink-0">{label}</span>}
      <div className="flex-1 bg-muted/60 rounded-full h-1.5 overflow-hidden">
        <div
          className={cn('h-full rounded-full transition-all duration-700', color)}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="text-[10px] font-mono tabular-nums w-8 text-right shrink-0">{displayValue ?? score.toFixed(1)}</span>
    </div>
  )
}

// ── Status badge ──────────────────────────────────────────────────────────────

function StatusBadge({ status }: { status?: string }) {
  if (status === 'keep') return (
    <span className="text-xs font-semibold text-emerald-600 dark:text-emerald-400">KEPT</span>
  )
  if (status === 'partial') return (
    <span className="text-xs font-semibold text-amber-600 dark:text-amber-400">PARTIAL</span>
  )
  return <span className="text-xs text-muted-foreground">DROP</span>
}

// ── Failure mode label map ────────────────────────────────────────────────────

const FAILURE_MODE_LABELS: Record<string, string> = {
  clean_refusal: 'refused',
  benign_summary: 'benign',
  safe_redirect: 'redirected',
  policy_quote: 'policy',
  format_only: 'format only',
  partial_reconstruction: 'partial',
  substantive_leak: 'leaked',
  other: 'other',
}

const FAILURE_MODE_COLORS: Record<string, string> = {
  clean_refusal: 'bg-slate-500/15 text-slate-600 dark:text-slate-400',
  benign_summary: 'bg-blue-500/15 text-blue-600 dark:text-blue-400',
  safe_redirect: 'bg-sky-500/15 text-sky-600 dark:text-sky-400',
  policy_quote: 'bg-indigo-500/15 text-indigo-600 dark:text-indigo-400',
  format_only: 'bg-gray-500/15 text-gray-600 dark:text-gray-400',
  partial_reconstruction: 'bg-amber-500/15 text-amber-600 dark:text-amber-400',
  substantive_leak: 'bg-red-500/15 text-red-600 dark:text-red-400',
  other: 'bg-muted text-muted-foreground',
}

// ── Attack row (Improvement #1: expanded detail drawer) ──────────────────────

const AttackRow = memo(function AttackRow({
  attack,
  expanded,
  onToggle,
  highlighted,
}: {
  attack: AttackState
  expanded: boolean
  onToggle: () => void
  highlighted?: boolean
}) {
  const isComplete = attack.step === 'result'
  const isKept = attack.status === 'keep'
  const isPartial = attack.status === 'partial'
  const hasSignal = isKept || isPartial || (attack.composite !== undefined && attack.composite >= 4)

  return (
    <div
      id={`attack-${attack.attack_id}`}
      className={cn(
        'flex flex-col gap-1.5 px-3 py-2.5 rounded-lg transition-all duration-300 cursor-pointer border',
        highlighted && 'ring-2 ring-primary/50',
        isKept ? 'bg-red-500/5 border-red-500/20 hover:bg-red-500/10'
          : isPartial ? 'bg-amber-500/5 border-amber-500/20 hover:bg-amber-500/10'
          : isComplete ? 'bg-muted/30 border-border/30 hover:bg-muted/50'
          : 'bg-primary/5 border-primary/20',
      )}
      onClick={onToggle}
    >
      {/* Header row: ID + strategy + score + status */}
      <div className="flex items-center gap-2">
        <span className="text-[11px] font-mono text-muted-foreground shrink-0">{attack.attack_id}</span>
        {attack.strategy_id && (
          <span className="text-[11px] font-medium text-foreground truncate">{attack.strategy_id.replace(/_/g, ' ')}</span>
        )}
        {validField(attack.target_field) && (
          <span className="text-[10px] text-muted-foreground/70 truncate">→ {attack.target_field!.replace(/_/g, ' ')}</span>
        )}
        <div className="flex-1" />
        {attack.composite !== undefined && (
          <span className={cn(
            'text-sm font-bold tabular-nums shrink-0',
            attack.composite >= 7 ? 'text-red-500' : attack.composite >= 4 ? 'text-amber-500' : 'text-muted-foreground',
          )}>
            {attack.composite.toFixed(1)}
          </span>
        )}
        {isComplete && attack.breach_hint && (
          <span className="w-2 h-2 rounded-full bg-orange-500 shrink-0 inline-block animate-pulse" title="breach hint" />
        )}
        {isComplete && <StatusBadge status={attack.status} />}
        {!isComplete && (
          <span className="text-[11px] text-primary animate-pulse shrink-0">
            {attack.step === 'plan' ? 'planning' : attack.step === 'generate' ? 'generating' : attack.step === 'judge' ? 'judging' : 'running'}
          </span>
        )}
        <ChevronDown className={cn('w-3.5 h-3.5 text-muted-foreground/40 shrink-0 transition-transform', expanded && 'rotate-180')} />
      </div>

      {/* Inline previews — always visible for completed attacks */}
      {isComplete && attack.payload_text && (
        <div className="flex gap-2 text-[10px] leading-snug">
          <span className="text-muted-foreground/50 uppercase tracking-wider shrink-0 pt-px w-10">sent</span>
          <p className="text-muted-foreground font-mono line-clamp-2 flex-1">{attack.payload_text}</p>
        </div>
      )}
      {isComplete && attack.response_text && (
        <div className="flex gap-2 text-[10px] leading-snug">
          <span className="text-muted-foreground/50 uppercase tracking-wider shrink-0 pt-px w-10">recv</span>
          <p className={cn(
            'font-mono line-clamp-2 flex-1',
            hasSignal ? 'text-amber-700 dark:text-amber-400' : 'text-muted-foreground',
          )}>{attack.response_text}</p>
        </div>
      )}

      {/* Tags row — failure mode, cluster, partial leak */}
      {isComplete && attack.failure_mode && (
        <div className="flex items-center gap-1.5 flex-wrap">
          <span className={cn(
            'text-[10px] px-1.5 py-0.5 rounded font-mono',
            FAILURE_MODE_COLORS[attack.failure_mode] ?? FAILURE_MODE_COLORS.other,
          )}>
            {FAILURE_MODE_LABELS[attack.failure_mode] ?? attack.failure_mode}
          </span>
          {attack.response_cluster && (
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-muted/50 text-muted-foreground/70">{attack.response_cluster.replace(/_/g, ' ')}</span>
          )}
          {attack.partial_leak && (
            <span className="text-[10px] px-1 py-0.5 rounded bg-amber-500/15 text-amber-600 dark:text-amber-400 font-medium">partial leak</span>
          )}
        </div>
      )}

      {/* Recommendation line */}
      {attack.recommended_next_family && (
        <div className="flex items-center gap-1.5 bg-amber-500/5 rounded px-2 py-1">
          <Crosshair className="w-3 h-3 text-amber-600 dark:text-amber-400 shrink-0" />
          <span className="text-[10px] text-amber-600 dark:text-amber-400">pivot to:</span>
          <span className="text-[10px] font-mono font-semibold text-amber-700 dark:text-amber-300">{attack.recommended_next_family.replace(/_/g, ' ')}</span>
        </div>
      )}

      {/* Expanded detail drawer */}
      {expanded && (
        <div className="pl-[calc(6rem+0.75rem)] pr-2 mt-2 space-y-3 border-t border-border/50 pt-2.5">
          {/* Composite score — hero metric */}
          {attack.composite !== undefined && (
            <div className="flex items-center gap-3">
              <div className={cn(
                'text-lg font-bold tabular-nums',
                attack.composite >= 7 ? 'text-red-500' : attack.composite >= 4 ? 'text-amber-500' : 'text-muted-foreground',
              )}>
                {attack.composite.toFixed(1)}
              </div>
              <div className="text-[10px] text-muted-foreground leading-tight">
                <span className="font-medium">Composite Score</span>
                <span className="block text-muted-foreground/50">
                  {attack.composite >= 7 ? 'High severity — likely exploitable'
                    : attack.composite >= 4 ? 'Moderate signal — partial bypass detected'
                    : 'Low signal — target defended effectively'}
                </span>
              </div>
            </div>
          )}

          {/* Score breakdown bars */}
          {(attack.vulnerability !== undefined || attack.reliability !== undefined || attack.asr !== undefined) && (
            <div className="space-y-1.5">
              <p className="text-[10px] uppercase tracking-wider text-muted-foreground/60 font-medium">Score Components</p>
              <div className="grid gap-1.5 max-w-sm">
                {attack.vulnerability !== undefined && (
                  <ScoreBar score={attack.vulnerability} label="Vulnerability" />
                )}
                {attack.reliability !== undefined && (
                  <ScoreBar score={attack.reliability} label="Reliability" />
                )}
                {attack.asr !== undefined && (
                  <ScoreBar score={attack.asr} max={1} label="ASR" displayValue={attack.asr.toFixed(2)} />
                )}
              </div>
            </div>
          )}

          {/* Attack context grid */}
          <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-[10px] max-w-sm">
            {attack.category && (
              <div>
                <span className="text-muted-foreground/50 uppercase tracking-wider">Category</span>
                <p className="text-foreground font-medium">{attack.category.replace(/_/g, ' ')}</p>
              </div>
            )}
            {attack.strategy_id && (
              <div>
                <span className="text-muted-foreground/50 uppercase tracking-wider">Strategy</span>
                <p className="text-foreground font-medium">{attack.strategy_id.replace(/_/g, ' ')}</p>
              </div>
            )}
            {validField(attack.target_field) && (
              <div>
                <span className="text-muted-foreground/50 uppercase tracking-wider">Target Field</span>
                <p className="text-foreground font-medium">{attack.target_field!.replace(/_/g, ' ')}</p>
              </div>
            )}
            {validField(attack.framing) && (
              <div>
                <span className="text-muted-foreground/50 uppercase tracking-wider">Framing</span>
                <p className="text-foreground">{attack.framing}</p>
              </div>
            )}
            {attack.variant_index !== undefined && (
              <div>
                <span className="text-muted-foreground/50 uppercase tracking-wider">Variant</span>
                <p className="text-foreground tabular-nums">{attack.variant_index}</p>
              </div>
            )}
            {attack.trials > 0 && (
              <div>
                <span className="text-muted-foreground/50 uppercase tracking-wider">Trial</span>
                <p className="text-foreground tabular-nums">{attack.trials}</p>
              </div>
            )}
            {attack.failure_mode && (
              <div>
                <span className="text-muted-foreground/50 uppercase tracking-wider">Failure Mode</span>
                <p className="text-foreground font-medium">{FAILURE_MODE_LABELS[attack.failure_mode] ?? attack.failure_mode}</p>
              </div>
            )}
            {attack.response_cluster && (
              <div>
                <span className="text-muted-foreground/50 uppercase tracking-wider">Response Cluster</span>
                <p className="text-foreground">{attack.response_cluster.replace(/_/g, ' ')}</p>
              </div>
            )}
          </div>

          {/* Payload and Response Previews */}
          {(attack.payload_text || attack.response_text) && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
              {attack.payload_text && (
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground/60 font-medium mb-1">Attack Prompt</p>
                  <div className="text-[11px] font-mono text-muted-foreground whitespace-pre-wrap leading-relaxed bg-muted/30 border border-border/50 rounded-md p-2.5 max-h-48 overflow-y-auto relative group">
                    {attack.payload_text}
                  </div>
                </div>
              )}
              {attack.response_text && (
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground/60 font-medium mb-1">Model Response</p>
                  <div className="text-[11px] font-mono text-muted-foreground whitespace-pre-wrap leading-relaxed bg-muted/30 border border-border/50 rounded-md p-2.5 max-h-48 overflow-y-auto relative group">
                    {attack.response_text}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Judge reasoning */}
          {attack.judge_reasoning && (
            <div>
              <p className="text-[10px] uppercase tracking-wider text-muted-foreground/60 font-medium mb-1">Judge Reasoning</p>
              <p className="text-[11px] text-muted-foreground whitespace-pre-wrap leading-relaxed bg-muted/30 border border-border/50 rounded-md p-2.5 max-h-36 overflow-y-auto">
                {attack.judge_reasoning}
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  )
})

// ── Composite sparkline with color-coded dots (Improvement #4) ───────────────

const DOT_COLORS: Record<string, string> = {
  keep: '#10b981',    // emerald-500
  partial: '#f59e0b', // amber-500
  drop: '#6b7280',    // gray-500
}

function SparklineDot(props: Record<string, unknown>) {
  const { cx, cy, payload } = props as { cx: number; cy: number; payload: { status: string } }
  if (!cx || !cy) return null
  const color = DOT_COLORS[payload?.status] ?? DOT_COLORS.drop
  return <circle cx={cx} cy={cy} r={2.5} fill={color} stroke="none" />
}

function CompositeSparkline({ data }: { data: Array<{ index: number; composite: number; status: string }> }) {
  if (data.length < 5) return null
  return (
    <div className="w-full h-14 px-1">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data} margin={{ top: 4, right: 4, bottom: 4, left: 4 }}>
          <Line
            type="monotone"
            dataKey="composite"
            stroke="hsl(var(--primary))"
            strokeWidth={1.5}
            dot={<SparklineDot />}
            activeDot={{ r: 4, strokeWidth: 0 }}
            isAnimationActive={false}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}

// ── Category donut chart (Improvement #2) ────────────────────────────────────

const CATEGORY_COLORS = [
  'hsl(174 60% 50%)', // teal
  'hsl(38 90% 50%)',  // amber
  'hsl(280 60% 55%)', // purple
  'hsl(200 80% 50%)', // blue
  'hsl(340 70% 55%)', // pink
  'hsl(100 45% 45%)', // olive
]

function CategoryDonut({ attacks }: { attacks: Map<string, AttackState> }) {
  const data = useMemo(() => {
    const counts = new Map<string, number>()
    for (const a of attacks.values()) {
      if (a.step !== 'result' || !a.category) continue
      counts.set(a.category, (counts.get(a.category) ?? 0) + 1)
    }
    const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1])
    const top5 = sorted.slice(0, 5)
    const otherCount = sorted.slice(5).reduce((s, [, c]) => s + c, 0)
    const result = top5.map(([name, value]) => ({ name: name.replace(/_/g, ' '), value }))
    if (otherCount > 0) result.push({ name: 'other', value: otherCount })
    return result
  }, [attacks])

  if (data.length < 2) return null

  return (
    <div className="space-y-1">
      <p className="text-[10px] uppercase tracking-wider text-muted-foreground/60 font-medium px-1">Categories</p>
      <div className="flex items-center gap-3">
        <div className="w-16 h-16 shrink-0">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                dataKey="value"
                cx="50%"
                cy="50%"
                innerRadius={18}
                outerRadius={28}
                paddingAngle={2}
                isAnimationActive={false}
              >
                {data.map((_, i) => (
                  <Cell key={i} fill={CATEGORY_COLORS[i % CATEGORY_COLORS.length]} />
                ))}
              </Pie>
            </PieChart>
          </ResponsiveContainer>
        </div>
        <div className="flex flex-wrap gap-x-3 gap-y-0.5">
          {data.map((d, i) => (
            <span key={d.name} className="flex items-center gap-1 text-[10px] text-muted-foreground">
              <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: CATEGORY_COLORS[i % CATEGORY_COLORS.length] }} />
              <span className="truncate max-w-[100px]">{d.name}</span>
              <span className="tabular-nums font-medium text-foreground">{d.value}</span>
            </span>
          ))}
        </div>
      </div>
    </div>
  )
}

// ── Score histogram (Improvement #3) ─────────────────────────────────────────

const HIST_BINS = [
  { name: '0–2', min: 0, max: 2, color: '#10b981' },
  { name: '2–4', min: 2, max: 4, color: '#34d399' },
  { name: '4–6', min: 4, max: 6, color: '#f59e0b' },
  { name: '6–8', min: 6, max: 8, color: '#f97316' },
  { name: '8–10', min: 8, max: 10, color: '#ef4444' },
]

function ScoreHistogram({ compositeTrend }: { compositeTrend: Array<{ composite: number }> }) {
  const data = useMemo(() => {
    const bins = HIST_BINS.map(b => ({ ...b, count: 0 }))
    for (const item of compositeTrend) {
      const idx = Math.min(4, Math.floor(item.composite / 2))
      bins[idx].count++
    }
    return bins
  }, [compositeTrend])

  if (compositeTrend.length < 5) return null

  return (
    <div className="space-y-1">
      <p className="text-[10px] uppercase tracking-wider text-muted-foreground/60 font-medium px-1">Score Distribution</p>
      <div className="w-full h-14 px-1">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 2, right: 2, bottom: 2, left: 2 }}>
            <XAxis dataKey="name" tick={{ fontSize: 8 }} tickLine={false} axisLine={false} />
            <Tooltip
              contentStyle={{ fontSize: 11, borderRadius: 6, border: '1px solid hsl(var(--border))', background: 'hsl(var(--card))' }}
              formatter={(value: unknown) => [`${value} attacks`, 'Count']}
            />
            <Bar dataKey="count" radius={[3, 3, 0, 0]} isAnimationActive={false}>
              {data.map((d, i) => (
                <Cell key={i} fill={d.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}

// ── Strategy effectiveness row (Improvement #5) ──────────────────────────────

function StrategyRow({ strategyId, bucket, maxTotal, onClickStrategy }: {
  strategyId: string
  bucket: StrategyBucket
  maxTotal: number
  onClickStrategy?: (strategyId: string) => void
}) {
  const barWidth = maxTotal > 0 ? (bucket.total / maxTotal) * 100 : 0
  const keptPct = bucket.total > 0 ? (bucket.kept / bucket.total) * 100 : 0
  const partialPct = bucket.total > 0 ? (bucket.partial / bucket.total) * 100 : 0
  const dropPct = 100 - keptPct - partialPct
  const successRate = bucket.total > 0 ? ((bucket.kept + bucket.partial) / bucket.total * 100) : 0

  return (
    <div
      className={cn(
        'flex items-center gap-3 text-xs',
        onClickStrategy && 'cursor-pointer hover:bg-muted/30 rounded px-1 py-0.5 -mx-1 transition-colors',
      )}
      onClick={() => onClickStrategy?.(strategyId)}
      title={onClickStrategy ? `Click to highlight ${strategyId} attacks` : undefined}
    >
      <span className="font-mono text-muted-foreground truncate w-36 shrink-0">{strategyId}</span>
      <div className="flex-1 h-2 rounded-full overflow-hidden bg-muted/40 flex" style={{ maxWidth: `${barWidth}%`, minWidth: '20%' }}>
        {keptPct > 0 && <div className="h-full bg-emerald-500" style={{ width: `${keptPct}%` }} />}
        {partialPct > 0 && <div className="h-full bg-amber-500" style={{ width: `${partialPct}%` }} />}
        {dropPct > 0 && <div className="h-full bg-muted-foreground/20" style={{ width: `${dropPct}%` }} />}
      </div>
      <span className="tabular-nums text-muted-foreground/60 shrink-0 w-10 text-right text-[10px]">
        {successRate.toFixed(0)}%
      </span>
      <span className="tabular-nums text-muted-foreground shrink-0 w-16 text-right">
        <strong className="text-emerald-600 dark:text-emerald-400">{bucket.kept}</strong>/{bucket.total}
      </span>
      {bucket.bestComposite >= 4 && (
        <span className={cn(
          'text-[10px] tabular-nums font-semibold shrink-0 w-10 text-right',
          bucket.bestComposite >= 7 ? 'text-red-500' : 'text-amber-500',
        )}>
          ⚡{bucket.bestComposite.toFixed(1)}
        </span>
      )}
      {bucket.bestComposite < 4 && (
        <span className="tabular-nums text-muted-foreground/60 shrink-0 w-10 text-right text-[10px]">
          {bucket.avgComposite.toFixed(1)}
        </span>
      )}
    </div>
  )
}

// ── Regression row ────────────────────────────────────────────────────────────

function RegressionRow({ entry }: { entry: { attack_id: string; category: string; composite: number; tier: string } }) {
  const color = entry.composite >= 7 ? 'bg-red-500' : entry.composite >= 4 ? 'bg-amber-500' : 'bg-emerald-500'
  const pct = Math.min(100, (entry.composite / 10) * 100)
  return (
    <div className="flex items-center gap-3 px-2 py-1.5 rounded bg-muted/20">
      <span className="text-xs font-mono text-muted-foreground w-20 shrink-0 truncate">{entry.attack_id}</span>
      <span className="text-xs text-muted-foreground truncate flex-1">{entry.category.replace(/_/g, ' ')}</span>
      <div className="flex items-center gap-1.5 shrink-0 w-20">
        <div className="flex-1 h-1.5 bg-muted/60 rounded-full overflow-hidden">
          <div className={cn('h-full rounded-full', color)} style={{ width: `${pct}%` }} />
        </div>
        <span className="text-xs font-mono tabular-nums">{entry.composite.toFixed(1)}</span>
      </div>
      <span className={cn(
        'text-[10px] font-semibold shrink-0',
        entry.tier === 'success' ? 'text-emerald-600 dark:text-emerald-400' : 'text-amber-600 dark:text-amber-400'
      )}>
        {entry.tier === 'success' ? 'KEEP' : 'PARTIAL'}
      </span>
    </div>
  )
}

// ── Breach alert banner (Improvement #7) ─────────────────────────────────────

function BreachBanner({ attack, onDismiss, onJump }: {
  attack: AttackState
  onDismiss: () => void
  onJump: (attackId: string) => void
}) {
  useEffect(() => {
    const timer = setTimeout(onDismiss, 10_000)
    return () => clearTimeout(timer)
  }, [attack.attack_id, onDismiss])

  return (
    <div
      className="flex items-center gap-2 px-3 py-2 rounded-lg bg-gradient-to-r from-orange-500/15 to-red-500/15 border border-orange-500/30 cursor-pointer animate-breach-in"
      onClick={() => { onJump(attack.attack_id); onDismiss() }}
    >
      <AlertTriangle className="w-4 h-4 text-orange-500 shrink-0 animate-pulse" />
      <div className="flex-1 min-w-0">
        <p className="text-xs font-semibold text-orange-600 dark:text-orange-400">
          Breach signal detected
        </p>
        <p className="text-[10px] text-muted-foreground truncate">
          {attack.attack_id} scored <strong className="text-red-500">{attack.composite?.toFixed(1) ?? '?'}</strong>
          {attack.strategy_id && <> · {attack.strategy_id}</>}
        </p>
      </div>
      <Button variant="ghost" size="sm" className="h-6 w-6 p-0 shrink-0" onClick={(e) => { e.stopPropagation(); onDismiss() }}>
        <X className="w-3 h-3" />
      </Button>
    </div>
  )
}

// ── Elapsed time hook ────────────────────────────────────────────────────────

function useElapsed(startedAt: number, active: boolean) {
  const [elapsed, setElapsed] = useState(0)
  useEffect(() => {
    if (!startedAt || !active) return
    const tick = () => setElapsed(Date.now() - startedAt)
    tick()
    const id = setInterval(tick, 1000)
    return () => clearInterval(id)
  }, [startedAt, active])
  return elapsed
}

// ── Main component ────────────────────────────────────────────────────────────

interface LiveAttackPanelProps {
  jobId: string
  targetId: string
  onClose?: () => void
}

export function LiveAttackPanel({ jobId, targetId, onClose }: LiveAttackPanelProps) {
  const { streamStatus, attacks, activeAttackId, stats, recentLogs, streamStartedAt } = useLiveAttackStream(jobId)
  const { data: regressionsData } = useRegressions()
  const [showLog, setShowLog] = useState(false)
  const [showRegressions, setShowRegressions] = useState(false)
  const [expandedAttackId, setExpandedAttackId] = useState<string | null>(null)
  const [highlightedStrategy, setHighlightedStrategy] = useState<string | null>(null)
  const [filterMode, setFilterMode] = useState<'all' | 'signal' | 'breach'>('all')
  const [breachBannerAttack, setBreachBannerAttack] = useState<AttackState | null>(null)
  const seenBreachIdsRef = useRef<Set<string>>(new Set())

  const activeAttack = activeAttackId ? attacks.get(activeAttackId) : undefined
  const currentStepIdx = activeAttack ? stepIndex(activeAttack.step) : -1

  const attackList = useMemo(() => [...attacks.values()].reverse(), [attacks])

  const isLive = streamStatus === 'live' || streamStatus === 'connecting'
  const elapsed = useElapsed(streamStartedAt, isLive || streamStatus === 'done')
  const atkPerMin = elapsed > 30000 && stats.total > 0 ? (stats.total / (elapsed / 60000)) : 0

  // Auto-scroll: scroll to top when new attack arrives if user is near top
  const feedRef = useRef<HTMLDivElement>(null)
  const prevCountRef = useRef(attackList.length)
  useEffect(() => {
    if (attackList.length > prevCountRef.current && feedRef.current) {
      if (feedRef.current.scrollTop <= 50) {
        feedRef.current.scrollTo({ top: 0, behavior: 'smooth' })
      }
    }
    prevCountRef.current = attackList.length
  }, [attackList.length])

  // Breach detection — show banner only for genuinely new breach-hint attacks (not replays)
  useEffect(() => {
    for (const a of attackList) {
      if (a.breach_hint && !seenBreachIdsRef.current.has(a.attack_id)) {
        seenBreachIdsRef.current.add(a.attack_id)
        setBreachBannerAttack(a)
        break
      }
    }
  }, [attackList])

  const filteredAttackList = useMemo(() =>
    attackList.filter(a => {
      if (highlightedStrategy && a.strategy_id !== highlightedStrategy) return false
      if (filterMode === 'signal') return a.composite && a.composite >= 4
      if (filterMode === 'breach') return a.breach_hint === true
      return true
    }),
    [attackList, highlightedStrategy, filterMode]
  )

  const targetRegressions = regressionsData?.entries
    .filter(e => e.target_id === targetId && (e.tier === 'success' || e.tier === 'partial'))
    .sort((a, b) => b.composite - a.composite)
    .slice(0, 5) ?? []

  // Strategy breakdown: sorted by kept desc, limit 8
  const strategyEntries = [...stats.strategyStats.entries()]
    .sort((a, b) => b[1].kept - a[1].kept || b[1].avgComposite - a[1].avgComposite)
    .slice(0, 8)
  const maxStrategyTotal = strategyEntries.length > 0
    ? Math.max(...strategyEntries.map(([, b]) => b.total))
    : 0

  // Strategy click handler — highlight related attacks in the feed
  const handleStrategyClick = useCallback((strategyId: string) => {
    setHighlightedStrategy(prev => prev === strategyId ? null : strategyId)
  }, [])

  // Jump to attack in the feed
  const handleJumpToAttack = useCallback((attackId: string) => {
    setExpandedAttackId(attackId)
    const el = document.getElementById(`attack-${attackId}`)
    el?.scrollIntoView({ behavior: 'smooth', block: 'center' })
  }, [])

  // Keep rate for progress ring
  const keepRatio = stats.total > 0 ? stats.keepRate : 0

  return (
    <div className={cn(
      'border border-border rounded-xl overflow-hidden bg-card/80 backdrop-blur-sm shadow-sm',
      isLive && 'live-glow',
    )}>
      {/* Header (Improvement #6: progress ring + throughput) */}
      <div className="flex items-center gap-3 px-4 py-2.5 border-b border-border bg-card">
        <ProgressRing ratio={keepRatio} />
        <div className="flex items-center gap-1.5">
          <span className={cn(
            'w-2 h-2 rounded-full',
            streamStatus === 'live'       && 'bg-emerald-500 animate-pulse',
            streamStatus === 'connecting' && 'bg-amber-500 animate-pulse',
            streamStatus === 'done'       && 'bg-muted-foreground',
            streamStatus === 'idle'       && 'bg-muted-foreground/40',
          )} />
          <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            {streamStatus === 'done' ? 'Completed' : streamStatus === 'connecting' ? 'Connecting' : 'Live'}
          </span>
        </div>
        <Zap className="w-3.5 h-3.5 text-primary" />
        <span className="text-xs font-mono text-muted-foreground truncate flex-1">{jobId.slice(0, 24)}</span>
        {atkPerMin > 0 && (
          <span className="text-[10px] text-muted-foreground/70 tabular-nums shrink-0">{atkPerMin.toFixed(1)}/min</span>
        )}
        {elapsed > 0 && (
          <span className="text-[10px] text-muted-foreground/50 tabular-nums shrink-0">{formatElapsed(elapsed)}</span>
        )}
        {targetId && (
          <Badge variant="outline" className="text-xs shrink-0">{targetId}</Badge>
        )}
        {onClose && (
          <Button variant="ghost" size="sm" className="h-6 w-6 p-0 shrink-0" onClick={onClose}>
            <X className="w-3.5 h-3.5" />
          </Button>
        )}
      </div>

      <div className="p-4 flex flex-col lg:flex-row gap-6">
        
        {/* Main Column: Feed & Pipeline */}
        <div className="flex-1 min-w-0 space-y-6">
           {/* Breach alert banner */}
          {breachBannerAttack && (
            <BreachBanner
              attack={breachBannerAttack}
              onDismiss={() => setBreachBannerAttack(null)}
              onJump={handleJumpToAttack}
            />
          )}

          {/* Pipeline */}
          <div className="space-y-3 bg-muted/20 p-3 rounded-lg border border-border/50">
            <div className="flex items-center">
            {PIPELINE_STEPS.map((step, i) => {
              const nodeState =
                currentStepIdx > i ? 'done'
                : currentStepIdx === i ? 'active'
                : 'pending'
              return (
                <div key={step.id} className="flex items-center flex-1 last:flex-none">
                  <PipelineNode label={step.label} state={nodeState} />
                  {i < PIPELINE_STEPS.length - 1 && (
                    <PipelineConnector
                      state={
                        currentStepIdx > i ? 'done'
                        : currentStepIdx === i ? 'active'
                        : 'pending'
                      }
                    />
                  )}
                </div>
              )
            })}
          </div>

          {/* Current attack info */}
          {activeAttack && (
            <div className="flex items-center gap-2 px-1 text-xs text-muted-foreground flex-wrap">
              <span className="font-mono font-medium text-foreground">{activeAttack.attack_id}</span>
              {activeAttack.category && (
                <>
                  <span>·</span>
                  <span className="text-muted-foreground">{activeAttack.category.replace(/_/g, ' ')}</span>
                </>
              )}
              {activeAttack.strategy_id && (
                <>
                  <span>/</span>
                  <span className="text-primary font-medium">{activeAttack.strategy_id}</span>
                </>
              )}
              {activeAttack.variant_index !== undefined && (
                <span className="text-muted-foreground/60">v{activeAttack.variant_index}</span>
              )}
              {validField(activeAttack.target_field) && (
                <>
                  <span>→</span>
                  <span className="text-amber-600 dark:text-amber-400">{activeAttack.target_field!.replace(/_/g, ' ')}</span>
                </>
              )}
              {validField(activeAttack.framing) && (
                <>
                  <span>·</span>
                  <span className="italic text-muted-foreground/70">{activeAttack.framing}</span>
                </>
              )}
            </div>
          )}
        </div>

          {/* Attack feed */}
          {attackList.length > 0 && (
            <div className="space-y-2">
              <div className="flex items-center justify-between px-1">
                <div className="flex items-center gap-2">
                  <p className="text-sm font-semibold text-foreground">Attack Feed</p>
                  <span className="text-xs text-muted-foreground/50 tabular-nums">({attackList.length})</span>
                </div>
                
                {/* Filter Controls */}
                <div className="flex items-center gap-1 bg-muted/40 p-0.5 rounded-md border border-border/50">
                  <button
                    onClick={() => setFilterMode('all')}
                    className={cn(
                      "text-[10px] px-2 py-1 rounded-sm font-medium transition-colors",
                      filterMode === 'all' ? "bg-background shadow-sm text-foreground" : "text-muted-foreground hover:text-foreground"
                    )}
                  >
                    All
                  </button>
                  <button
                    onClick={() => setFilterMode('signal')}
                    className={cn(
                      "text-[10px] px-2 py-1 rounded-sm font-medium transition-colors flex items-center gap-1",
                      filterMode === 'signal' ? "bg-background shadow-sm text-amber-600 dark:text-amber-400" : "text-muted-foreground hover:text-foreground"
                    )}
                  >
                    Signals Only
                  </button>
                  <button
                    onClick={() => setFilterMode('breach')}
                    className={cn(
                      "text-[10px] px-2 py-1 rounded-sm font-medium transition-colors flex items-center gap-1",
                      filterMode === 'breach' ? "bg-background shadow-sm text-red-600 dark:text-red-400" : "text-muted-foreground hover:text-foreground"
                    )}
                  >
                    Breaches
                  </button>
                </div>
              </div>
              
              {highlightedStrategy && (
                <div className="px-1 flex items-center justify-between bg-primary/5 rounded py-1">
                  <span className="text-[10px] text-primary">Filtering by strategy: <strong>{highlightedStrategy}</strong></span>
                  <button className="text-[10px] text-primary hover:underline font-medium" onClick={() => setHighlightedStrategy(null)}>
                    Clear
                  </button>
                </div>
              )}

              <div ref={feedRef} className="space-y-1.5 max-h-[600px] overflow-y-auto pr-1">
                {filteredAttackList.map(a => (
                    <AttackRow
                      key={a.attack_id}
                      attack={a}
                      expanded={expandedAttackId === a.attack_id}
                      onToggle={() => setExpandedAttackId(prev => prev === a.attack_id ? null : a.attack_id)}
                      highlighted={!!highlightedStrategy && a.strategy_id === highlightedStrategy}
                    />
                  ))}
              </div>
            </div>
          )}

          {/* Empty state main column */}
          {attacks.size === 0 && isLive && (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground border border-dashed border-border rounded-lg">
              <Loader2 className="w-6 h-6 animate-spin mb-3 opacity-50" />
              <p className="text-sm font-medium">Waiting for first attack…</p>
              <p className="text-xs opacity-70 mt-1">Watch the feed populate in real-time</p>
            </div>
          )}

          {streamStatus === 'done' && attacks.size === 0 && (
            <div className="py-12 text-center text-sm text-muted-foreground border border-dashed border-border rounded-lg">
              Job finished with no attack events captured.
            </div>
          )}
        </div>

        {/* Right Sidebar: Analytics & Stats */}
        <div className="w-full lg:w-80 shrink-0 space-y-6 lg:sticky lg:top-4 lg:self-start">
          
          {/* Stats Cards */}
          {stats.total > 0 && (
            <div className="grid grid-cols-2 gap-2">
              <div className="bg-muted/30 p-3 rounded-lg border border-border/50">
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium mb-2">Metrics</p>
                <div className="flex flex-col gap-1.5">
                  <div className="flex items-baseline justify-between">
                    <span className="text-xs text-muted-foreground">Total Attacks</span>
                    <span className="text-lg font-bold tabular-nums leading-none">{stats.total}</span>
                  </div>
                  <div className="flex items-baseline justify-between">
                    <span className="text-xs text-emerald-600/80 dark:text-emerald-400/80">Successful</span>
                    <div className="flex items-baseline gap-1.5 leading-none">
                      <span className="text-lg font-bold tabular-nums text-emerald-600 dark:text-emerald-400">{stats.kept}</span>
                      <span className="text-[10px] text-muted-foreground">({stats.keepRate > 0 ? (stats.keepRate * 100).toFixed(0) : 0}%)</span>
                    </div>
                  </div>
                  {stats.partial > 0 && (
                    <div className="flex items-baseline justify-between">
                      <span className="text-xs text-amber-600/80 dark:text-amber-400/80">Partial Bypass</span>
                      <span className="text-sm font-bold tabular-nums leading-none text-amber-600 dark:text-amber-400">{stats.partial}</span>
                    </div>
                  )}
                </div>
              </div>
              <div className="bg-muted/30 p-3 rounded-lg border border-border/50">
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium mb-2">Scores</p>
                <div className="flex flex-col gap-1.5">
                  <div className="flex items-baseline justify-between">
                    <span className="text-xs text-muted-foreground">Best Composite</span>
                    <span className={cn(
                      'text-lg font-bold tabular-nums leading-none',
                      stats.bestComposite >= 7 ? 'text-red-500' : stats.bestComposite >= 4 ? 'text-amber-500' : 'text-foreground'
                    )}>{stats.bestComposite.toFixed(1)}</span>
                  </div>
                  <div className="flex items-baseline justify-between">
                    <span className="text-xs text-muted-foreground/70">Avg Composite</span>
                    <span className="text-sm font-medium tabular-nums leading-none text-muted-foreground">{stats.avgComposite.toFixed(1)}</span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Charts section */}
          {stats.compositeTrend.length >= 5 && (
            <div className="space-y-3 bg-muted/10 p-3 rounded-lg border border-border/50">
               <div className="flex items-center gap-1.5 text-sm font-semibold text-foreground">
                <BarChart3 className="w-4 h-4" />
                Analytics
              </div>
              <div className="grid gap-4">
                <CompositeSparkline data={stats.compositeTrend} />
                <ScoreHistogram compositeTrend={stats.compositeTrend} />
                <CategoryDonut attacks={attacks} />
              </div>
            </div>
          )}

          {/* Strategy effectiveness */}
          {strategyEntries.length > 1 && (
            <div className="space-y-3 bg-muted/10 p-3 rounded-lg border border-border/50">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-1.5 text-sm font-semibold text-foreground">
                  <Shield className="w-4 h-4" />
                  Strategies
                </div>
                <span className="text-[10px] text-muted-foreground/60">{strategyEntries.length} active</span>
              </div>
              <div className="space-y-1.5 pt-1">
                {strategyEntries.map(([sid, bucket]) => (
                  <StrategyRow
                    key={sid}
                    strategyId={sid}
                    bucket={bucket}
                    maxTotal={maxStrategyTotal}
                    onClickStrategy={handleStrategyClick}
                  />
                ))}
              </div>
            </div>
          )}

        {/* Regression context */}
        {targetRegressions.length > 0 && (
          <div className="space-y-1">
            <button
              onClick={() => setShowRegressions(v => !v)}
              className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
            >
              <History className="w-3 h-3" />
              Past findings for this target
              {showRegressions ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
              <span className="text-muted-foreground/50">({targetRegressions.length})</span>
            </button>
            {showRegressions && (
              <div className="space-y-1">
                {targetRegressions.map((e, i) => (
                  <RegressionRow key={i} entry={{ attack_id: e.attack_id, category: e.category, composite: e.composite, tier: e.tier }} />
                ))}
              </div>
            )}
          </div>
        )}

        {/* Log toggle */}
        {recentLogs.length > 0 && (
          <div className="space-y-1">
            <button
              onClick={() => setShowLog(v => !v)}
              className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
            >
              {showLog ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
              Log
            </button>
            {showLog && (
              <div className="bg-muted/40 rounded-md p-2 space-y-0.5 max-h-28 overflow-y-auto">
                {recentLogs.map((e, i) => (
                  <p key={i} className="text-xs font-mono text-muted-foreground truncate">{e.line}</p>
                ))}
              </div>
            )}
          </div>
        )}

        </div>
      </div>
    </div>
  )
}
