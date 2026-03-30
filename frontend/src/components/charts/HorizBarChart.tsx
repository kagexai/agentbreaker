import { cn } from '@/lib/utils'

interface BarRow {
  label: string
  value: number
  color?: string
}

interface HorizBarChartProps {
  data: BarRow[]
  maxValue?: number
  formatValue?: (v: number) => string
  className?: string
}

const DEFAULT_COLOR = '#0f766e'

export function HorizBarChart({ data, maxValue, formatValue, className }: HorizBarChartProps) {
  const max = maxValue ?? Math.max(...data.map(d => d.value), 1)

  return (
    <div className={cn('grid gap-2', className)}>
      {data.map((row, i) => {
        const pct = Math.min((row.value / max) * 100, 100)
        const display = formatValue ? formatValue(row.value) : row.value.toFixed(2)
        return (
          <div key={i} className="grid gap-1">
            <div className="flex items-center justify-between gap-3">
              <span className="text-sm text-foreground truncate">{row.label}</span>
              <span className="text-xs font-mono text-muted-foreground shrink-0">{display}</span>
            </div>
            <div className="h-2 rounded-full bg-muted overflow-hidden">
              <div
                className="h-full rounded-full transition-all"
                style={{ width: `${pct}%`, backgroundColor: row.color ?? DEFAULT_COLOR }}
              />
            </div>
          </div>
        )
      })}
    </div>
  )
}
