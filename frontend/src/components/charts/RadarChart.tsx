import {
  RadarChart as RechartsRadar,
  Radar,
  PolarGrid,
  PolarAngleAxis,
  ResponsiveContainer,
  Tooltip,
} from 'recharts'

interface RadarRow {
  category: string
  value: number
  fullMark?: number
}

interface RadarChartProps {
  data: RadarRow[]
  color?: string
  height?: number
}

export function RadarChart({ data, color = '#0f766e', height = 300 }: RadarChartProps) {
  if (data.length === 0) return <p className="text-sm text-muted-foreground">No data.</p>

  return (
    <ResponsiveContainer width="100%" height={height}>
      <RechartsRadar data={data} margin={{ top: 8, right: 24, bottom: 8, left: 24 }}>
        <PolarGrid stroke="hsl(var(--border))" />
        <PolarAngleAxis
          dataKey="category"
          tick={{ fontSize: 11, fill: 'hsl(var(--muted-foreground))' }}
        />
        <Tooltip
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
        formatter={(v: any) => [Number(v).toFixed(2), 'Composite']}
          contentStyle={{
            fontSize: 12,
            background: 'hsl(var(--card))',
            border: '1px solid hsl(var(--border))',
            borderRadius: 6,
          }}
        />
        <Radar
          dataKey="value"
          stroke={color}
          fill={color}
          fillOpacity={0.18}
          strokeWidth={2}
          dot={{ r: 3, fill: color }}
        />
      </RechartsRadar>
    </ResponsiveContainer>
  )
}
