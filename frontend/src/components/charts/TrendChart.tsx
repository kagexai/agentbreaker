import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts'
import type { TrendPoint } from '@/lib/api'

interface TrendChartProps {
  data: TrendPoint[]
  height?: number
}

export function TrendChart({ data, height = 260 }: TrendChartProps) {
  if (!data.length) {
    return <p className="text-sm text-muted-foreground py-6 text-center">No trend data yet.</p>
  }

  return (
    <ResponsiveContainer width="100%" height={height}>
      <LineChart data={data} margin={{ left: 0, right: 40, top: 8, bottom: 4 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="currentColor" strokeOpacity={0.08} />
        <XAxis dataKey="index" tick={{ fontSize: 11 }} label={{ value: 'Eval #', position: 'insideBottomRight', offset: -8, fontSize: 11 }} />
        <YAxis yAxisId="composite" domain={[0, 10]} tickFormatter={(v: number) => v.toFixed(1)} tick={{ fontSize: 11 }} />
        <YAxis yAxisId="asr" orientation="right" domain={[0, 1]} tickFormatter={(v: number) => v.toFixed(2)} tick={{ fontSize: 11 }} />
        {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
        <Tooltip formatter={(v: any, name: any) => [Number(v).toFixed(3), name]} labelFormatter={(i) => `Eval #${i}`} />
        <Legend />
        <Line yAxisId="composite" type="monotone" dataKey="composite_score" stroke="#0f766e" strokeWidth={2} dot={data.length < 50 ? { r: 3 } : false} name="Composite" />
        <Line yAxisId="asr" type="monotone" dataKey="asr" stroke="#c2410c" strokeWidth={2} dot={data.length < 50 ? { r: 3 } : false} name="ASR" />
      </LineChart>
    </ResponsiveContainer>
  )
}
