import { cn } from '@/lib/utils'

interface RiskBadgeProps {
  level: 'high' | 'medium' | 'low' | string
  className?: string
}

export function RiskBadge({ level, className }: RiskBadgeProps) {
  const l = level?.toLowerCase()
  return (
    <span
      className={cn(
        'inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold',
        l === 'high' && 'bg-destructive/15 text-destructive',
        l === 'medium' && 'bg-secondary/15 text-secondary',
        l === 'low' && 'bg-primary/15 text-primary',
        !['high', 'medium', 'low'].includes(l) && 'bg-muted text-muted-foreground',
        className
      )}
    >
      {level}
    </span>
  )
}

export function statusVariant(status: string): string {
  switch (status?.toLowerCase()) {
    case 'validated': return 'bg-primary/15 text-primary'
    case 'tested': return 'bg-secondary/15 text-secondary'
    case 'coverage_gap': return 'bg-destructive/15 text-destructive'
    default: return 'bg-muted text-muted-foreground'
  }
}
