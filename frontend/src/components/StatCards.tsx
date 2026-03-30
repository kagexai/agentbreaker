import { Card, CardContent } from '@/components/ui/card'
import { cn } from '@/lib/utils'

export interface StatCard {
  label: string
  value: string | number
  meta?: string
}

interface StatCardsProps {
  cards: StatCard[]
  className?: string
}

export function StatCards({ cards, className }: StatCardsProps) {
  return (
    <div className={cn('grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3', className)}>
      {cards.map((card, i) => (
        <Card key={i} className="py-0">
          <CardContent className="p-4">
            <div className="text-xs text-muted-foreground uppercase tracking-wider mb-1">{card.label}</div>
            <div className="text-2xl font-bold text-foreground">{card.value}</div>
            {card.meta && <div className="text-xs text-muted-foreground mt-1">{card.meta}</div>}
          </CardContent>
        </Card>
      ))}
    </div>
  )
}
