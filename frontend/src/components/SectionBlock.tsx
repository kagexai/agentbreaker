import { cn } from '@/lib/utils'
import type { ReactNode } from 'react'

interface SectionBlockProps {
  id: string
  kicker?: string
  title: string
  description?: string
  children: ReactNode
  className?: string
}

export function SectionBlock({ id, kicker, title, description, children, className }: SectionBlockProps) {
  return (
    <section
      id={id}
      className={cn('grid gap-4 scroll-mt-28', className)}
    >
      <div>
        {kicker && (
          <p className="text-xs uppercase tracking-widest text-muted-foreground mb-1">{kicker}</p>
        )}
        <h2 className="text-2xl font-bold">{title}</h2>
        {description && (
          <p className="mt-1.5 text-sm text-muted-foreground max-w-3xl">{description}</p>
        )}
      </div>
      {children}
    </section>
  )
}
