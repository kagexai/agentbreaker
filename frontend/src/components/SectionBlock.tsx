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
          <p className="kagex-label kagex-kicker text-muted-foreground mb-2">{kicker}</p>
        )}
        <h2 className="text-[1.45rem] font-bold tracking-[-0.03em]">{title}</h2>
        {description && (
          <p className="mt-1.5 text-sm text-muted-foreground max-w-3xl">{description}</p>
        )}
      </div>
      {children}
    </section>
  )
}
