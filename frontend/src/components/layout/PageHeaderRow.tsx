import { Link } from 'react-router-dom'
import { ChevronRight } from 'lucide-react'
import { cn } from '@/lib/utils'

interface Crumb {
  label: string
  to?: string
}

interface Action {
  label: string
  href: string
  external?: boolean
}

interface PageHeaderRowProps {
  crumbs: Crumb[]
  actions?: Action[]
  className?: string
}

export function PageHeaderRow({ crumbs, actions = [], className }: PageHeaderRowProps) {
  return (
    <div className={cn('flex items-center justify-between flex-wrap gap-3 mb-5', className)}>
      <nav className="flex items-center gap-1 text-sm text-muted-foreground" aria-label="Breadcrumb">
        {crumbs.map((crumb, i) => (
          <span key={i} className="flex items-center gap-1">
            {i > 0 && <ChevronRight className="w-3.5 h-3.5 opacity-40" />}
            {crumb.to ? (
              <Link to={crumb.to} className="hover:text-foreground hover:underline transition-colors text-primary">
                {crumb.label}
              </Link>
            ) : (
              <strong className="text-foreground font-medium">{crumb.label}</strong>
            )}
          </span>
        ))}
      </nav>
      {actions.length > 0 && (
        <div className="flex items-center gap-2">
          {actions.map((action) =>
            action.external ? (
              <a
                key={action.label}
                href={action.href}
                target="_blank"
                rel="noopener noreferrer"
                className="px-3 py-1 text-xs font-medium rounded-full border border-border bg-card text-muted-foreground hover:text-primary hover:border-primary/30 hover:bg-primary/5 transition-colors"
              >
                {action.label}
              </a>
            ) : (
              <Link
                key={action.label}
                to={action.href}
                className="px-3 py-1 text-xs font-medium rounded-full border border-border bg-card text-muted-foreground hover:text-primary hover:border-primary/30 hover:bg-primary/5 transition-colors"
              >
                {action.label}
              </Link>
            )
          )}
        </div>
      )}
    </div>
  )
}
