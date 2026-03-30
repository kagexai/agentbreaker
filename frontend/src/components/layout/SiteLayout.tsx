import { NavLink, Outlet } from 'react-router-dom'
import { Moon, Sun, Shield } from 'lucide-react'
import { useState, useEffect } from 'react'
import { cn } from '@/lib/utils'

const NAV_LINKS = [
  { to: '/', label: 'Home', exact: true },
  { to: '/targets', label: 'Targets' },
  { to: '/coverage', label: 'Coverage & Frameworks' },
  { to: '/regressions', label: 'Regressions' },
  { to: '/taxonomy', label: 'Taxonomy' },
  { to: '/ops', label: 'Operations' },
]

export function SiteLayout() {
  const [dark, setDark] = useState(() =>
    typeof window !== 'undefined'
      ? localStorage.getItem('theme') === 'dark'
      : false
  )

  useEffect(() => {
    document.documentElement.classList.toggle('dark', dark)
    localStorage.setItem('theme', dark ? 'dark' : 'light')
  }, [dark])

  return (
    <div className="min-h-screen bg-background text-foreground">
      <header className="border-b border-border bg-card/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-[1320px] mx-auto px-6 flex items-center gap-6 h-14">
          <NavLink to="/" className="flex items-center gap-2 text-primary font-semibold shrink-0">
            <Shield className="w-5 h-5" />
            AgentBreaker
          </NavLink>
          <nav className="flex items-center gap-1 flex-1">
            {NAV_LINKS.map(({ to, label, exact }) => (
              <NavLink
                key={to}
                to={to}
                end={exact}
                className={({ isActive }) =>
                  cn(
                    'px-3 py-1.5 rounded-md text-sm font-medium transition-colors',
                    isActive
                      ? 'bg-primary/10 text-primary'
                      : 'text-muted-foreground hover:text-foreground hover:bg-muted'
                  )
                }
              >
                {label}
              </NavLink>
            ))}
          </nav>
          <button
            onClick={() => setDark(d => !d)}
            className="p-2 rounded-md text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
            aria-label="Toggle theme"
          >
            {dark ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
          </button>
        </div>
      </header>
      <main className="max-w-[1320px] mx-auto px-6 py-8">
        <Outlet />
      </main>
    </div>
  )
}
