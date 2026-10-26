import { NavLink, Outlet } from 'react-router-dom'
import { Moon, Sun } from 'lucide-react'
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

const THEME_KEY = 'kagex_theme'

export function SiteLayout() {
  const [dark, setDark] = useState(() => {
    if (typeof window === 'undefined') return true
    return localStorage.getItem(THEME_KEY) !== 'light'
  })

  useEffect(() => {
    document.documentElement.classList.toggle('dark', dark)
    document.documentElement.dataset.theme = dark ? 'dark' : 'light'
    localStorage.setItem(THEME_KEY, dark ? 'dark' : 'light')
    document.querySelector('meta[name="theme-color"]')?.setAttribute('content', dark ? '#111214' : '#fbfbfb')
  }, [dark])

  return (
    <div className="min-h-screen bg-background text-foreground">
      <header className="border-b border-border bg-card/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-[80rem] mx-auto px-8 flex items-center gap-6 min-h-[4.5rem]">
          <NavLink to="/" className="flex items-center gap-2.5 shrink-0">
            <img src="/logoW.svg" alt="" className="hidden dark:block h-8 w-8" />
            <img src="/logo.svg" alt="" className="block dark:hidden h-8 w-8" />
            <span className="leading-none">
              <span className="block font-extrabold tracking-[-0.04em] text-foreground">KageX</span>
              <span className="kagex-label text-muted-foreground">AgentBreaker</span>
            </span>
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
      <main className="max-w-[80rem] mx-auto px-8 py-8">
        <Outlet />
      </main>
    </div>
  )
}
