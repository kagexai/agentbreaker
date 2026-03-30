import { useEffect, useRef } from 'react'
import { cn } from '@/lib/utils'

interface Section {
  id: string
  label: string
}

interface SectionNavProps {
  sections: Section[]
  className?: string
}

export function SectionNav({ sections, className }: SectionNavProps) {
  const navRef = useRef<HTMLElement>(null)

  useEffect(() => {
    const anchors = navRef.current?.querySelectorAll('a[data-section]')
    if (!anchors?.length) return

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) {
            anchors.forEach((a) => {
              a.classList.toggle('active-section', a.getAttribute('data-section') === e.target.id)
            })
          }
        })
      },
      { rootMargin: '-20% 0px -70% 0px', threshold: 0 }
    )

    sections.forEach(({ id }) => {
      const el = document.getElementById(id)
      if (el) observer.observe(el)
    })

    return () => observer.disconnect()
  }, [sections])

  return (
    <nav
      ref={navRef}
      className={cn(
        'flex flex-wrap gap-2 py-2 sticky top-14 z-40 bg-background border-b border-border mb-6',
        className
      )}
    >
      {sections.map(({ id, label }) => (
        <a
          key={id}
          href={`#${id}`}
          data-section={id}
          className={cn(
            'px-3 py-1.5 rounded-full border border-border bg-card text-muted-foreground',
            'text-xs font-bold uppercase tracking-wider transition-colors',
            'hover:text-primary hover:bg-primary/5 hover:border-primary/20',
            '[&.active-section]:text-primary [&.active-section]:bg-primary/8 [&.active-section]:border-primary/20'
          )}
          onClick={(e) => {
            e.preventDefault()
            document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
          }}
        >
          {label}
        </a>
      ))}
    </nav>
  )
}
