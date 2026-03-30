import { useState, useEffect } from 'react'
import { RefreshCw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'

function relativeAge(isoString: string): string {
  const diff = Date.now() - new Date(isoString).getTime()
  const mins = Math.floor(diff / 60_000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

export function DataAge({ generatedAt, onRefresh, isRefetching }: {
  generatedAt: string
  onRefresh: () => void
  isRefetching?: boolean
}) {
  const [age, setAge] = useState(() => relativeAge(generatedAt))

  useEffect(() => {
    setAge(relativeAge(generatedAt))
    const id = setInterval(() => setAge(relativeAge(generatedAt)), 30_000)
    return () => clearInterval(id)
  }, [generatedAt])

  return (
    <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
      <span>Updated {age}</span>
      <Button
        variant="ghost"
        size="sm"
        className="h-6 px-2 text-xs gap-1"
        onClick={onRefresh}
        disabled={isRefetching}
      >
        <RefreshCw className={cn('w-3 h-3', isRefetching && 'animate-spin')} />
        Refresh
      </Button>
    </div>
  )
}
