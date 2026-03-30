import { useState, useMemo } from 'react'
import { useTaxonomy, useArcDimension, useSeedListing } from '@/hooks/useApi'
import { DataAge } from '@/components/DataAge'
import { Skeleton } from '@/components/ui/skeleton'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { ChevronDown, ChevronRight, Search } from 'lucide-react'
import type { TaxonomyCategory, ArcEntry, SeedEntry } from '@/lib/api'

// ── Attack Taxonomy Tab ───────────────────────────────────────────────────────

function DifficultyBadge({ range }: { range: [number, number] }) {
  const [min, max] = range
  const avg = (min + max) / 2
  const cls =
    avg <= 2 ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400'
    : avg <= 3.5 ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400'
    : 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400'
  return (
    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium ${cls}`}>
      D{min}–{max}
    </span>
  )
}

function CategoryCard({ cat }: { cat: TaxonomyCategory }) {
  const [open, setOpen] = useState(false)
  return (
    <Collapsible open={open} onOpenChange={setOpen}>
      <CollapsibleTrigger asChild>
        <button className="w-full flex items-center gap-3 px-4 py-3 bg-card border border-border rounded-lg hover:bg-accent/50 transition-colors text-left">
          <span className="text-muted-foreground mt-0.5 flex-shrink-0">
            {open ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          </span>
          <span className="font-medium text-sm flex-1 font-mono">{cat.id}</span>
          <span className="text-xs text-muted-foreground hidden sm:block flex-1">{cat.description}</span>
          <div className="flex items-center gap-2 flex-shrink-0">
            {cat.owasp.map(ref => (
              <Badge key={ref} variant="outline" className="text-xs">{ref}</Badge>
            ))}
            <DifficultyBadge range={cat.difficulty} />
            {cat.requires && (
              <Badge variant="secondary" className="text-xs">{cat.requires}</Badge>
            )}
            <span className="text-xs text-muted-foreground">{cat.subcategory_count} subcats</span>
          </div>
        </button>
      </CollapsibleTrigger>
      <CollapsibleContent>
        <div className="mt-1 ml-7 space-y-2 pb-2">
          {cat.benchmarks.length > 0 && (
            <div className="flex gap-1 flex-wrap px-3">
              {cat.benchmarks.map(b => (
                <span key={b} className="text-xs bg-muted px-2 py-0.5 rounded text-muted-foreground">{b}</span>
              ))}
            </div>
          )}
          {cat.subcategories.map(sub => (
            <div key={sub.id} className="border border-border/60 rounded-lg px-4 py-3 bg-muted/20">
              <div className="flex items-start gap-2 flex-wrap">
                <span className="text-xs font-mono text-muted-foreground font-medium">{sub.id}</span>
                {sub.requires && (
                  <Badge variant="secondary" className="text-xs">{sub.requires}</Badge>
                )}
                {sub.seed_count > 0 && (
                  <span className="text-xs text-muted-foreground">{sub.seed_count} seeds</span>
                )}
              </div>
              {sub.description && (
                <p className="text-xs text-muted-foreground mt-1">{sub.description}</p>
              )}
              {sub.strategies.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-2">
                  {sub.strategies.map(s => (
                    <Badge key={s} className="text-xs font-mono">{s}</Badge>
                  ))}
                </div>
              )}
              {(sub.arc_techniques.length > 0 || sub.arc_evasions.length > 0) && (
                <div className="flex flex-wrap gap-1 mt-1.5">
                  {sub.arc_techniques.map(t => (
                    <span key={t} className="text-xs bg-blue-50 text-blue-700 dark:bg-blue-900/20 dark:text-blue-400 px-1.5 py-0.5 rounded">{t}</span>
                  ))}
                  {sub.arc_evasions.map(e => (
                    <span key={e} className="text-xs bg-purple-50 text-purple-700 dark:bg-purple-900/20 dark:text-purple-400 px-1.5 py-0.5 rounded">{e}</span>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      </CollapsibleContent>
    </Collapsible>
  )
}

function AttackTaxonomyTab() {
  const { data, isLoading } = useTaxonomy()

  if (isLoading) return (
    <div className="space-y-3">
      {Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-12 w-full" />)}
    </div>
  )
  if (!data) return <p className="text-sm text-muted-foreground">No taxonomy data.</p>

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-6 text-sm text-muted-foreground">
        <span><strong className="text-foreground">{data.category_count}</strong> categories</span>
        <span><strong className="text-foreground">{data.strategy_count}</strong> strategies</span>
        {Object.entries(data.arc_dimension_counts).map(([dim, count]) => (
          <span key={dim}><strong className="text-foreground">{count}</strong> Arc {dim}</span>
        ))}
      </div>
      <div className="space-y-2">
        {data.categories.map(cat => <CategoryCard key={cat.id} cat={cat} />)}
      </div>
    </div>
  )
}

// ── Arc Intelligence Tab ──────────────────────────────────────────────────────

const DIMENSION_LABELS: Record<string, string> = {
  inputs: 'Inputs',
  techniques: 'Techniques',
  evasions: 'Evasions',
  intents: 'Intents',
  intent_leaves: 'Intent Leaves',
  intent_playbooks: 'Intent Playbooks',
  technique_playbooks: 'Technique Playbooks',
  evasion_playbooks: 'Evasion Playbooks',
}

const DIMENSION_COLORS: Record<string, string> = {
  inputs: 'bg-sky-100 text-sky-700 dark:bg-sky-900/30 dark:text-sky-400',
  techniques: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400',
  evasions: 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400',
  intents: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400',
  intent_leaves: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400',
  intent_playbooks: 'bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-400',
  technique_playbooks: 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-400',
  evasion_playbooks: 'bg-violet-100 text-violet-700 dark:bg-violet-900/30 dark:text-violet-400',
}

function ArcEntryCard({ entry }: { entry: ArcEntry }) {
  const colorCls = DIMENSION_COLORS[entry.dimension] ?? 'bg-muted text-muted-foreground'
  return (
    <Card className="p-0 overflow-hidden">
      <CardContent className="px-4 py-3 space-y-2">
        <div className="flex items-center gap-2 flex-wrap">
          <span className={`text-xs px-1.5 py-0.5 rounded font-medium ${colorCls}`}>
            {DIMENSION_LABELS[entry.dimension] ?? entry.dimension}
          </span>
          <span className="text-xs font-mono text-muted-foreground">{entry.id}</span>
        </div>
        <p className="text-sm font-medium">{entry.title}</p>
        {entry.description && (
          <p className="text-xs text-muted-foreground leading-relaxed">{entry.description}</p>
        )}
        {entry.ideas.length > 0 && (
          <ul className="space-y-0.5">
            {entry.ideas.slice(0, 4).map((idea, i) => (
              <li key={i} className="text-xs text-muted-foreground flex gap-1.5">
                <span className="text-muted-foreground/50 select-none">•</span>
                {idea}
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}

function ArcIntelligenceTab() {
  const { data: taxonomy } = useTaxonomy()
  const [activeDimension, setActiveDimension] = useState<string | null>(null)
  const [search, setSearch] = useState('')

  const { data, isLoading } = useArcDimension(activeDimension)

  const dimensions = taxonomy?.arc_dimensions ?? []
  const primaryDims = dimensions.filter(d => !d.includes('playbook') && d !== 'intent_leaves')

  const filtered = useMemo(() => {
    const entries = data?.entries ?? []
    if (!search.trim()) return entries
    const q = search.toLowerCase()
    return entries.filter((e: ArcEntry) =>
      e.title.toLowerCase().includes(q) ||
      e.description.toLowerCase().includes(q) ||
      e.id.toLowerCase().includes(q)
    )
  }, [data?.entries, search])

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="flex gap-2 flex-wrap">
          <Button
            variant={activeDimension === null ? 'default' : 'outline'}
            size="sm"
            onClick={() => setActiveDimension(null)}
          >
            All
          </Button>
          {primaryDims.map(dim => (
            <Button
              key={dim}
              variant={activeDimension === dim ? 'default' : 'outline'}
              size="sm"
              onClick={() => setActiveDimension(dim)}
            >
              {DIMENSION_LABELS[dim] ?? dim}
            </Button>
          ))}
        </div>
        <div className="relative ml-auto w-full sm:w-64">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input
            className="pl-8 h-9"
            placeholder="Search entries..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
      </div>

      {isLoading ? (
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {Array.from({ length: 9 }).map((_, i) => <Skeleton key={i} className="h-32" />)}
        </div>
      ) : (
        <>
          <p className="text-xs text-muted-foreground">
            {filtered.length} entr{filtered.length === 1 ? 'y' : 'ies'}
            {search && ` matching "${search}"`}
          </p>
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {filtered.map((entry: ArcEntry) => (
              <ArcEntryCard key={`${entry.dimension}:${entry.id}`} entry={entry} />
            ))}
          </div>
        </>
      )}
    </div>
  )
}

// ── Seed Library Tab ──────────────────────────────────────────────────────────

function SeedCard({ seed }: { seed: SeedEntry }) {
  const isEnterprise = seed.tier === 'enterprise'
  return (
    <Card className="overflow-hidden">
      <CardHeader className="px-4 py-3 pb-2">
        <div className="flex items-start justify-between gap-2">
          <CardTitle className="text-sm font-mono font-medium leading-tight">{seed.name}</CardTitle>
          <div className="flex gap-1.5 flex-shrink-0">
            {isEnterprise ? (
              <Badge className="bg-amber-500/15 text-amber-700 dark:text-amber-400 border-amber-300/30 text-xs">
                Enterprise
              </Badge>
            ) : (
              <Badge variant="outline" className="text-xs">Community</Badge>
            )}
            {seed.owasp && <Badge variant="outline" className="text-xs">{seed.owasp}</Badge>}
          </div>
        </div>
        <p className="text-xs text-muted-foreground font-mono">{seed.path}</p>
      </CardHeader>
      <CardContent className="px-4 pb-3 space-y-2">
        {seed.notes && <p className="text-xs text-muted-foreground">{seed.notes}</p>}
        {seed.preview && !isEnterprise && (
          <pre className="text-xs bg-muted/50 rounded p-2 overflow-x-auto whitespace-pre-wrap font-mono text-muted-foreground max-h-28">
            {seed.preview}
          </pre>
        )}
        {isEnterprise && (
          <div className="text-xs text-muted-foreground italic border border-dashed border-amber-300/40 rounded p-2 bg-amber-50/30 dark:bg-amber-900/10">
            Preview available with an Enterprise license.
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function SeedLibraryTab() {
  const { data: taxonomy } = useTaxonomy()
  const [categoryFilter, setCategoryFilter] = useState<string>('all')
  const [strategyFilter, setStrategyFilter] = useState<string>('all')

  const categories = taxonomy?.categories.map(c => c.id) ?? []
  const strategies = useMemo(() => {
    if (!taxonomy) return []
    if (categoryFilter === 'all') return taxonomy.strategy_index.map(s => s.id)
    const cat = taxonomy.categories.find(c => c.id === categoryFilter)
    if (!cat) return []
    return cat.subcategories.flatMap(s => s.strategies)
  }, [taxonomy, categoryFilter])

  const { data, isLoading } = useSeedListing(
    categoryFilter === 'all' ? null : categoryFilter,
    strategyFilter === 'all' ? null : strategyFilter,
  )

  function handleCategoryChange(val: string) {
    setCategoryFilter(val)
    setStrategyFilter('all')
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row gap-3">
        <Select value={categoryFilter} onValueChange={handleCategoryChange}>
          <SelectTrigger className="w-full sm:w-52">
            <SelectValue placeholder="All categories" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All categories</SelectItem>
            {categories.map(c => (
              <SelectItem key={c} value={c}>{c}</SelectItem>
            ))}
          </SelectContent>
        </Select>

        {categoryFilter !== 'all' && strategies.length > 0 && (
          <Select value={strategyFilter} onValueChange={setStrategyFilter}>
            <SelectTrigger className="w-full sm:w-52">
              <SelectValue placeholder="All strategies" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All strategies</SelectItem>
              {strategies.map(s => (
                <SelectItem key={s} value={s}>{s}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}

        {data && (
          <span className="text-xs text-muted-foreground self-center sm:ml-auto">
            {data.count} seed{data.count !== 1 ? 's' : ''}
          </span>
        )}
      </div>

      {isLoading ? (
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-40" />)}
        </div>
      ) : data?.seeds.length === 0 ? (
        <p className="text-sm text-muted-foreground py-8 text-center">No seeds found for the selected filters.</p>
      ) : (
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {(data?.seeds ?? []).map((seed: SeedEntry) => (
            <SeedCard key={seed.path} seed={seed} />
          ))}
        </div>
      )}
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function Taxonomy() {
  const { data, refetch, isRefetching } = useTaxonomy()

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold">Taxonomy</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Attack categories, Arc PI intelligence, and seed library
          </p>
        </div>
        {data && <DataAge generatedAt={data.generated_at} onRefresh={refetch} isRefetching={isRefetching} />}
      </div>

      <Tabs defaultValue="taxonomy">
        <TabsList>
          <TabsTrigger value="taxonomy">Attack Taxonomy</TabsTrigger>
          <TabsTrigger value="arc">Arc PI Intelligence</TabsTrigger>
          <TabsTrigger value="seeds">Seed Library</TabsTrigger>
        </TabsList>

        <TabsContent value="taxonomy" className="mt-4">
          <AttackTaxonomyTab />
        </TabsContent>

        <TabsContent value="arc" className="mt-4">
          <ArcIntelligenceTab />
        </TabsContent>

        <TabsContent value="seeds" className="mt-4">
          <SeedLibraryTab />
        </TabsContent>
      </Tabs>
    </div>
  )
}
