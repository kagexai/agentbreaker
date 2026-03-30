import { useParams } from 'react-router-dom'
import { useTargetProfile, useTargetAiSummary } from '@/hooks/useApi'
import { PageHeaderRow } from '@/components/layout/PageHeaderRow'
import { DataAge } from '@/components/DataAge'
import { SectionNav } from '@/components/layout/SectionNav'
import { SectionBlock } from '@/components/SectionBlock'
import { Skeleton } from '@/components/ui/skeleton'
import { Card, CardContent, CardHeader } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { ChevronDown } from 'lucide-react'
import { cn } from '@/lib/utils'

const SECTIONS = [
  { id: 'ai-summary', label: 'AI Summary' },
  { id: 'guardrails', label: 'Guardrails' },
  { id: 'attack-angles', label: 'Attack Angles' },
  { id: 'raw-profile', label: 'Raw Data' },
]

export function TargetProfile() {
  const { targetId = '' } = useParams()
  const profile = useTargetProfile(targetId)
  const aiSummary = useTargetAiSummary(targetId)

  if (profile.isLoading) return <div className="grid gap-4"><Skeleton className="h-12" /><Skeleton className="h-24" /><Skeleton className="h-64" /></div>
  if (profile.error) return <p className="text-destructive">Failed to load: {profile.error.message}</p>
  if (!profile.data) return null

  const story = profile.data.profile_story
  const identity = story.identity as Record<string, string>

  return (
    <div className="grid gap-6">
      <div className="flex items-start justify-between gap-4">
        <PageHeaderRow
          crumbs={[
            { label: 'Targets', to: '/targets' },
            { label: targetId, to: `/targets/${encodeURIComponent(targetId)}` },
            { label: 'Profile Story' },
          ]}
          actions={[
            { label: 'Target Deep Dive', href: `/targets/${encodeURIComponent(targetId)}` },
            { label: 'Report API', href: `/api/targets/${encodeURIComponent(targetId)}`, external: true },
          ]}
        />
        <DataAge generatedAt={profile.data.generated_at} onRefresh={() => profile.refetch()} isRefetching={profile.isFetching} />
      </div>

      <SectionNav sections={SECTIONS} />

      {/* ── AI Summary ── */}
      <SectionBlock id="ai-summary" kicker="AI Summary" title="Campaign Intelligence"
        description="LLM-generated narrative and target identity derived from probe responses and attack results.">

        <Card>
          <CardHeader className="pb-2">
            <h3 className="font-semibold">AI Campaign Summary</h3>
            <p className="text-xs text-muted-foreground">Dynamically generated analysis of attack effectiveness and target behavior.</p>
          </CardHeader>
          <CardContent>
            {aiSummary.isLoading ? (
              <Skeleton className="h-20" />
            ) : aiSummary.data ? (
              <p className="text-sm whitespace-pre-wrap leading-relaxed">{String(aiSummary.data.summary ?? JSON.stringify(aiSummary.data, null, 2))}</p>
            ) : (
              <p className="text-sm text-muted-foreground">No AI summary available yet. Run a campaign to generate one.</p>
            )}
          </CardContent>
        </Card>

        {/* Identity card — compact, not duplicating Deep Dive's full stat cards */}
        <Card>
          <CardHeader className="pb-2">
            <h3 className="font-semibold">Target Identity</h3>
            <p className="text-xs text-muted-foreground">Inferred from probe responses during the profiling phase.</p>
          </CardHeader>
          <CardContent>
            {story.headline && <p className="text-sm font-medium mb-3">{story.headline}</p>}
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
              {Object.entries(identity).filter(([, v]) => v).map(([k, v]) => (
                <div key={k}>
                  <span className="text-[10px] text-muted-foreground uppercase tracking-wider block">{k.replace(/_/g, ' ')}</span>
                  <span className="text-sm font-medium">{v}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </SectionBlock>

      {/* ── Guardrails ── */}
      <SectionBlock id="guardrails" kicker="Defense Analysis" title="Guardrails and Refusal Intelligence"
        description="Refusal patterns, behavioral boundaries, and capability signals — the target's defensive posture.">
        <div className="grid lg:grid-cols-2 gap-4">
          <Card>
            <CardHeader className="pb-2">
              <h3 className="font-semibold">Guardrail Patterns</h3>
              <p className="text-xs text-muted-foreground">Refusal types and phrases observed during probing and attacks.</p>
            </CardHeader>
            <CardContent className="grid gap-4">
              {story.guardrail_clues.hard_refusals.length > 0 && (
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-wider text-destructive mb-1.5">Hard Refusals</p>
                  <div className="flex flex-wrap gap-1.5">{story.guardrail_clues.hard_refusals.map((r, i) =>
                    <Badge key={i} className="bg-destructive/10 text-destructive text-xs border border-destructive/20">{r}</Badge>
                  )}</div>
                </div>
              )}
              {story.guardrail_clues.soft_refusals.length > 0 && (
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-wider text-amber-600 dark:text-amber-400 mb-1.5">Soft Refusals</p>
                  <div className="flex flex-wrap gap-1.5">{story.guardrail_clues.soft_refusals.map((r, i) =>
                    <Badge key={i} className="bg-amber-500/10 text-amber-600 dark:text-amber-400 text-xs border border-amber-500/20">{r}</Badge>
                  )}</div>
                </div>
              )}
              {story.guardrail_clues.refusal_phrases.length > 0 && (
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-1.5">Observed Phrases</p>
                  <div className="flex flex-wrap gap-1.5">{story.guardrail_clues.refusal_phrases.map((r, i) =>
                    <Badge key={i} variant="outline" className="text-xs font-mono">{r}</Badge>
                  )}</div>
                </div>
              )}
              {story.guardrail_clues.hard_refusals.length === 0 && story.guardrail_clues.soft_refusals.length === 0 && story.guardrail_clues.refusal_phrases.length === 0 && (
                <p className="text-sm text-muted-foreground">No guardrail patterns detected yet.</p>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <h3 className="font-semibold">Capability Signals</h3>
              <p className="text-xs text-muted-foreground">What the target can and cannot do — inferred from probe responses.</p>
            </CardHeader>
            <CardContent>
              {story.capability_signals.length === 0
                ? <p className="text-sm text-muted-foreground">No capability signals detected.</p>
                : <div className="grid gap-2">
                    {story.capability_signals.map((s, i) => (
                      <div key={i} className="flex items-center justify-between text-sm">
                        <span>{s.name}</span>
                        <Badge
                          variant="outline"
                          className={cn('text-[10px]',
                            s.state === 'confirmed' ? 'bg-emerald-500/10 text-emerald-600 border-emerald-500/20'
                            : s.state === 'not_detected' ? 'bg-muted text-muted-foreground'
                            : 'bg-amber-500/10 text-amber-600 border-amber-500/20',
                          )}
                        >
                          {s.state.replace(/_/g, ' ')}
                        </Badge>
                      </div>
                    ))}
                  </div>
              }
            </CardContent>
          </Card>
        </div>
      </SectionBlock>

      {/* ── Attack Angles ── */}
      <SectionBlock id="attack-angles" kicker="Offensive Intel" title="Domain-Tailored Attack Angles"
        description="Custom attack ideas generated from the target's deployment type, industry, and behavioral profile.">
        <div className="grid lg:grid-cols-2 gap-4">
          <Card>
            <CardHeader className="pb-2">
              <h3 className="font-semibold">Tailored Angles</h3>
              <p className="text-xs text-muted-foreground">Attack strategies specific to this target's domain and deployment.</p>
            </CardHeader>
            <CardContent>
              {story.domain_angles.length === 0
                ? <p className="text-sm text-muted-foreground">No domain angles available. Run a profile probe first.</p>
                : <div className="grid gap-3">{story.domain_angles.map((s, i) => (
                    <div key={i} className="p-2.5 rounded-lg bg-muted/30 border border-border/50">
                      <span className="text-sm font-medium">{s.name || s.category}</span>
                      {s.description && <p className="text-xs text-muted-foreground mt-0.5 leading-relaxed">{s.description}</p>}
                    </div>
                  ))}</div>
              }
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <h3 className="font-semibold">Multimodal Surface</h3>
              <p className="text-xs text-muted-foreground">Image, document, and multi-turn capabilities that expand the attack surface.</p>
            </CardHeader>
            <CardContent>
              {story.multimodal_surface && Object.keys(story.multimodal_surface).length > 0 ? (
                <div className="grid gap-2">
                  {Object.entries(story.multimodal_surface).map(([k, v]) => (
                    <div key={k} className="flex items-center justify-between text-sm">
                      <span>{k.replace(/_/g, ' ')}</span>
                      <Badge
                        variant="outline"
                        className={cn('text-[10px]',
                          v === true || v === 'confirmed' ? 'bg-emerald-500/10 text-emerald-600 border-emerald-500/20'
                          : v === false || v === 'not_detected' ? 'bg-muted text-muted-foreground'
                          : '',
                        )}
                      >
                        {String(v)}
                      </Badge>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-muted-foreground">No multimodal data available.</p>
              )}
            </CardContent>
          </Card>
        </div>
      </SectionBlock>

      {/* ── Raw Profile ── */}
      <SectionBlock id="raw-profile" kicker="Raw Data" title="Probe Data">
        <Collapsible>
          <Card>
            <CollapsibleTrigger className="w-full">
              <CardHeader className="pb-2 flex flex-row items-center justify-between">
                <div>
                  <h3 className="font-semibold text-left">Raw Profile Snapshot</h3>
                  <p className="text-xs text-muted-foreground text-left">Complete probe response data as JSON.</p>
                </div>
                <ChevronDown className="w-4 h-4 text-muted-foreground shrink-0" />
              </CardHeader>
            </CollapsibleTrigger>
            <CollapsibleContent>
              <CardContent>
                <pre className="text-xs bg-muted/50 p-3 rounded overflow-auto max-h-[600px] font-mono leading-relaxed">{JSON.stringify(profile.data.profile, null, 2)}</pre>
              </CardContent>
            </CollapsibleContent>
          </Card>
        </Collapsible>
      </SectionBlock>
    </div>
  )
}
