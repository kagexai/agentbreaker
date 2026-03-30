import { useEffect, useState, useMemo, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  getJson,
  postJson,
  type OverviewPayload,
  type CoveragePayload,
  type AtlasPayload,
  type OwaspPayload,
  type RegressionsPayload,
  type OpsPayload,
  type TargetReport,
  type ProfileStoryPayload,
  type TaxonomyPayload,
  type ArcDimensionPayload,
  type SeedListingPayload,
  type LiveEvent,
  type LivePlanEvent,
  type LiveJudgeEvent,
  type LiveLogEvent,
  type LiveResultEvent,
} from '@/lib/api'

export function useOverview() {
  return useQuery({
    queryKey: ['overview'],
    queryFn: () => getJson<OverviewPayload>('/api/overview'),
  })
}

export function useCoverage() {
  return useQuery({
    queryKey: ['coverage'],
    queryFn: () => getJson<CoveragePayload>('/api/coverage'),
  })
}

export function useAtlas() {
  return useQuery({
    queryKey: ['atlas'],
    queryFn: () => getJson<AtlasPayload>('/api/atlas'),
  })
}

export function useOwasp() {
  return useQuery({
    queryKey: ['owasp'],
    queryFn: () => getJson<OwaspPayload>('/api/owasp'),
  })
}

export function useRegressions() {
  return useQuery({
    queryKey: ['regressions'],
    queryFn: () => getJson<RegressionsPayload>('/api/regressions'),
  })
}

export function useOps() {
  return useQuery({
    queryKey: ['ops'],
    queryFn: () => getJson<OpsPayload>('/api/ops'),
    refetchInterval: 5000,
  })
}

export function useTargetReport(targetId: string) {
  return useQuery({
    queryKey: ['target', targetId],
    queryFn: () => getJson<TargetReport>(`/api/targets/${encodeURIComponent(targetId)}`),
    enabled: !!targetId,
  })
}

export function useTargetProfile(targetId: string) {
  return useQuery({
    queryKey: ['target-profile', targetId],
    queryFn: () => getJson<ProfileStoryPayload>(`/api/targets/${encodeURIComponent(targetId)}/profile-story`),
    enabled: !!targetId,
  })
}

export function useTargetAiSummary(targetId: string) {
  return useQuery({
    queryKey: ['target-ai-summary', targetId],
    queryFn: () => getJson<{ target_id: string; generated_at: string; summary: string }>(`/api/targets/${encodeURIComponent(targetId)}/ai-summary`),
    enabled: !!targetId,
  })
}

export function useTaxonomy() {
  return useQuery({
    queryKey: ['taxonomy'],
    queryFn: () => getJson<TaxonomyPayload>('/api/taxonomy'),
    staleTime: 5 * 60 * 1000,
  })
}

export function useArcDimension(dimension: string | null) {
  const param = dimension ? `?dimension=${encodeURIComponent(dimension)}` : ''
  return useQuery({
    queryKey: ['taxonomy-arc', dimension],
    queryFn: () => getJson<ArcDimensionPayload>(`/api/taxonomy/arc${param}`),
    staleTime: 5 * 60 * 1000,
  })
}

export function useSeedListing(category: string | null, strategy: string | null) {
  const params = new URLSearchParams()
  if (category) params.set('category', category)
  if (strategy) params.set('strategy', strategy)
  const qs = params.toString() ? `?${params.toString()}` : ''
  return useQuery({
    queryKey: ['taxonomy-seeds', category, strategy],
    queryFn: () => getJson<SeedListingPayload>(`/api/taxonomy/seeds${qs}`),
    staleTime: 5 * 60 * 1000,
  })
}

// ── Mutations ────────────────────────────────────────────────────────────────

export function useLaunchScan() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (payload: Record<string, unknown>) => postJson('/api/ops/scan', payload),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ops'] }),
  })
}

export function useAddTarget() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (payload: Record<string, unknown>) => postJson('/api/ops/add-target', payload),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['ops'] })
      qc.invalidateQueries({ queryKey: ['overview'] })
    },
  })
}

export function useRemoveTarget() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (targetId: string) => postJson('/api/ops/remove-target', { target_id: targetId }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['ops'] })
      qc.invalidateQueries({ queryKey: ['overview'] })
    },
  })
}

export function useStopJob() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (jobId: string) => postJson(`/api/ops/jobs/${jobId}/stop`, {}),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ops'] }),
  })
}

export function useAddApi() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (payload: Record<string, unknown>) => postJson('/api/ops/add-api', payload),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ops'] }),
  })
}

// ── Live attack stream ────────────────────────────────────────────────────────

export type AttackStep = 'plan' | 'generate' | 'judge' | 'result'

export interface AttackState {
  attack_id: string
  strategy_id?: string
  category?: string
  target_field?: string
  framing?: string
  variant_index?: number
  step: AttackStep
  composite?: number
  asr?: number
  status?: string
  failure_mode?: string
  response_cluster?: string
  recommended_next_family?: string
  breach_hint?: boolean
  partial_leak?: boolean
  judge_reasoning?: string
  vulnerability?: number
  reliability?: number
  trials: number
  payload_text?: string
  response_text?: string
}

export interface StrategyBucket {
  total: number
  kept: number
  partial: number
  avgComposite: number
  bestComposite: number
}

export type StreamStatus = 'idle' | 'connecting' | 'live' | 'done' | 'error'

export function useLiveAttackStream(jobId: string | null) {
  const [events, setEvents] = useState<LiveEvent[]>([])
  const [streamStatus, setStreamStatus] = useState<StreamStatus>('idle')
  const streamStartedAtRef = useRef(0)
  const bufferRef = useRef<LiveEvent[]>([])
  const flushTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const retryCountRef = useRef(0)
  const retryTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    if (!jobId) {
      setEvents([])
      setStreamStatus('idle')
      streamStartedAtRef.current = 0
      bufferRef.current = []
      retryCountRef.current = 0
      if (flushTimerRef.current) clearTimeout(flushTimerRef.current)
      if (retryTimerRef.current) clearTimeout(retryTimerRef.current)
      return
    }

    let es: EventSource | null = null
    let cancelled = false

    const flushBuffer = () => {
      flushTimerRef.current = null
      const batch = bufferRef.current
      if (batch.length === 0) return
      bufferRef.current = []
      setEvents(prev => {
        const next = prev.concat(batch)
        return next.length > 10000 ? next.slice(-10000) : next
      })
    }

    function connect() {
      if (cancelled) return
      setStreamStatus('connecting')
      es = new EventSource(`/api/ops/jobs/${encodeURIComponent(jobId!)}/stream`)

      es.onmessage = (e: MessageEvent) => {
        let event: LiveEvent
        try { event = JSON.parse(e.data) as LiveEvent } catch { return }
        retryCountRef.current = 0 // reset on successful message
        if (event.type === 'heartbeat') {
          setStreamStatus('live')
        } else if (event.type === 'done') {
          setStreamStatus('done')
          flushBuffer()
          es?.close()
        } else {
          if (!streamStartedAtRef.current) streamStartedAtRef.current = Date.now()
          bufferRef.current.push(event)
          if (!flushTimerRef.current) {
            flushTimerRef.current = setTimeout(flushBuffer, 200)
          }
        }
      }

      es.onerror = () => {
        es?.close()
        if (cancelled) return
        retryCountRef.current++
        if (retryCountRef.current > 10) {
          setStreamStatus('error')
          return
        }
        setStreamStatus('connecting')
        const delay = Math.min(1000 * Math.pow(2, retryCountRef.current - 1), 30000)
        retryTimerRef.current = setTimeout(connect, delay)
      }
    }

    connect()

    return () => {
      cancelled = true
      if (flushTimerRef.current) clearTimeout(flushTimerRef.current)
      if (retryTimerRef.current) clearTimeout(retryTimerRef.current)
      es?.close()
    }
  }, [jobId])

  const attacks = useMemo(() => {
    const map = new Map<string, AttackState>()
    for (const ev of events) {
      if (ev.type === 'plan') {
        const e = ev as LivePlanEvent
        map.set(e.attack_id, {
          attack_id: e.attack_id,
          strategy_id: e.strategy_id,
          target_field: e.target_field,
          framing: e.framing,
          step: 'plan',
          trials: 0,
        })
      } else if (ev.type === 'judge') {
        const e = ev as LiveJudgeEvent
        const existing = map.get(e.attack_id)
        map.set(e.attack_id, {
          ...(existing ?? { attack_id: e.attack_id, step: 'judge', trials: 0 }),
          step: existing?.step === 'result' ? 'result' : 'judge',
          composite: e.composite,
          asr: e.asr,
          vulnerability: e.vulnerability,
          reliability: e.reliability,
          failure_mode: e.failure_mode,
          response_cluster: e.response_cluster,
          breach_hint: e.breach_hint,
          ...(e.recommended_next_family !== undefined && { recommended_next_family: e.recommended_next_family }),
          ...(e.partial_leak_detected !== undefined && { partial_leak: e.partial_leak_detected }),
          ...(e.judge_reasoning !== undefined && { judge_reasoning: e.judge_reasoning }),
          ...(e.payload_text !== undefined && { payload_text: e.payload_text }),
          ...(e.response_text !== undefined && { response_text: e.response_text }),
          trials: e.trial,
        })
      } else if (ev.type === 'result') {
        const e = ev as LiveResultEvent
        const existing = map.get(e.attack_id)
        map.set(e.attack_id, {
          ...(existing ?? { attack_id: e.attack_id, step: 'result', trials: 0 }),
          step: 'result',
          status: e.status,
          composite: e.composite ?? existing?.composite,
        })
      } else if (ev.type === 'log') {
        const e = ev as LiveLogEvent
        if (e.subtype === 'result' && e.attack_id) {
          const existing = map.get(e.attack_id)
          map.set(e.attack_id, {
            ...(existing ?? { attack_id: e.attack_id, step: 'result', trials: 0 }),
            step: 'result',
            status: e.status,
            composite: e.composite ?? existing?.composite,
          })
        } else if (e.subtype === 'attack_start' && e.attack_id) {
          const existing = map.get(e.attack_id)
          const stepForward = (!existing?.step || existing.step === 'plan') ? 'generate' : existing.step
          map.set(e.attack_id, {
            ...(existing ?? { attack_id: e.attack_id, trials: 0 }),
            step: stepForward,
            ...(e.strategy_id && { strategy_id: e.strategy_id }),
            ...(e.category && { category: e.category }),
            ...(e.variant_index !== undefined && { variant_index: e.variant_index }),
          } as AttackState)
        } else if (e.subtype === 'planner_detail') {
          // Find the most recent in-progress attack and enrich it
          const inProgress = [...map.values()].filter(a => a.step !== 'result').at(-1)
          if (inProgress) {
            map.set(inProgress.attack_id, {
              ...inProgress,
              ...(e.target_field && { target_field: e.target_field }),
              ...(e.framing && { framing: e.framing }),
            })
          }
        }
      }
    }
    return map
  }, [events])

  const activeAttackId = useMemo(() => {
    for (let i = events.length - 1; i >= 0; i--) {
      const ev = events[i]
      let candidateId: string | undefined
      if (ev.type === 'plan' || ev.type === 'judge') {
        candidateId = (ev as LivePlanEvent | LiveJudgeEvent).attack_id
      } else if (ev.type === 'log' && (ev as LiveLogEvent).attack_id) {
        candidateId = (ev as LiveLogEvent).attack_id!
      }
      if (candidateId && attacks.get(candidateId)?.step !== 'result') {
        return candidateId
      }
    }
    return null
  }, [events, attacks])

  const stats = useMemo(() => {
    const all = [...attacks.values()]
    const completed = all.filter(a => a.composite !== undefined)

    // Compute derived status for stats if missing (e.g. from interrupted jobs tailing attack_log)
    for (const a of completed) {
      if (!a.status && a.composite !== undefined) {
        if (a.composite >= 7) a.status = 'keep'
        else if (a.composite >= 4) a.status = 'partial'
        else a.status = 'drop'
      }
    }

    const kept = completed.filter(a => a.status === 'keep').length
    const partial = completed.filter(a => a.status === 'partial').length
    const composites = completed.map(a => a.composite!).filter(c => c !== undefined)

    // Strategy effectiveness
    const strategyMap = new Map<string, { total: number; kept: number; partial: number; compositeSum: number; best: number }>()
    for (const a of completed) {
      const sid = a.strategy_id || 'unknown'
      const bucket = strategyMap.get(sid) ?? { total: 0, kept: 0, partial: 0, compositeSum: 0, best: 0 }
      bucket.total++
      if (a.status === 'keep') bucket.kept++
      if (a.status === 'partial') bucket.partial++
      bucket.compositeSum += a.composite!
      if (a.composite! > bucket.best) bucket.best = a.composite!
      strategyMap.set(sid, bucket)
    }
    const strategyStats = new Map<string, StrategyBucket>()
    for (const [sid, b] of strategyMap) {
      strategyStats.set(sid, {
        total: b.total,
        kept: b.kept,
        partial: b.partial,
        avgComposite: b.total ? b.compositeSum / b.total : 0,
        bestComposite: b.best,
      })
    }

    // Composite trend (completed attacks in insertion order)
    const compositeTrend = completed.map((a, i) => ({
      index: i,
      composite: a.composite!,
      status: a.status || 'drop',
    }))

    return {
      total: all.length,
      kept,
      partial,
      keepRate: completed.length ? kept / completed.length : 0,
      avgComposite: composites.length ? composites.reduce((s, v) => s + v, 0) / composites.length : 0,
      bestComposite: composites.length ? Math.max(...composites) : 0,
      strategyStats,
      compositeTrend,
    }
  }, [attacks])

  const recentLogs = useMemo(
    () => events.filter(e => e.type === 'log').slice(-6) as LiveLogEvent[],
    [events]
  )

  return { events, streamStatus, attacks, activeAttackId, stats, recentLogs, streamStartedAt: streamStartedAtRef.current }
}
