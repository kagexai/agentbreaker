import { lazy, Suspense } from 'react'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { SiteLayout } from '@/components/layout/SiteLayout'
import { Toaster } from '@/components/ui/sonner'
import { Skeleton } from '@/components/ui/skeleton'

const Overview      = lazy(() => import('@/pages/Overview').then(m => ({ default: m.Overview })))
const Targets       = lazy(() => import('@/pages/Targets').then(m => ({ default: m.Targets })))
const TargetDeepDive = lazy(() => import('@/pages/TargetDeepDive').then(m => ({ default: m.TargetDeepDive })))

const Coverage      = lazy(() => import('@/pages/Coverage').then(m => ({ default: m.Coverage })))
const Regressions   = lazy(() => import('@/pages/Regressions').then(m => ({ default: m.Regressions })))
const Ops           = lazy(() => import('@/pages/Ops').then(m => ({ default: m.Ops })))
const Taxonomy      = lazy(() => import('@/pages/Taxonomy'))

function PageFallback() {
  return <div className="grid gap-4"><Skeleton className="h-12" /><Skeleton className="h-24" /><Skeleton className="h-64" /></div>
}

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: 1,
    },
  },
})

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route element={<SiteLayout />}>
            <Route index element={<Suspense fallback={<PageFallback />}><Overview /></Suspense>} />
            <Route path="targets" element={<Suspense fallback={<PageFallback />}><Targets /></Suspense>} />
            <Route path="targets/:targetId" element={<Suspense fallback={<PageFallback />}><TargetDeepDive /></Suspense>} />

            <Route path="coverage" element={<Suspense fallback={<PageFallback />}><Coverage /></Suspense>} />
            <Route path="regressions" element={<Suspense fallback={<PageFallback />}><Regressions /></Suspense>} />
            <Route path="ops" element={<Suspense fallback={<PageFallback />}><Ops /></Suspense>} />
            <Route path="taxonomy" element={<Suspense fallback={<PageFallback />}><Taxonomy /></Suspense>} />
          </Route>
        </Routes>
      </BrowserRouter>
      <Toaster />
    </QueryClientProvider>
  )
}
