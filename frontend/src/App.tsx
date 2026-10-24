import { lazy, Suspense, useEffect, type ComponentType } from 'react'
import ProvenanceDrawer from './components/ProvenanceDrawer'
import Shell from './components/Shell'
import StoreProvider from './components/StoreProvider'
import { Skeleton } from './components/ui'
import { useRoute, type RouteId } from './lib/route'
import CityScreen from './screens/CityScreen'

// The Overview ships in the main bundle; the other workspaces load on first visit.
const SCREENS: Record<RouteId, { title: string; Screen: ComponentType }> = {
  overview: { title: 'Overview', Screen: CityScreen },
  risk: { title: 'Risk Intelligence', Screen: lazy(() => import('./screens/PlansScreen')) },
  response: { title: 'Response & Mitigation', Screen: lazy(() => import('./screens/AgentsScreen')) },
  devices: { title: 'Devices', Screen: lazy(() => import('./screens/DevicesScreen')) },
  judge: { title: 'Judge Mode', Screen: lazy(() => import('./screens/JudgeScreen')) },
  audit: { title: 'Audit Log', Screen: lazy(() => import('./screens/AuditScreen')) },
}

function ScreenFallback() {
  return (
    <div className="space-y-5" aria-busy="true">
      <Skeleton className="h-24 w-1/2" />
      <div className="grid grid-cols-5 gap-3">
        {Array.from({ length: 5 }, (_, i) => (
          <Skeleton key={i} className="h-24" />
        ))}
      </div>
      <Skeleton className="h-[420px]" />
    </div>
  )
}

export default function App() {
  const route = useRoute()
  const { title, Screen } = SCREENS[route.id]
  useEffect(() => {
    document.title = `${title} · UrbanShield`
  }, [title])
  return (
    <StoreProvider>
      <Shell route={route.id}>
        <Suspense fallback={<ScreenFallback />}>
          <Screen />
        </Suspense>
      </Shell>
      <ProvenanceDrawer />
    </StoreProvider>
  )
}
