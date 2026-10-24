import { useState } from 'react'
import { api, useLoad } from './api'
import AgentsScreen from './screens/AgentsScreen'
import CityScreen from './screens/CityScreen'
import PlansScreen from './screens/PlansScreen'

const TABS = [
  { id: 'city', label: 'City', Screen: CityScreen },
  { id: 'plans', label: 'Plans', Screen: PlansScreen },
  { id: 'agents', label: 'Agents', Screen: AgentsScreen },
] as const

type TabId = (typeof TABS)[number]['id']

export default function App() {
  const [tab, setTab] = useState<TabId>('city')
  const [health] = useLoad(() => api.health())
  const { Screen } = TABS.find((t) => t.id === tab)!

  return (
    <div className="flex h-full flex-col">
      {health?.data === 'placeholder' && (
        <div role="status" className="bg-warn px-6 py-1 text-center text-xs font-semibold text-bg">
          PLACEHOLDER DATA: numbers are not from the simulator yet
        </div>
      )}
      <header className="flex items-center gap-8 border-b border-line px-6 py-3">
        <h1 className="text-lg font-semibold tracking-tight">
          Urban<span className="text-accent">Shield</span>
        </h1>
        <nav className="flex gap-1" aria-label="Screens">
          {TABS.map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              aria-current={tab === t.id ? 'page' : undefined}
              className={`rounded-md px-3 py-1.5 text-sm transition-colors ${
                tab === t.id ? 'bg-panel text-ink' : 'text-muted hover:text-ink'
              }`}
            >
              {t.label}
            </button>
          ))}
        </nav>
      </header>
      <main className="min-h-0 flex-1">
        <Screen />
      </main>
    </div>
  )
}
