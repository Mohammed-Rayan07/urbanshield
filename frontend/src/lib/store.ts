// App-wide state: the loaded twin, shared selection, the active run, and the provenance drawer.
// One provider (components/StoreProvider.tsx), so the Overview, Risk and Response screens never hold contradictory copies.
import { createContext, useContext } from 'react'
import type { Health, Loaded } from '../api'
import type { AdvisoryPreset, AgentEvent, City, CityRisk, Device, Plan } from '../types'
import type { RunView } from './run'

export interface ProvenanceTarget {
  toolCallId: string
  runId?: string
  /** What the number on screen was, e.g. "Worst-case loss 4.54". */
  label?: string
}

export interface RunState {
  runId: string | null
  advisoryTitle: string | null
  constraints: string | null
  events: AgentEvent[]
  done: boolean
  view: RunView
  starting: boolean
  error: string | null
  start: (preset: { title: string; text: string }, constraints: string) => Promise<void>
  /** Follow an existing run (a deep link): SSE replays it from the first event. */
  attach: (runId: string) => void
  reset: () => void
}

export interface Store {
  health: Loaded<Health>
  city: Loaded<City>
  plans: Loaded<Plan[]>
  risk: Loaded<CityRisk>
  presets: Loaded<AdvisoryPreset[]>
  devices: Map<string, Device>
  selectedDevice: string | null
  selectDevice: (id: string | null) => void
  selectedCve: string | null
  selectCve: (cve: string | null) => void
  run: RunState
  provenance: ProvenanceTarget | null
  openProvenance: (t: ProvenanceTarget) => void
  closeProvenance: () => void
}

export const StoreContext = createContext<Store | null>(null)

export function useStore(): Store {
  const s = useContext(StoreContext)
  if (!s) throw new Error('useStore outside StoreProvider')
  return s
}
