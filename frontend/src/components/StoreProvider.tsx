// Owns the app-wide state described in lib/store.ts and provides it to every screen.
import { useCallback, useMemo, useState, type ReactNode } from 'react'
import { api, useLoad, useRunEvents } from '../api'
import { byId } from '../lib/derive'
import { foldRun } from '../lib/run'
import { StoreContext, type ProvenanceTarget, type Store } from '../lib/store'

export default function StoreProvider({ children }: { children: ReactNode }) {
  const health = useLoad(() => api.health())
  const city = useLoad(() => api.city())
  const plans = useLoad(() => api.plans())
  const risk = useLoad(() => api.risk())
  const presets = useLoad(() => api.advisories())
  const [selectedDevice, selectDevice] = useState<string | null>(null)
  const [selectedCve, selectCve] = useState<string | null>(null)
  const [provenance, setProvenance] = useState<ProvenanceTarget | null>(null)

  const [runId, setRunId] = useState<string | null>(null)
  const [advisoryTitle, setAdvisoryTitle] = useState<string | null>(null)
  const [constraints, setConstraints] = useState<string | null>(null)
  const [starting, setStarting] = useState(false)
  const [runError, setRunError] = useState<string | null>(null)
  const { events, done } = useRunEvents(runId)
  const view = useMemo(() => foldRun(events, done), [events, done])

  const start = useCallback(async (preset: { title: string; text: string }, text: string) => {
    setStarting(true)
    setRunError(null)
    try {
      const { run_id } = await api.startIncident(preset.text, text.trim() || undefined)
      setAdvisoryTitle(preset.title)
      setConstraints(text.trim() || null)
      setRunId(run_id)
    } catch (e) {
      setRunError((e as Error).message)
    } finally {
      setStarting(false)
    }
  }, [])
  const attach = useCallback((id: string) => {
    setRunError(null)
    setAdvisoryTitle(null)
    setConstraints(null)
    setRunId(id)
  }, [])
  const reset = useCallback(() => {
    setRunId(null)
    setRunError(null)
  }, [])

  const closeProvenance = useCallback(() => setProvenance(null), [])
  const devices = useMemo(() => byId(city.data?.devices ?? []), [city.data])
  const value: Store = {
    health,
    city,
    plans,
    risk,
    presets,
    devices,
    selectedDevice,
    selectDevice,
    selectedCve,
    selectCve,
    run: {
      runId,
      advisoryTitle,
      constraints,
      events,
      done,
      view,
      starting,
      error: runError,
      start,
      attach,
      reset,
    },
    provenance,
    openProvenance: setProvenance,
    closeProvenance,
  }
  return <StoreContext.Provider value={value}>{children}</StoreContext.Provider>
}
