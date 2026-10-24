// Typed client for the UrbanShield API. Every network call in the app goes through here.
import { useEffect, useRef, useState } from 'react'
import type {
  AgentEvent,
  AuditEntry,
  City,
  Plan,
  QuarantinePreview,
  ToolResult,
  VerifyResult,
} from './types'

export const CITY_ID = 'mangaluru-demo'

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/api${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...init,
  })
  if (!res.ok) throw new Error(`${init?.method ?? 'GET'} ${path} failed: ${res.status}`)
  return res.json() as Promise<T>
}

export const api = {
  city: (cityId = CITY_ID) => request<City>(`/cities/${cityId}`),
  plans: (cityId = CITY_ID) => request<Plan[]>(`/cities/${cityId}/plans`),
  startIncident: (advisoryText: string, constraintsText?: string, cityId = CITY_ID) =>
    request<{ run_id: string }>(`/cities/${cityId}/incidents`, {
      method: 'POST',
      body: JSON.stringify({ advisory_text: advisoryText, constraints_text: constraintsText ?? null }),
    }),
  approve: (runId: string, planId: string, approve = true) =>
    request<AgentEvent>(`/runs/${runId}/approvals`, {
      method: 'POST',
      body: JSON.stringify({ plan_id: planId, approve }),
    }),
  toolResult: (toolCallId: string) => request<ToolResult>(`/tool-results/${toolCallId}`),
  quarantinePreview: (advisoryText: string) =>
    request<QuarantinePreview>('/quarantine/preview', {
      method: 'POST',
      body: JSON.stringify({ advisory_text: advisoryText }),
    }),
  auditEntries: () => request<AuditEntry[]>('/audit/entries'),
  verifyAudit: () => request<VerifyResult>('/audit/verify'),
}

/** Load once on mount. Returns [data, error]. */
export function useLoad<T>(load: () => Promise<T>): [T | null, Error | null] {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<Error | null>(null)
  const loadOnce = useRef(load) // callers pass inline arrows; load only the first one
  useEffect(() => {
    let live = true
    loadOnce.current().then(
      (d) => live && setData(d),
      (e: Error) => live && setError(e),
    )
    return () => {
      live = false
    }
  }, [])
  return [data, error]
}

/** Subscribe to a run's Server-Sent Events. Events accumulate in arrival order. */
export function useRunEvents(runId: string | null): { events: AgentEvent[]; done: boolean } {
  // State is tagged with its run so a new run starts empty without a reset inside the effect.
  const [state, setState] = useState({ runId: null as string | null, events: [] as AgentEvent[], done: false })
  useEffect(() => {
    if (!runId) return
    const source = new EventSource(`/api/runs/${runId}/events`)
    source.onmessage = (msg) => {
      const event = JSON.parse(msg.data) as AgentEvent
      setState((prev) =>
        prev.runId === runId
          ? { ...prev, events: [...prev.events, event] }
          : { runId, events: [event], done: false },
      )
    }
    source.addEventListener('done', () => {
      setState((prev) => ({ ...prev, runId, done: true }))
      source.close()
    })
    source.onerror = () => source.close()
    return () => source.close()
  }, [runId])
  return state.runId === runId ? state : { events: [], done: false }
}
