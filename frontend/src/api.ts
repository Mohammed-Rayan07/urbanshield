// Typed client for the UrbanShield API. Every network call in the app goes through here.
import { useCallback, useEffect, useRef, useState } from 'react'
import type {
  AdvisoryPreset,
  AgentEvent,
  AuditEntry,
  City,
  CityRisk,
  EnforcerStatus,
  Frontier,
  Plan,
  QuarantinePreview,
  SignalCommand,
  ToolResult,
  TwoCities,
  Verdict,
  VerifyResult,
} from './types'

export const CITY_ID = 'mangaluru-demo'

/** An API error that keeps the HTTP status and the server's `detail` message. */
export class ApiError extends Error {
  readonly status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/api${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...init,
  })
  if (!res.ok) {
    let detail = `${init?.method ?? 'GET'} ${path} failed: ${res.status}`
    try {
      const body = (await res.json()) as { detail?: unknown }
      if (typeof body.detail === 'string') detail = body.detail
    } catch {
      // not JSON: keep the status line
    }
    throw new ApiError(res.status, detail)
  }
  return res.json() as Promise<T>
}

export interface Health {
  status: string
  version: string
  llm_mode: 'live' | 'replay' | 'mock'
  data: 'placeholder' | 'live'
  engine_ready: boolean
  /** 'ephemeral' = no AUDIT_SIGNING_KEY: signatures stop verifying after a restart (show a warning). */
  audit_key: 'fixed' | 'ephemeral'
  /** 'ok', or 'unavailable: <reason>' (incidents are refused until it is fixed). */
  audit: string
}

export const api = {
  health: () => request<Health>('/health'),
  city: (cityId = CITY_ID) => request<City>(`/cities/${cityId}`),
  plans: (cityId = CITY_ID) => request<Plan[]>(`/cities/${cityId}/plans`),
  /** Held-out simulation: per-device loss and the loss distribution per strategy. */
  risk: (cityId = CITY_ID) => request<CityRisk>(`/cities/${cityId}/risk`),
  /** One held-out worst-5% scenario replayed hop by hop: no controls, CVSS-first, UrbanShield. */
  replay: (cityId = CITY_ID) => request<TwoCities>(`/cities/${cityId}/replay`),
  /** Precomputed held-out worst-case loss per planner across budgets (the budget slider). */
  frontier: (cityId = CITY_ID) => request<Frontier>(`/cities/${cityId}/frontier`),
  /** Policy in force at the Enforcer, corridor paths and recent decisions. */
  enforcer: (cityId = CITY_ID) => request<EnforcerStatus>(`/cities/${cityId}/enforcer`),
  /** Judge one signal command at the Enforcer (audited). */
  command: (command: SignalCommand, cityId = CITY_ID) =>
    request<Verdict>(`/cities/${cityId}/enforcer/commands`, { method: 'POST', body: JSON.stringify(command) }),
  startIncident: (advisoryText: string, constraintsText?: string, cityId = CITY_ID) =>
    request<{ run_id: string }>(`/cities/${cityId}/incidents`, {
      method: 'POST',
      body: JSON.stringify({ advisory_text: advisoryText, constraints_text: constraintsText || null }),
    }),
  // Demo RBAC: the approver role travels in a header (not real authentication).
  approve: (runId: string, planId: string, approve = true) =>
    request<AgentEvent>(`/runs/${runId}/approvals`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Role': 'approver' },
      body: JSON.stringify({ plan_id: planId, approve }),
    }),
  /** Provenance for the precomputed /plans comparison and /risk simulation. */
  toolResult: (toolCallId: string) => request<ToolResult>(`/tool-results/${toolCallId}`),
  /** Provenance for a number in a run's timeline (tool ids restart at tc-001 in every run). */
  runToolResult: (runId: string, toolCallId: string) =>
    request<ToolResult>(`/runs/${runId}/tool-results/${toolCallId}`),
  advisories: () => request<AdvisoryPreset[]>('/advisories'),
  auditKey: () => request<{ verify_key_hex: string }>('/audit/key'),
  quarantinePreview: (advisoryText: string) =>
    request<QuarantinePreview>('/quarantine/preview', {
      method: 'POST',
      body: JSON.stringify({ advisory_text: advisoryText }),
    }),
  auditEntries: () => request<AuditEntry[]>('/audit/entries'),
  verifyAudit: () => request<VerifyResult>('/audit/verify'),
  /** Judge Mode only: exists when the server runs with ALLOW_DEMO_TAMPER=1 (404 otherwise). */
  tamper: (seq: number) =>
    request<{ tampered_seq: number }>('/audit/tamper', { method: 'POST', body: JSON.stringify({ seq }) }),
}

export interface Loaded<T> {
  data: T | null
  error: Error | null
  reload: () => void
}

/** Load on mount; `reload()` fetches again (keeping the old data on screen meanwhile). */
export function useLoad<T>(load: () => Promise<T>): Loaded<T> {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<Error | null>(null)
  const [tick, setTick] = useState(0)
  const loadRef = useRef(load) // callers pass inline arrows; keep the first one
  useEffect(() => {
    let live = true
    loadRef.current().then(
      (d) => {
        if (!live) return
        setData(d)
        setError(null)
      },
      (e: Error) => live && setError(e),
    )
    return () => {
      live = false
    }
  }, [tick])
  const reload = useCallback(() => setTick((t) => t + 1), [])
  return { data, error, reload }
}

/** Subscribe to a run's Server-Sent Events. Events accumulate in arrival order.
 *  The browser reconnects after a dropped connection and the server replays the run from its first
 *  event, so events already shown (same id) are skipped rather than duplicated. */
export function useRunEvents(runId: string | null): { events: AgentEvent[]; done: boolean } {
  // State is tagged with its run so a new run starts empty without a reset inside the effect.
  const [state, setState] = useState({ runId: null as string | null, events: [] as AgentEvent[], done: false })
  useEffect(() => {
    if (!runId) return
    const source = new EventSource(`/api/runs/${runId}/events`)
    source.onmessage = (msg) => {
      const event = JSON.parse(msg.data) as AgentEvent
      setState((prev) => {
        if (prev.runId !== runId) return { runId, events: [event], done: false }
        if (prev.events.some((e) => e.id === event.id)) return prev
        return { ...prev, events: [...prev.events, event] }
      })
    }
    source.addEventListener('done', () => {
      setState((prev) => (prev.runId === runId ? { ...prev, done: true } : { runId, events: [], done: true }))
      source.close()
    })
    return () => source.close()
  }, [runId])
  return state.runId === runId ? state : { events: [], done: false }
}
