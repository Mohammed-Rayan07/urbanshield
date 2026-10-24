// Owner: D. Live agent timeline (SSE), approvals, Auditor counter, audit log, Judge Mode.
// See docs/manuals/D_frontend.md for the full spec.
import { useState } from 'react'
import { api, useRunEvents } from '../api'

export default function AgentsScreen() {
  const [runId, setRunId] = useState<string | null>(null)
  const { events, done } = useRunEvents(runId)

  const start = async () => {
    const { run_id } = await api.startIncident('CVE-2025-31337 affects Lumenos SL-200 below 4.2.0')
    setRunId(run_id)
  }

  return (
    <section className="p-6">
      <button
        onClick={start}
        className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-bg hover:opacity-90"
      >
        Inject advisory
      </button>
      <ol className="mt-4 space-y-1 font-mono text-sm">
        {events.map((e) => (
          <li key={e.id}>
            <span className="text-accent">{e.agent.padEnd(9)}</span> {e.summary}
          </li>
        ))}
      </ol>
      {done && <p className="mt-3 text-ok">Run complete.</p>}
    </section>
  )
}
