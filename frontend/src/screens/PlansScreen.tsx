// Owner: D. Same budget, three plans side by side, loss distribution, plan diff, full table.
// See docs/manuals/D_frontend.md for the full spec.
import { api, useLoad } from '../api'

export default function PlansScreen() {
  const [plans, error] = useLoad(() => api.plans())
  if (error) return <p className="p-6 text-danger">{error.message}</p>
  if (!plans) return <p className="p-6 text-muted">Loading plans…</p>
  return (
    <section className="p-6">
      <h2 className="text-xl font-semibold">Plans</h2>
      <ul className="mt-3 space-y-1 font-mono text-sm">
        {plans.map((p) => (
          <li key={p.id}>
            {p.objective.padEnd(16)} CVaR {p.metrics?.cvar.toFixed(1) ?? '–'}
          </li>
        ))}
      </ul>
    </section>
  )
}
