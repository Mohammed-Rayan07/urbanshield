// Owner: D. Map of Mangaluru with devices, edges, ambulance corridor and a device side panel.
// See docs/manuals/D_frontend.md for the full spec.
import { api, useLoad } from '../api'

export default function CityScreen() {
  const [city, error] = useLoad(() => api.city())
  if (error) return <p className="p-6 text-danger">{error.message}</p>
  if (!city) return <p className="p-6 text-muted">Loading city…</p>
  return (
    <section className="p-6">
      <h2 className="text-xl font-semibold">{city.name}</h2>
      <p className="mt-1 text-muted">
        {city.devices.length} devices · {city.edges.length} edges (map goes here)
      </p>
    </section>
  )
}
