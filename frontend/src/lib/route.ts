// Hash routing: #/overview, #/risk?plan=…, deep-linkable without a router dependency.
import { useEffect, useState } from 'react'

export type RouteId = 'overview' | 'story' | 'risk' | 'response' | 'devices' | 'judge' | 'audit'

export const ROUTES: RouteId[] = ['overview', 'story', 'risk', 'response', 'devices', 'judge', 'audit']

export interface Route {
  id: RouteId
  params: URLSearchParams
}

function parse(): Route {
  const [path, query = ''] = window.location.hash.replace(/^#\/?/, '').split('?')
  const id = (ROUTES as string[]).includes(path) ? (path as RouteId) : 'overview'
  return { id, params: new URLSearchParams(query) }
}

export function href(id: RouteId, params?: Record<string, string>) {
  const q = params ? new URLSearchParams(params).toString() : ''
  return `#/${id}${q ? `?${q}` : ''}`
}

export function navigate(id: RouteId, params?: Record<string, string>) {
  window.location.hash = href(id, params)
}

export function useRoute(): Route {
  const [route, setRoute] = useState(parse)
  useEffect(() => {
    const on = () => setRoute(parse())
    window.addEventListener('hashchange', on)
    return () => window.removeEventListener('hashchange', on)
  }, [])
  return route
}
