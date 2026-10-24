// The city twin on a real basemap. One component for the large Overview map and the compact
// context maps on Risk Intelligence and Response, so every view draws devices the same way.
import L from 'leaflet'
import { Crosshair, Layers, Minus, Plus } from 'lucide-react'
import { useEffect, useMemo, type ReactNode } from 'react'
import { MapContainer, Marker, Polygon, Polyline, TileLayer, Tooltip, useMap } from 'react-leaflet'
import {
  DEVICE_THRESHOLDS,
  ZONE_THRESHOLDS,
  isCorridor,
  levelOf,
  riskById,
  riskColor,
  sum,
  zones as deriveZones,
  type LatLng,
} from '../lib/derive'
import { CATEGORY_LABEL, share } from '../lib/format'
import type { Category, City, CityRisk, Device } from '../types'
import { C } from '../lib/colors'
import { cx } from '../lib/cx'

export type MapMode = 'risk' | 'protected' | 'exposure' | 'network'
export type Basemap = 'map' | 'satellite'

const ESRI = 'https://server.arcgisonline.com/ArcGIS/rest/services'
const TILES: Record<Basemap, { base: string; labels: string; attribution: string }> = {
  map: {
    base: `${ESRI}/Canvas/World_Light_Gray_Base/MapServer/tile/{z}/{y}/{x}`,
    labels: `${ESRI}/Canvas/World_Light_Gray_Reference/MapServer/tile/{z}/{y}/{x}`,
    attribution: 'Tiles © Esri — Esri, HERE, Garmin, © OpenStreetMap contributors',
  },
  satellite: {
    base: `${ESRI}/World_Imagery/MapServer/tile/{z}/{y}/{x}`,
    labels: `${ESRI}/Reference/World_Boundaries_and_Places/MapServer/tile/{z}/{y}/{x}`,
    attribution: 'Imagery © Esri, Maxar, Earthstar Geographics',
  },
}

/** Shape encodes category, colour encodes risk/state: colour never has to do both jobs. */
function shapeSvg(category: Category, r: number, fill: string, stroke: string) {
  const s = r * 2
  const common = `fill="${fill}" stroke="${stroke}" stroke-width="1.6"`
  const body =
    category === 'streetlight'
      ? `<circle cx="${r}" cy="${r}" r="${r - 1}" ${common}/>`
      : category === 'meter'
        ? `<rect x="1" y="1" width="${s - 2}" height="${s - 2}" rx="2" ${common}/>`
        : category === 'signal'
          ? `<path d="M${r} 0.5 L${s - 0.5} ${r} L${r} ${s - 0.5} L0.5 ${r} Z" ${common}/>`
          : `<path d="M${r} 0.8 L${s - 0.6} ${s - 1} L0.6 ${s - 1} Z" ${common}/>`
  return `<svg width="${s}" height="${s}" viewBox="0 0 ${s} ${s}">${body}</svg>`
}

export function ShapeGlyph(props: { category: Category; color?: string; size?: number }) {
  const r = (props.size ?? 12) / 2
  return (
    <span
      aria-hidden
      className="inline-block align-middle"
      dangerouslySetInnerHTML={{ __html: shapeSvg(props.category, r, props.color ?? '#fff', C.ink2) }}
    />
  )
}

export interface DeviceStyle {
  fill: string
  stroke?: string
  ping?: boolean
  dim?: boolean
}

export interface CityMapProps {
  city: City
  risk: CityRisk | null
  mode: MapMode
  basemap?: Basemap
  className?: string
  /** Overrides per device (Response screen: matched / applied / attacked). */
  styleFor?: (d: Device) => DeviceStyle | null
  attackPaths?: [string, string][]
  selected?: string | null
  onSelect?: (id: string | null) => void
  ripple?: string[]
  focus?: string[] | null
  showZones?: boolean
  showEdges?: boolean
  showCorridor?: boolean
  compact?: boolean
  children?: ReactNode
}

function Controls(props: { bounds: L.LatLngBounds; compact?: boolean }) {
  const map = useMap()
  const btn =
    'grid size-8 cursor-pointer place-items-center bg-surface text-ink-2 transition-colors hover:bg-forest-50 hover:text-ink'
  return (
    <div className="absolute right-3 top-3 z-[500] flex flex-col overflow-hidden rounded-lg border border-line shadow-sm">
      <button type="button" aria-label="Zoom in" className={btn} onClick={() => map.zoomIn()}>
        <Plus className="size-4" />
      </button>
      <button type="button" aria-label="Zoom out" className={cx(btn, 'border-t border-line')} onClick={() => map.zoomOut()}>
        <Minus className="size-4" />
      </button>
      {!props.compact && (
        <button
          type="button"
          aria-label="Reset view"
          className={cx(btn, 'border-t border-line')}
          onClick={() => map.flyToBounds(props.bounds, { padding: [40, 40], duration: 0.6 })}
        >
          <Crosshair className="size-4" />
        </button>
      )}
    </div>
  )
}

function Focus(props: { points: LatLng[] | null; bounds: L.LatLngBounds }) {
  const map = useMap()
  const key = props.points?.map((p) => p.join(',')).join('|') ?? ''
  useEffect(() => {
    if (!props.points?.length) return
    const b = L.latLngBounds(props.points)
    if (props.points.length === 1) map.flyTo(props.points[0], Math.max(map.getZoom(), 14), { duration: 0.6 })
    else map.flyToBounds(b.pad(0.25), { duration: 0.7, maxZoom: 14 })
    // key captures the points; bounds are stable per city
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, map])
  return null
}

/** Keep Leaflet's size in step with the layout, and fit the city once the container has a size. */
function Resize(props: { bounds: L.LatLngBounds }) {
  const map = useMap()
  const { bounds } = props
  useEffect(() => {
    const el = map.getContainer()
    let fitted = false
    const ro = new ResizeObserver(() => {
      map.invalidateSize()
      if (!fitted && el.clientHeight > 0) {
        fitted = true
        map.fitBounds(bounds, { padding: [36, 36] })
      }
    })
    ro.observe(el)
    return () => ro.disconnect()
  }, [map, bounds])
  return null
}

export default function CityMap(props: CityMapProps) {
  const { city, risk, mode } = props
  const basemap = props.basemap ?? 'map'
  const base = useMemo(() => riskById(risk?.baseline), [risk])
  const prot = useMemo(() => riskById(risk?.protected), [risk])
  const cvar = useMemo(() => sum((risk?.baseline ?? []).map((r) => r.tail_loss)) || 1, [risk])
  const zones = useMemo(() => deriveZones(city, risk), [city, risk])
  const devices = useMemo(() => new Map(city.devices.map((d) => [d.id, d])), [city])
  const bounds = useMemo(() => L.latLngBounds(city.devices.map((d) => [d.lat, d.lon] as LatLng)), [city])
  const ripple = useMemo(() => new Set(props.ripple ?? []), [props.ripple])
  const focus = useMemo(
    () => (props.focus ? props.focus.map((id) => devices.get(id)).filter(Boolean).map((d) => [d!.lat, d!.lon] as LatLng) : null),
    [props.focus, devices],
  )

  const deviceShare = (d: Device) =>
    ((mode === 'protected' ? prot.get(d.id) : base.get(d.id))?.tail_loss ?? 0) / cvar

  const styleOf = (d: Device): DeviceStyle => {
    const custom = props.styleFor?.(d)
    if (custom) return custom
    if (mode === 'exposure')
      return d.exposed
        ? { fill: C.danger }
        : d.tags.includes('gateway')
          ? { fill: C.high }
          : { fill: C.idle }
    if (mode === 'network') return { fill: C.forest700 }
    if (!risk) return { fill: C.idle }
    return { fill: riskColor(levelOf(deviceShare(d), DEVICE_THRESHOLDS)) }
  }

  const corridor = useMemo(
    () =>
      city.devices
        .filter(isCorridor)
        .sort((a, b) => a.lat - b.lat)
        .map((d): LatLng => [d.lat, d.lon]),
    [city],
  )

  const showZones = props.showZones ?? true
  const showEdges = props.showEdges ?? mode === 'network'
  const showCorridor = props.showCorridor ?? true

  return (
    <div className={cx('relative isolate overflow-hidden', props.className)}>
      <MapContainer
        bounds={bounds}
        boundsOptions={{ padding: [36, 36] }}
        zoomControl={false}
        zoomSnap={0.25}
        scrollWheelZoom={!props.compact}
        attributionControl
        className="h-full w-full"
      >
        <TileLayer key={basemap} url={TILES[basemap].base} attribution={TILES[basemap].attribution} maxZoom={18} />
        <TileLayer key={`${basemap}-labels`} url={TILES[basemap].labels} maxZoom={18} opacity={0.85} />
        <Resize bounds={bounds} />
        <Focus points={focus} bounds={bounds} />
        <Controls bounds={bounds} compact={props.compact} />

        {showZones &&
          zones.map((z) => {
            const zoneShare = (mode === 'protected' ? z.tailLossProtected : z.tailLoss) / cvar
            const color =
              risk && (mode === 'risk' || mode === 'protected')
                ? riskColor(levelOf(zoneShare, ZONE_THRESHOLDS))
                : C.forest700
            return (
              <Polygon
                key={`${z.name}-${mode}`}
                positions={z.hull}
                pathOptions={{
                  color,
                  weight: 1.2,
                  opacity: 0.7,
                  fillColor: color,
                  fillOpacity: basemap === 'satellite' ? 0.28 : mode === 'network' || mode === 'exposure' ? 0.06 : 0.17,
                  dashArray: mode === 'network' ? '4 4' : undefined,
                }}
                interactive={false}
              />
            )
          })}

        {showEdges &&
          city.edges.map((e, i) => {
            const a = devices.get(e.src)
            const b = devices.get(e.dst)
            if (!a || !b) return null
            return (
              <Polyline
                key={i}
                positions={[
                  [a.lat, a.lon],
                  [b.lat, b.lon],
                ]}
                pathOptions={
                  e.kind === 'depends'
                    ? { color: C.forest800, weight: 1.6, opacity: 0.75 }
                    : { color: '#7d8b83', weight: 0.9, opacity: 0.45, dashArray: '3 4' }
                }
                interactive={false}
              />
            )
          })}

        {showCorridor && corridor.length > 1 && (
          <Polyline
            positions={corridor}
            pathOptions={{ color: C.info, weight: 4, opacity: 0.75, lineCap: 'round' }}
          >
            <Tooltip sticky className="us-tip">
              Ambulance corridor · {corridor.length} signals
            </Tooltip>
          </Polyline>
        )}

        {(props.attackPaths ?? []).map(([s, t], i) => {
          const a = devices.get(s)
          const b = devices.get(t)
          if (!a || !b) return null
          return (
            <Polyline
              key={`atk-${i}`}
              positions={[
                [a.lat, a.lon],
                [b.lat, b.lon],
              ]}
              pathOptions={{ color: C.danger, weight: 2.2, opacity: 0.9, className: 'us-attack' }}
              interactive={false}
            />
          )
        })}

        {showZones &&
          !props.compact &&
          zones.map((z) => {
            const zoneShare = (mode === 'protected' ? z.tailLossProtected : z.tailLoss) / cvar
            const html = `<div style="position:absolute;left:0;top:0;width:max-content;transform:translate(calc(-100% - 6px),-50%);white-space:nowrap;pointer-events:none">
              <div style="background:var(--color-forest-950);color:#fff;border-radius:6px;padding:3px 8px 4px;font:600 12px var(--font-sans);box-shadow:0 4px 14px rgb(9 39 31/.18);text-align:center">
                ${z.name}${risk && (mode === 'risk' || mode === 'protected') ? `<div style="font:700 13px var(--font-sans);font-variant-numeric:tabular-nums;color:#e5efe7">${share(zoneShare)}</div>` : ''}
              </div></div>`
            return (
              <Marker
                key={`lbl-${z.name}-${mode}`}
                position={[z.center[0], Math.min(...z.hull.map((p) => p[1]))]}
                interactive={false}
                icon={L.divIcon({ className: 'us-zone-label', html, iconSize: [0, 0] })}
              />
            )
          })}

        {city.devices.map((d) => {
          const st = styleOf(d)
          const r = 5 + Math.round(d.criticality * 4) + (props.compact ? 0 : 1)
          const sel = props.selected === d.id
          const ring = ripple.has(d.id) || st.ping
          const html = `<div class="us-marker ${sel ? 'is-selected' : ''}" style="width:${r * 2}px;height:${r * 2}px;color:${st.fill};opacity:${st.dim ? 0.35 : 1}">
            ${ring ? `<span class="us-ping ${ripple.has(d.id) ? 'us-ripple' : ''}"></span>` : ''}
            ${shapeSvg(d.category, r, st.fill, sel ? C.ink : (st.stroke ?? '#fff'))}
          </div>`
          return (
            <Marker
              key={`${d.id}-${mode}`}
              position={[d.lat, d.lon]}
              icon={L.divIcon({ className: '', html, iconSize: [r * 2, r * 2], iconAnchor: [r, r] })}
              keyboard={!!props.onSelect}
              title={d.name}
              eventHandlers={props.onSelect ? { click: () => props.onSelect!(sel ? null : d.id) } : undefined}
              zIndexOffset={sel ? 1000 : ring ? 500 : 0}
            >
              <Tooltip direction="top" offset={[0, -r]} className="us-tip" opacity={1}>
                <div className="font-semibold">{d.name}</div>
                <div style={{ opacity: 0.75 }}>
                  {CATEGORY_LABEL[d.category]} · {d.firmware}
                  {risk ? ` · ${share(deviceShare(d), 1)} of worst case` : ''}
                </div>
              </Tooltip>
            </Marker>
          )
        })}
      </MapContainer>
      {props.children}
    </div>
  )
}

export function BasemapToggle(props: { value: Basemap; onChange: (b: Basemap) => void }) {
  return (
    <div className="flex overflow-hidden rounded-lg border border-line bg-surface text-[12.5px] font-medium shadow-sm">
      {(['map', 'satellite'] as Basemap[]).map((b) => (
        <button
          key={b}
          type="button"
          aria-pressed={props.value === b}
          onClick={() => props.onChange(b)}
          className={cx(
            'flex cursor-pointer items-center gap-1.5 px-3 py-1.5 capitalize transition-colors',
            props.value === b ? 'bg-forest-800 text-white' : 'text-ink-2 hover:bg-forest-50',
          )}
        >
          {b === 'satellite' && <Layers className="size-3.5" aria-hidden />}
          {b}
        </button>
      ))}
    </div>
  )
}

export function RiskLegend(props: { title: string; thresholds: readonly number[]; compact?: boolean }) {
  const [a, b, c, d] = props.thresholds
  const rows: [string, string][] = [
    [C.danger, `Very high  ≥ ${share(a)}`],
    [C.high, `High  ${share(b)}–${share(a)}`],
    [C.warn, `Moderate  ${share(c, 1)}–${share(b)}`],
    [C.low, `Low  ${share(d, 1)}–${share(c, 1)}`],
    [C.ok, `Very low  < ${share(d, 1)}`],
  ]
  return (
    <div className="rounded-lg border border-line bg-surface/95 px-3 py-2.5 text-[11.5px] shadow-sm backdrop-blur-sm">
      <p className="mb-1.5 font-semibold text-ink">{props.title}</p>
      <ul className="space-y-1">
        {rows.map(([color, label]) => (
          <li key={label} className="flex items-center gap-2 text-ink-2">
            <span className="size-2.5 rounded-full" style={{ background: color }} />
            <span className="num whitespace-pre">{label}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

export function ShapeLegend() {
  return (
    <div className="flex flex-wrap gap-x-3 gap-y-1 text-[11.5px] text-ink-2">
      {(['signal', 'meter', 'streetlight', 'ev_charger'] as Category[]).map((c) => (
        <span key={c} className="flex items-center gap-1.5">
          <ShapeGlyph category={c} color={C.surfaceMuted} size={11} />
          {CATEGORY_LABEL[c]}
        </span>
      ))}
    </div>
  )
}
