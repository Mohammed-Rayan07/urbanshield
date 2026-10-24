// Token values for places CSS variables cannot reach (SVG presentation attributes written by
// Leaflet and Recharts). Keep in sync with the @theme block in index.css.
export const C = {
  forest950: '#09271f',
  forest900: '#10382d',
  forest800: '#174a3a',
  forest700: '#236747',
  forest200: '#c9dccd',
  forest100: '#e5efe7',
  forest50: '#f1f5f0',
  surface: '#ffffff',
  surfaceMuted: '#f8f9f6',
  line: '#e1e6df',
  lineStrong: '#cdd5cc',
  ink: '#17251f',
  ink2: '#53625b',
  muted: '#66736b',
  idle: '#c3ccc5',
  danger: '#d93632',
  high: '#f07832',
  warn: '#e9ad36',
  info: '#2784d8',
  ok: '#2f9158',
  low: '#4daa70',
} as const

/** Series colours for the strategies the dashboard compares. UrbanShield is always forest. */
export const SERIES = {
  none: '#8f9a93',
  cvss: C.high,
  cvss_kev_epss: '#c2410c',
  bfs_centrality: C.info,
  loss_per_inr: '#7c8a3c',
  mean: '#6d8a7d',
  patch_only: '#a3a3a3',
  greedy_tail: C.forest700,
  cvar: C.forest800,
} as const
