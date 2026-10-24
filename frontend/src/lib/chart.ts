// Chart helpers shared by the SVG charts and the legends around them.
import { useEffect, useRef, useState } from 'react'
import type { LossHistogram, Objective } from '../types'
import { C, SERIES } from './colors'
import { OBJECTIVE_LABEL } from './format'

/** Track an element's content size (charts redraw to fit their card). */
export function useSize<T extends HTMLElement>() {
  const ref = useRef<T>(null)
  const [size, setSize] = useState({ w: 0, h: 0 })
  useEffect(() => {
    const el = ref.current
    if (!el) return
    const ro = new ResizeObserver(([e]) => setSize({ w: e.contentRect.width, h: e.contentRect.height }))
    ro.observe(el)
    return () => ro.disconnect()
  }, [])
  return [ref, size] as const
}

export const seriesColor = (label: LossHistogram['label']) => SERIES[label as keyof typeof SERIES] ?? C.muted

export const seriesLabel = (label: LossHistogram['label']) =>
  label === 'none' ? 'No controls' : OBJECTIVE_LABEL[label as Objective]
