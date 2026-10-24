import type { CSSProperties } from 'react'

/** Join class names, skipping falsy parts. */
export function cx(...parts: (string | false | null | undefined)[]) {
  return parts.filter(Boolean).join(' ')
}

/** Stagger an element's entrance: pass its index in reading order. */
export const rise = (i: number): CSSProperties => ({ animationDelay: `${Math.min(i, 12) * 45}ms` })
