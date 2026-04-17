import React from 'react'
import { COLORS } from '../colors'

/**
 * Terminal-style stats block.
 *
 * Each card is a labeled data slot — bracketed key, oversized monospace
 * numeral, and a unicode bar that fills relative to the largest value.
 * No glass, no gradient, no chrome. Reads like the output of `top` or `htop`.
 */
const Block = ({ label, key_, value, accent, ratio, delay }) => {
  // ASCII bar — 24 cells wide
  const cells = 24
  const filled = Math.max(0, Math.min(cells, Math.round(ratio * cells)))
  const bar = '█'.repeat(filled) + '░'.repeat(cells - filled)

  return (
    <div
      style={{
        position: 'relative',
        padding: '14px 18px 16px',
        border: '1px solid var(--rule-hot)',
        background: 'var(--bg-elev)',
        animation: `fadeIn 0.4s steps(8) ${delay}s backwards`,
      }}
    >
      {/* Top-left bracket — defining motif */}
      <div style={{
        position: 'absolute',
        top: -1,
        left: -1,
        width: 10,
        height: 10,
        borderTop: `1px solid ${accent}`,
        borderLeft: `1px solid ${accent}`,
      }} />
      <div style={{
        position: 'absolute',
        bottom: -1,
        right: -1,
        width: 10,
        height: 10,
        borderBottom: `1px solid ${accent}`,
        borderRight: `1px solid ${accent}`,
      }} />

      <div style={{
        fontFamily: 'var(--font-mono)',
        fontSize: 10,
        fontWeight: 700,
        textTransform: 'uppercase',
        letterSpacing: '0.16em',
        color: 'var(--ink-dim)',
        display: 'flex',
        justifyContent: 'space-between',
        marginBottom: 12,
      }}>
        <span>[{key_}]</span>
        <span style={{ color: 'var(--ink-faint)' }}>{label}</span>
      </div>

      <div
        className="display-number"
        style={{
          fontSize: 'clamp(36px, 4.5vw, 56px)',
          color: accent,
          marginBottom: 12,
          textShadow: accent === COLORS.phosphor ? `0 0 24px rgba(158, 255, 125, 0.3)` : 'none',
        }}
      >
        {String(value).padStart(2, '0')}
      </div>

      <div style={{
        fontFamily: 'var(--font-mono)',
        fontSize: 11,
        color: accent,
        letterSpacing: 0,
        lineHeight: 1,
        whiteSpace: 'nowrap',
        overflow: 'hidden',
        textShadow: accent === COLORS.phosphor ? `0 0 6px rgba(158, 255, 125, 0.4)` : 'none',
      }}>
        {bar}
      </div>
    </div>
  )
}

export default function StatsCards({ stats }) {
  if (!stats) return null

  // Compute ratios against the highest count for proportional bars
  const total = stats.total_issues || 0
  const high = stats.high || 0
  const medium = stats.medium || 0
  const low = stats.low || 0
  const drafted = stats.patches_generated || 0
  const witnessed = stats.patches_verified || 0
  const max = Math.max(total, 1)

  const cards = [
    { key_: 'TOT', label: 'total',     value: total,     accent: COLORS.ink,      ratio: total / max },
    { key_: 'HIG', label: 'high',      value: high,      accent: COLORS.blood,    ratio: high / max },
    { key_: 'MED', label: 'med',       value: medium,    accent: COLORS.amber,    ratio: medium / max },
    { key_: 'LOW', label: 'low',       value: low,       accent: COLORS.cyan,     ratio: low / max },
    { key_: 'GEN', label: 'drafted',   value: drafted,   accent: COLORS.cyan,     ratio: drafted / Math.max(total, 1) },
    { key_: 'VER', label: 'witnessed', value: witnessed, accent: COLORS.phosphor, ratio: witnessed / Math.max(total, 1) },
  ]

  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
        gap: 16,
      }}
    >
      {cards.map((c, i) => (
        <Block key={i} {...c} delay={i * 0.04} />
      ))}
    </div>
  )
}
