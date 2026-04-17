// Terminal palette — single source of truth
export const COLORS = {
  // Terminal accents
  phosphor:   '#9eff7d',  // primary — phosphor green
  phosphorDim:'#5fa050',
  amber:      '#ffb000',  // warning
  amberDim:   '#a07000',
  blood:      '#ff3d24',  // critical
  bloodDim:   '#a02817',
  bloodDeep:  '#c8160c',
  cyan:       '#5dd6ff',  // info / link
  cyanDim:    '#3a7c96',
  magenta:    '#ff5fb8',  // rare accent

  // Surfaces
  bg:         '#0a0a0a',
  bgDeep:     '#050505',
  bgElev:     '#131311',
  bgElev2:    '#1a1a17',
  bgRow:      '#0f0f0d',

  // Ink
  ink:        '#e9e6d8',
  inkDim:     '#8a8678',
  inkFaint:   '#4a4843',
  inkGhost:   '#2a2a26',

  rule:       '#232320',
  ruleHot:    '#3a3a34',

  // Legacy semantic aliases (compat with existing component imports)
  danger:        '#ff3d24',
  warning:       '#ffb000',
  success:       '#9eff7d',
  info:          '#5dd6ff',
  purple:        '#ff5fb8',
  brand:         '#9eff7d',
  brandLight:    '#9eff7d',
  critical:      '#c8160c',
  muted:         '#8a8678',
  textPrimary:   '#e9e6d8',
  textSecondary: '#8a8678',
  textTertiary:  '#8a8678',

  // Editorial-era aliases — preserved so components written before the
  // terminal redesign keep working without per-file rewrites.
  rust:      '#9eff7d',  // accent role → phosphor
  rustSoft:  '#5fa050',
  oxblood:   '#c8160c',
  ochre:     '#ffb000',
  olive:     '#9eff7d',
  navy:      '#5dd6ff',
  plum:      '#ff5fb8',
  paper:     '#0a0a0a',
  paperDeep: '#050505',
  paperHi:   '#131311',
  inkSoft:   '#e9e6d8',
  inkMute:   '#8a8678',
}

// Semantic severity mapping
export const SEVERITY = {
  CRITICAL: COLORS.bloodDeep,
  HIGH:     COLORS.blood,
  MEDIUM:   COLORS.amber,
  LOW:      COLORS.cyan,
  UNKNOWN:  COLORS.inkDim,
}

// Status mapping
export const STATUS = {
  verified:  COLORS.phosphor,
  generated: COLORS.cyan,
  failed:    COLORS.blood,
  pending:   COLORS.inkDim,
}

// Terminal chart palette — phosphor + warning hues only
export const CHART_PALETTE = [
  COLORS.blood,
  COLORS.amber,
  COLORS.cyan,
  COLORS.phosphor,
  COLORS.magenta,
  COLORS.bloodDeep,
  COLORS.amberDim,
  COLORS.cyanDim,
]

// Helper: hex + alpha suffix
export function alpha(hex, opacity) {
  const a = Math.round(opacity * 255).toString(16).padStart(2, '0')
  return hex + a
}

// Helper: rgba string from hex
export function rgba(hex, opacity) {
  const r = parseInt(hex.slice(1, 3), 16)
  const g = parseInt(hex.slice(3, 5), 16)
  const b = parseInt(hex.slice(5, 7), 16)
  return `rgba(${r}, ${g}, ${b}, ${opacity})`
}
