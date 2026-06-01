// Warm-paper light palette — single source of truth
export const COLORS = {
  // Accents (tuned for readability on white)
  phosphor:   '#0a7d56',  // brand — mature emerald
  phosphorDim:'#0a6646',
  amber:      '#b9740b',  // warning
  amberDim:   '#8a5608',
  blood:      '#d23a2c',  // high / danger
  bloodDim:   '#a52a1f',
  bloodDeep:  '#b21f16',  // critical
  cyan:       '#2563c9',  // info / link (blue)
  cyanDim:    '#3f6fc0',
  magenta:    '#b5179e',  // rare accent

  // Surfaces
  bg:         '#f5f4f0',
  bgDeep:     '#ecebe4',
  bgElev:     '#ffffff',
  bgElev2:    '#f3f1ea',
  bgRow:      '#faf9f5',

  // Ink
  ink:        '#232019',
  inkDim:     '#6b6557',
  inkFaint:   '#9c958a',
  inkGhost:   '#cbc6ba',

  rule:       '#e8e5dd',
  ruleHot:    '#dcd8cd',

  // Legacy semantic aliases (compat with existing component imports)
  danger:        '#d23a2c',
  warning:       '#b9740b',
  success:       '#0a7d56',
  info:          '#2563c9',
  purple:        '#b5179e',
  brand:         '#0a7d56',
  brandLight:    '#0e9f6e',
  critical:      '#b21f16',
  muted:         '#6b6557',
  textPrimary:   '#232019',
  textSecondary: '#6b6557',
  textTertiary:  '#6b6557',

  // Editorial-era aliases — preserved so older components keep working.
  rust:      '#0a7d56',  // accent role → emerald
  rustSoft:  '#0a6646',
  oxblood:   '#b21f16',
  ochre:     '#b9740b',
  olive:     '#0a7d56',
  navy:      '#2563c9',
  plum:      '#b5179e',
  paper:     '#f5f4f0',
  paperDeep: '#ecebe4',
  paperHi:   '#ffffff',
  inkSoft:   '#232019',
  inkMute:   '#6b6557',
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

// Chart palette — readable hues on a light background
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
