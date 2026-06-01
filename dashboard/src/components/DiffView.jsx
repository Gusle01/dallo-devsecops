import React, { useState, useMemo } from 'react'
import { diffLines, splitFromLines } from '../utils/diff'

// GitHub PR diff 스타일 코드 비교 컴포넌트.
// 원본(original) vs 수정(fixed) 코드를 좌우 분할/통합 보기로 표시하고
// 변경된 라인을 색으로 강조합니다.
//
// props:
//   original  : 원본(취약) 코드 문자열
//   fixed     : 수정된 코드 문자열
//   defaultMode: 'split' | 'unified' (기본 'split')

const GUTTER = {
  fontFamily: 'var(--font-mono)',
  fontSize: 11,
  color: 'var(--ink-faint)',
  textAlign: 'right',
  padding: '0 8px',
  userSelect: 'none',
  minWidth: 38,
  whiteSpace: 'nowrap',
}

const CELL = {
  fontFamily: 'var(--font-mono)',
  fontSize: 11.5,
  lineHeight: 1.7,
  whiteSpace: 'pre-wrap',
  // 긴 토큰(연결 문자열/시크릿 등)도 칸 안에서 강제로 줄바꿈 — Safari 등에서
  // word-break:break-word가 불안정해 가로 오버플로우가 나는 것을 방지한다.
  overflowWrap: 'anywhere',
  wordBreak: 'break-word',
  padding: '0 10px',
  width: '100%',
}

const ROW_BG = {
  add: 'rgba(10, 125, 86, 0.12)',
  del: 'rgba(210, 58, 44, 0.10)',
  equal: 'transparent',
}
const SIGN_COLOR = {
  add: 'var(--phosphor)',
  del: 'var(--blood)',
  equal: 'var(--ink-faint)',
}
const SIGN = { add: '+', del: '-', equal: ' ' }

function ModeToggle({ mode, setMode, stats }) {
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8, flexWrap: 'wrap',
    }}>
      <span style={{
        fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--ink-dim)',
        textTransform: 'uppercase', letterSpacing: '0.14em',
      }}>
        ── diff
      </span>
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10 }}>
        <span style={{ color: 'var(--phosphor)' }}>+{stats.added}</span>{' '}
        <span style={{ color: 'var(--blood)' }}>-{stats.removed}</span>
      </span>
      <div style={{ marginLeft: 'auto', display: 'flex', gap: 0 }}>
        {[
          { id: 'split', label: 'split' },
          { id: 'unified', label: 'unified' },
        ].map(opt => (
          <button
            key={opt.id}
            onClick={() => setMode(opt.id)}
            style={{
              border: '1px solid',
              borderColor: mode === opt.id ? 'var(--cyan)' : 'var(--rule-hot)',
              background: mode === opt.id ? 'var(--cyan)' : 'transparent',
              color: mode === opt.id ? 'var(--bg)' : 'var(--ink-dim)',
              padding: '3px 12px',
              cursor: 'pointer',
              fontFamily: 'var(--font-mono)',
              fontSize: 10,
              fontWeight: 700,
              textTransform: 'uppercase',
              letterSpacing: '0.1em',
            }}
          >
            {opt.label}
          </button>
        ))}
      </div>
    </div>
  )
}

function SplitView({ rows }) {
  const sideCell = (side) => {
    if (!side) {
      return (
        <td colSpan={2} style={{ background: 'var(--bg-deep)', borderRight: '1px solid var(--rule)' }} />
      )
    }
    return (
      <>
        <td style={{ ...GUTTER, background: ROW_BG[side.type], borderRight: '1px solid var(--rule)' }}>
          {side.number ?? ''}
        </td>
        <td style={{ ...CELL, background: ROW_BG[side.type], borderRight: '1px solid var(--rule)', color: 'var(--ink)' }}>
          <span style={{ color: SIGN_COLOR[side.type], userSelect: 'none' }}>{SIGN[side.type]} </span>
          {side.text}
        </td>
      </>
    )
  }
  return (
    <div style={{ overflowX: 'auto', border: '1px solid var(--rule-hot)', background: 'var(--bg-deep)' }}>
      <table style={{ borderCollapse: 'collapse', width: '100%', tableLayout: 'fixed' }}>
        <colgroup>
          <col style={{ width: 38 }} />
          <col style={{ width: '50%' }} />
          <col style={{ width: 38 }} />
          <col style={{ width: '50%' }} />
        </colgroup>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i}>
              {sideCell(r.left)}
              {sideCell(r.right)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function UnifiedView({ rows }) {
  return (
    <div style={{ overflowX: 'auto', border: '1px solid var(--rule-hot)', background: 'var(--bg-deep)' }}>
      <table style={{ borderCollapse: 'collapse', width: '100%' }}>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i} style={{ background: ROW_BG[r.type] }}>
              <td style={{ ...GUTTER, borderRight: '1px solid var(--rule)' }}>{r.oldNumber ?? ''}</td>
              <td style={{ ...GUTTER, borderRight: '1px solid var(--rule)' }}>{r.newNumber ?? ''}</td>
              <td style={{ ...CELL, color: 'var(--ink)' }}>
                <span style={{ color: SIGN_COLOR[r.type], userSelect: 'none' }}>{SIGN[r.type]} </span>
                {r.text}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default function DiffView({ original, fixed, defaultMode = 'split' }) {
  const [mode, setMode] = useState(defaultMode)

  // diff는 한 번만 계산하고(LCS 1회) split/통계는 그 결과에서 파생한다.
  // original/fixed 문자열이 그대로면 부모 리렌더에도 재계산하지 않는다.
  const lineRows = useMemo(() => diffLines(original || '', fixed || ''), [original, fixed])
  const splitRows = useMemo(() => splitFromLines(lineRows), [lineRows])
  const stats = useMemo(() => {
    let added = 0, removed = 0
    for (const r of lineRows) {
      if (r.type === 'add') added++
      else if (r.type === 'del') removed++
    }
    return { added, removed }
  }, [lineRows])

  // 원본이 없으면 diff 불가 → 수정 코드만 표시
  if (!original || !original.trim()) {
    return (
      <div>
        <div style={{
          fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--ink-dim)',
          marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.14em',
        }}>
          ── patched.code <span style={{ color: 'var(--ink-faint)' }}>// no original to diff</span>
        </div>
        <pre className="code-block code-block--success">{fixed}</pre>
      </div>
    )
  }

  return (
    <div>
      <ModeToggle mode={mode} setMode={setMode} stats={stats} />
      {mode === 'split'
        ? <SplitView rows={splitRows} />
        : <UnifiedView rows={lineRows} />}
    </div>
  )
}
