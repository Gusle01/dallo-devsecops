import React from 'react'

// 의존성 없는 경량 마크다운 렌더러.
// LLM 설명문에 쓰이는 최소 문법만 처리한다:
//   - 줄바꿈(\n) 보존
//   - **굵게**, `인라인 코드`
//   - "N. " 순서 목록 / "- ", "* " 글머리 목록 (들여쓰기 반영)
//   - "---" 구분선

// 인라인: **굵게**, `코드`
function renderInline(text, keyPrefix) {
  const nodes = []
  const re = /(\*\*([^*]+)\*\*|`([^`]+)`)/
  let rest = String(text)
  let k = 0
  let m
  while ((m = re.exec(rest)) !== null) {
    if (m.index > 0) nodes.push(rest.slice(0, m.index))
    if (m[2] !== undefined) {
      nodes.push(<strong key={`${keyPrefix}-b${k++}`} style={{ color: 'var(--ink)', fontWeight: 700 }}>{m[2]}</strong>)
    } else {
      nodes.push(
        <code key={`${keyPrefix}-c${k++}`} style={{
          fontFamily: 'var(--font-mono)', fontSize: '0.9em',
          background: 'var(--bg-deep)', padding: '1px 5px', borderRadius: 3, color: 'var(--cyan)',
          wordBreak: 'break-all',
        }}>{m[3]}</code>
      )
    }
    rest = rest.slice(m.index + m[0].length)
  }
  if (rest) nodes.push(rest)
  return nodes
}

export default function Markdown({ text, style }) {
  const lines = String(text || '').split('\n')

  return (
    <div style={style}>
      {lines.map((raw, i) => {
        const line = raw.replace(/\s+$/, '')
        const trimmed = line.trim()

        if (trimmed === '') return <div key={i} style={{ height: 7 }} />
        if (/^-{3,}$/.test(trimmed)) {
          return <hr key={i} style={{ border: 'none', borderTop: '1px dashed var(--rule)', margin: '11px 0' }} />
        }

        const indent = line.length - line.trimStart().length
        let m

        if ((m = trimmed.match(/^(\d+)\.\s+(.*)$/))) {
          return (
            <div key={i} style={{ display: 'flex', gap: 8, margin: '4px 0', marginLeft: 2 + indent * 4 }}>
              <span style={{ color: 'var(--cyan)', fontWeight: 700, flexShrink: 0 }}>{m[1]}.</span>
              <span>{renderInline(m[2], i)}</span>
            </div>
          )
        }
        if ((m = trimmed.match(/^[-*]\s+(.*)$/))) {
          return (
            <div key={i} style={{ display: 'flex', gap: 8, margin: '2px 0', marginLeft: 12 + indent * 4 }}>
              <span style={{ color: 'var(--ink-faint)', flexShrink: 0 }}>–</span>
              <span>{renderInline(m[1], i)}</span>
            </div>
          )
        }
        return <div key={i} style={{ margin: '4px 0', marginLeft: indent * 4 }}>{renderInline(trimmed, i)}</div>
      })}
    </div>
  )
}
