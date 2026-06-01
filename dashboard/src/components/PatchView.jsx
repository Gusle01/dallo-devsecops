import React, { useState, useRef, useCallback } from 'react'
import { STATUS, COLORS, alpha, rgba } from '../colors'
import DiffView from './DiffView'
import Markdown from './Markdown'
import { buildFixedFile } from '../utils/diff'

const STATUS_CONFIG = {
  verified:  { color: STATUS.verified,  label: '검증 완료', icon: '✓' },
  generated: { color: STATUS.generated, label: '생성됨',    icon: '◆' },
  failed:    { color: STATUS.failed,    label: '실패',      icon: '✕' },
  pending:   { color: STATUS.pending,   label: '대기중',    icon: '◷' },
}

function getStatus(patch) {
  const s = patch.status || ''
  return s.replace('PatchStatus.', '').toLowerCase()
}

export default function PatchView({ patches }) {
  const [selected, setSelected] = useState(null)
  const cardRefs = useRef({})

  // 항목 클릭 시 펼치고 해당 카드(diff 영역)로 스크롤 이동
  const selectPatch = useCallback((index) => {
    setSelected(prev => {
      const next = prev === index ? null : index
      if (next !== null) {
        // 펼쳐진 뒤 스크롤 (다음 페인트 이후)
        requestAnimationFrame(() => {
          const el = cardRefs.current[index]
          if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' })
        })
      }
      return next
    })
  }, [])

  if (patches.length === 0) {
    return (
      <div>
        <div className="page-header">
          <h1 className="page-title">
            <em>$</em>&nbsp;defense <span style={{ color: 'var(--ink-faint)' }}>--list</span>
          </h1>
          <p className="page-subtitle">
            blue team remediation actions · awaiting review · 0 records
          </p>
        </div>

        <div className="empty-state">
          <div className="empty-state__icon">∅</div>
          <div className="empty-state__title">no patches on file</div>
          <div className="empty-state__description">
            run a redscan with LLM enabled to populate blue team actions
          </div>
        </div>
      </div>
    )
  }

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">
          Blue <em style={{ fontStyle: 'italic', color: 'var(--cyan)' }}>Team</em>
          <br/>Defense Actions.
        </h1>
        <p className="page-subtitle">
          {patches.length} record(s) returned · llm remediation with syntax and security revalidation
        </p>
      </div>

      {/* 점프 인덱스 — 항목 클릭 시 해당 diff 영역으로 이동 */}
      <div style={{
        display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 18,
        padding: '10px 14px', border: '1px solid var(--rule-hot)', background: 'var(--bg-deep)',
      }}>
        <span style={{
          fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--ink-dim)',
          textTransform: 'uppercase', letterSpacing: '0.14em', marginRight: 8, alignSelf: 'center',
        }}>
          $ jump →
        </span>
        {patches.map((p, i) => {
          const status = getStatus(p)
          const cfg = STATUS_CONFIG[status] || STATUS_CONFIG.pending
          return (
            <button
              key={i}
              onClick={() => selectPatch(i)}
              title={p.title || p.vulnerability_id}
              style={{
                border: `1px solid ${selected === i ? cfg.color : 'var(--rule-hot)'}`,
                background: selected === i ? cfg.color : 'transparent',
                color: selected === i ? 'var(--bg)' : 'var(--ink-dim)',
                padding: '2px 8px', cursor: 'pointer',
                fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700,
              }}
            >
              {String(i + 1).padStart(2, '0')} {(p.rule_id || p.vulnerability_id || '').slice(0, 16)}
            </button>
          )
        })}
      </div>

      <div style={{ display: 'flex', flexDirection: 'column' }}>
        {patches.map((p, i) => {
          const status = getStatus(p)
          const cfg = STATUS_CONFIG[status] || STATUS_CONFIG.pending
          const englishStatus = { verified: 'verified', generated: 'drafted', failed: 'failed', pending: 'pending' }[status] || cfg.label
          const isOpen = selected === i

          return (
            <article
              key={i}
              ref={el => { cardRefs.current[i] = el }}
              className="fade-in"
              style={{
                borderTop: '1px solid var(--rule)',
                borderBottom: i === patches.length - 1 ? '1px solid var(--rule)' : 'none',
                animationDelay: `${i * 0.04}s`,
                animationFillMode: 'backwards',
                scrollMarginTop: 16,
              }}
            >
              {/* Header */}
              <div
                onClick={() => selectPatch(i)}
                style={{
                  padding: '20px 0',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'baseline',
                  justifyContent: 'space-between',
                  gap: 18,
                  flexWrap: 'wrap',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 14, flex: 1, minWidth: 0 }}>
                  <span style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: 14,
                    fontWeight: 800,
                    color: cfg.color,
                    minWidth: 36,
                  }}>
                    [{String(i + 1).padStart(2, '0')}]
                  </span>
                  <span style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: 10,
                    color: 'var(--cyan)',
                    flexShrink: 0,
                  }}>
                    {p.rule_id || p.vulnerability_id}
                  </span>
                  <span style={{
                    fontSize: 12,
                    color: 'var(--ink)',
                    fontWeight: 500,
                    fontFamily: 'var(--font-mono)',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                    flex: 1,
                  }}>
                    {p.title || ''}
                  </span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 14, flexShrink: 0 }}>
                  {p.file_path && (
                    <span style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: 10,
                      color: 'var(--ink-faint)',
                    }}>
                      {p.file_path.split('/').pop()}:{p.line_number}
                    </span>
                  )}
                  <span className={`badge-status badge-status--${status}`} style={{
                    flexShrink: 0,
                    color: cfg.color,
                  }}>
                    {englishStatus}
                  </span>
                </div>
              </div>

              {/* Detail */}
              {isOpen && (
                <div className="expand-in" style={{
                  padding: '4px 0 28px',
                  borderTop: '1px dotted var(--rule)',
                }}>
                  {p.explanation && (
                    <Markdown
                      text={p.explanation}
                      style={{
                        margin: '18px 0',
                        padding: '14px 18px',
                        background: 'var(--paper-deep)',
                        borderRadius: 0,
                        fontSize: 13.5,
                        lineHeight: 1.7,
                        color: 'var(--ink-soft)',
                        borderLeft: `2px solid ${cfg.color}`,
                        fontFamily: 'var(--font-body)',
                        maxWidth: '82ch',
                      }}
                    />
                  )}

                  {(p.defense_strategy || p.defense_outcome || p.residual_risk) && (
                    <div style={{
                      margin: '12px 0 18px',
                      padding: '12px 16px',
                      background: 'var(--paper-deep)',
                      border: '1px solid var(--rule)',
                      borderLeft: '2px solid var(--cyan)',
                      fontFamily: 'var(--font-mono)',
                      fontSize: 11,
                      color: 'var(--ink-dim)',
                      lineHeight: 1.7,
                      textTransform: 'uppercase',
                      letterSpacing: '0.08em',
                    }}>
                      <div>phase: <span style={{ color: 'var(--cyan)' }}>{p.blue_team_phase || 'remediation'}</span></div>
                      <div>outcome: <span style={{ color: 'var(--phosphor)' }}>{p.defense_outcome || 'drafted_defense'}</span></div>
                      <div>residual_risk: <span style={{ color: 'var(--amber)' }}>{p.residual_risk || 'unknown'}</span></div>
                      {p.defense_strategy && (
                        <div style={{ textTransform: 'none', letterSpacing: 0, marginTop: 8, color: 'var(--ink-soft)' }}>
                          {p.defense_strategy}
                        </div>
                      )}
                    </div>
                  )}

                  {p.fixed_code && (
                    <div>
                      <div style={{
                        display: 'flex',
                        gap: 6,
                        marginBottom: 10,
                        flexWrap: 'wrap',
                      }}>
                        <span className="badge-tag badge-tag--brand">
                          AI 수정안
                        </span>
                        {p.syntax_valid && (
                          <span className="badge-tag badge-tag--success">
                            ✓ 문법 검증 통과
                          </span>
                        )}
                        {p.test_passed && (
                          <span className="badge-tag badge-tag--info">
                            ✓ 테스트 통과
                          </span>
                        )}
                        {p.security_revalidation && p.security_revalidation.passed && (
                          <span className="badge-tag badge-tag--success">
                            ✓ 보안 재검증 통과
                          </span>
                        )}
                        {p.security_revalidation && !p.security_revalidation.passed && !p.security_revalidation.error && (
                          <span className="badge-tag badge-tag--danger">
                            ✕ 새 취약점 {p.security_revalidation.introduced_count}건
                          </span>
                        )}
                      </div>

                      <div className="section-label" style={{ color: 'var(--phosphor)', marginTop: 18, marginBottom: 8 }}>
                        ── before / after <span style={{ color: 'var(--ink-faint)' }}>// red → blue</span>
                      </div>
                      {(() => {
                        // 전체 원본이 있으면 redscan처럼 전체 파일 좌우 diff로 합성,
                        // 없으면(구버전 데이터) 스니펫 단위로 폴백한다.
                        const full = p.source_full || ''
                        const original = full || p.original_code || ''
                        const fixed = full ? buildFixedFile(full, p.fixed_code, p.line_number) : p.fixed_code
                        return <DiffView original={original} fixed={fixed} />
                      })()}

                      {p.security_revalidation && (
                        <div style={{
                          marginTop: 16,
                          padding: '16px 20px',
                          background: 'var(--paper-deep)',
                          border: '1px solid var(--rule)',
                          borderLeft: `2px solid ${p.security_revalidation.passed ? 'var(--olive)' : 'var(--rust)'}`,
                          borderRadius: 0,
                          fontSize: 13,
                          fontFamily: 'var(--font-body)',
                        }}>
                          <div style={{
                            fontWeight: 800,
                            marginBottom: 10,
                            color: p.security_revalidation.passed ? 'var(--phosphor)' : 'var(--blood)',
                            fontSize: 12,
                            fontFamily: 'var(--font-mono)',
                            textTransform: 'uppercase',
                            letterSpacing: '0.14em',
                          }}>
                            {p.security_revalidation.passed
                              ? '[OK] revalidation.passed'
                              : '[FAIL] revalidation.regressed'}
                          </div>
                          <div style={{ color: 'var(--ink-dim)', lineHeight: 1.7, fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                            <div>
                              tool: <span style={{ color: 'var(--cyan)' }}>{p.security_revalidation.tool_used}</span>{' '}
                              · before: <span style={{ color: 'var(--ink)' }}>{p.security_revalidation.original_vuln_count}</span>{' '}
                              → after: <span style={{ color: 'var(--ink)' }}>{p.security_revalidation.fixed_vuln_count}</span>
                              {p.security_revalidation.removed_count > 0 && (
                                <span style={{ color: 'var(--phosphor)' }}>
                                  {' '}(-{p.security_revalidation.removed_count})
                                </span>
                              )}
                            </div>
                            {p.security_revalidation.introduced_count > 0 && (
                              <div style={{ color: 'var(--blood)', marginTop: 8 }}>
                                {'>'} regression introduced:
                                {p.security_revalidation.new_vulnerabilities?.map((v, vi) => (
                                  <div key={vi} style={{ marginLeft: 14, fontSize: 11, marginTop: 2 }}>
                                    {'  '}[{v.severity}] {v.rule_id} :: {v.title}
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </article>
          )
        })}
      </div>
    </div>
  )
}
