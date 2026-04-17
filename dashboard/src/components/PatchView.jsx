import React, { useState } from 'react'
import { STATUS, COLORS, alpha, rgba } from '../colors'

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

  if (patches.length === 0) {
    return (
      <div>
        <div className="page-header">
          <h1 className="page-title">
            <em>$</em>&nbsp;patches <span style={{ color: 'var(--ink-faint)' }}>--list</span>
          </h1>
          <p className="page-subtitle">
            llm-drafted patches · awaiting review · 0 records
          </p>
        </div>

        <div className="empty-state">
          <div className="empty-state__icon">∅</div>
          <div className="empty-state__title">no patches on file</div>
          <div className="empty-state__description">
            run a scan with --llm to populate this register
          </div>
        </div>
      </div>
    )
  }

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">
          The <em style={{ fontStyle: 'italic', color: 'var(--rust)' }}>Remedies</em>,
          <br/>Drafted by Hand.
        </h1>
        <p className="page-subtitle">
          {patches.length} record(s) returned · llm drafts with revalidation status
        </p>
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
              className="fade-in"
              style={{
                borderTop: '1px solid var(--rule)',
                borderBottom: i === patches.length - 1 ? '1px solid var(--rule)' : 'none',
                animationDelay: `${i * 0.04}s`,
                animationFillMode: 'backwards',
              }}
            >
              {/* Header */}
              <div
                onClick={() => setSelected(isOpen ? null : i)}
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
                    <div style={{
                      margin: '18px 0',
                      padding: '14px 18px',
                      background: 'var(--paper-deep)',
                      borderRadius: 0,
                      fontSize: 14,
                      lineHeight: 1.7,
                      color: 'var(--ink-soft)',
                      borderLeft: `2px solid ${cfg.color}`,
                      fontStyle: 'italic',
                      fontFamily: 'var(--font-body)',
                      maxWidth: '64ch',
                    }}>
                      {p.explanation}
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

                      {p.original_code && (
                        <>
                          <div className="section-label" style={{ color: 'var(--blood)', marginTop: 18 }}>
                            ── original.code <span style={{ color: 'var(--ink-faint)' }}>// vulnerable</span>
                          </div>
                          <pre className="code-block code-block--danger">
                            {p.original_code}
                          </pre>
                        </>
                      )}

                      <div className="section-label" style={{ color: 'var(--phosphor)', marginTop: 18 }}>
                        ── patched.code <span style={{ color: 'var(--ink-faint)' }}>// llm draft</span>
                      </div>
                      <pre className="code-block code-block--success">
                        {p.fixed_code}
                      </pre>

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
