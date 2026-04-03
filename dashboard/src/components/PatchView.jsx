import React, { useState } from 'react'

const STATUS_COLORS = {
  verified: '#22c55e',
  generated: '#3b82f6',
  failed: '#ef4444',
  pending: '#64748b',
}

const STATUS_LABELS = {
  verified: '검증 완료',
  generated: '생성됨',
  failed: '실패',
  'PatchStatus.VERIFIED': '검증 완료',
  'PatchStatus.GENERATED': '생성됨',
  'PatchStatus.FAILED': '실패',
}

function getStatus(patch) {
  const s = patch.status || ''
  return s.replace('PatchStatus.', '').toLowerCase()
}

export default function PatchView({ patches }) {
  const [selected, setSelected] = useState(null)

  if (patches.length === 0) {
    return (
      <div style={{
        background: '#1e293b',
        border: '1px solid #334155',
        borderRadius: 12,
        padding: 60,
        textAlign: 'center',
        color: '#64748b',
      }}>
        <div style={{ fontSize: 40, marginBottom: 16 }}>🤖</div>
        <div style={{ fontSize: 16 }}>AI 수정안이 없습니다.</div>
        <div style={{ fontSize: 13, marginTop: 8 }}>
          코드 분석을 실행하면 AI 수정안이 생성됩니다.
        </div>
      </div>
    )
  }

  return (
    <div>
      <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 16 }}>
        AI 수정 제안 ({patches.length}건)
      </h2>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        {patches.map((p, i) => {
          const status = getStatus(p)
          const color = STATUS_COLORS[status] || '#64748b'
          const isOpen = selected === i

          return (
            <div key={i} style={{
              background: '#1e293b',
              border: `1px solid ${isOpen ? color + '60' : '#334155'}`,
              borderRadius: 12,
              overflow: 'hidden',
            }}>
              {/* 헤더 */}
              <div
                onClick={() => setSelected(isOpen ? null : i)}
                style={{
                  padding: '14px 20px',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <span style={{
                    display: 'inline-block',
                    width: 8, height: 8,
                    borderRadius: '50%',
                    background: color,
                  }} />
                  <span style={{ fontFamily: 'monospace', fontSize: 13, color: '#94a3b8' }}>
                    {p.rule_id || p.vulnerability_id}
                  </span>
                  <span style={{ fontSize: 14 }}>{p.title || ''}</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  {p.file_path && (
                    <span style={{ fontFamily: 'monospace', fontSize: 12, color: '#64748b' }}>
                      {p.file_path.split('/').pop()}:{p.line_number}
                    </span>
                  )}
                  <span style={{
                    padding: '3px 10px',
                    borderRadius: 20,
                    fontSize: 11,
                    fontWeight: 600,
                    background: `${color}20`,
                    color: color,
                    border: `1px solid ${color}40`,
                  }}>
                    {STATUS_LABELS[p.status] || status}
                  </span>
                </div>
              </div>

              {/* 상세 */}
              {isOpen && (
                <div style={{ padding: '0 20px 20px', borderTop: '1px solid #334155' }}>
                  {/* 수정 근거 */}
                  {p.explanation && (
                    <div style={{
                      margin: '16px 0',
                      padding: 12,
                      background: '#0f172a',
                      borderRadius: 8,
                      fontSize: 13,
                      lineHeight: 1.7,
                      color: '#cbd5e1',
                      borderLeft: `3px solid ${color}`,
                    }}>
                      {p.explanation}
                    </div>
                  )}

                  {/* 원본 vs 수정 코드 */}
                  {p.fixed_code && (
                    <div>
                      <div style={{
                        display: 'flex',
                        gap: 4,
                        marginBottom: 8,
                      }}>
                        <span style={{
                          fontSize: 12,
                          fontWeight: 600,
                          color: '#22c55e',
                          background: '#22c55e15',
                          padding: '4px 10px',
                          borderRadius: 6,
                        }}>
                          🤖 AI 수정안
                        </span>
                        {p.syntax_valid && (
                          <span style={{ fontSize: 11, padding: '4px 8px', background: '#22c55e15', color: '#22c55e', borderRadius: 6 }}>
                            ✓ 문법 검증 통과
                          </span>
                        )}
                        {p.test_passed && (
                          <span style={{ fontSize: 11, padding: '4px 8px', background: '#3b82f615', color: '#3b82f6', borderRadius: 6 }}>
                            ✓ 테스트 통과
                          </span>
                        )}
                        {p.security_revalidation && p.security_revalidation.passed && (
                          <span style={{ fontSize: 11, padding: '4px 8px', background: '#22c55e15', color: '#22c55e', borderRadius: 6 }}>
                            ✓ 보안 재검증 통과
                          </span>
                        )}
                        {p.security_revalidation && !p.security_revalidation.passed && !p.security_revalidation.error && (
                          <span style={{ fontSize: 11, padding: '4px 8px', background: '#ef444415', color: '#ef4444', borderRadius: 6 }}>
                            ✗ 새 취약점 발견 ({p.security_revalidation.introduced_count}건)
                          </span>
                        )}
                      </div>

                      {/* 원본 코드 */}
                      {p.original_code && (
                        <>
                          <div style={{ fontSize: 12, color: '#ef4444', fontWeight: 600, marginBottom: 4, marginTop: 12 }}>
                            원본 코드 (취약):
                          </div>
                          <pre style={{
                            background: '#0f172a',
                            padding: 14,
                            borderRadius: 8,
                            fontSize: 12,
                            lineHeight: 1.6,
                            overflow: 'auto',
                            color: '#fca5a5',
                            border: '1px solid #7f1d1d',
                            maxHeight: 300,
                          }}>
                            {p.original_code}
                          </pre>
                        </>
                      )}

                      {/* 수정된 코드 */}
                      <div style={{ fontSize: 12, color: '#22c55e', fontWeight: 600, marginBottom: 4, marginTop: 12 }}>
                        수정된 코드:
                      </div>
                      <pre style={{
                        background: '#0f172a',
                        padding: 14,
                        borderRadius: 8,
                        fontSize: 12,
                        lineHeight: 1.6,
                        overflow: 'auto',
                        color: '#86efac',
                        border: '1px solid #14532d',
                        maxHeight: 400,
                      }}>
                        {p.fixed_code}
                      </pre>

                      {/* 보안 재검증 결과 */}
                      {p.security_revalidation && (
                        <div style={{
                          marginTop: 12,
                          padding: 12,
                          background: p.security_revalidation.passed ? '#052e16' : '#450a0a',
                          border: `1px solid ${p.security_revalidation.passed ? '#14532d' : '#7f1d1d'}`,
                          borderRadius: 8,
                          fontSize: 12,
                        }}>
                          <div style={{
                            fontWeight: 600,
                            marginBottom: 8,
                            color: p.security_revalidation.passed ? '#22c55e' : '#ef4444',
                          }}>
                            {p.security_revalidation.passed
                              ? '🛡️ 보안 재검증: 통과'
                              : '⚠️ 보안 재검증: 실패'}
                          </div>
                          <div style={{ color: '#94a3b8', lineHeight: 1.8 }}>
                            <div>분석 도구: {p.security_revalidation.tool_used}</div>
                            <div>
                              원본: {p.security_revalidation.original_vuln_count}건 →
                              수정 후: {p.security_revalidation.fixed_vuln_count}건
                              {p.security_revalidation.removed_count > 0 && (
                                <span style={{ color: '#22c55e' }}>
                                  {' '}({p.security_revalidation.removed_count}건 제거됨)
                                </span>
                              )}
                            </div>
                            {p.security_revalidation.introduced_count > 0 && (
                              <div style={{ color: '#ef4444', marginTop: 4 }}>
                                새로 도입된 취약점:
                                {p.security_revalidation.new_vulnerabilities?.map((v, vi) => (
                                  <div key={vi} style={{ marginLeft: 12, fontSize: 11 }}>
                                    - [{v.severity}] {v.rule_id}: {v.title}
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
            </div>
          )
        })}
      </div>
    </div>
  )
}
