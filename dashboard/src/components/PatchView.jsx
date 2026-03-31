import React, { useState } from 'react'

const STATUS_COLORS = {
  verified: '#22c55e',
  generated: '#3b82f6',
  failed: '#ef4444',
  pending: '#64748b',
}

const STATUS_LABELS = {
  verified: 'Verified',
  generated: 'Generated',
  failed: 'Failed',
  'PatchStatus.VERIFIED': 'Verified',
  'PatchStatus.GENERATED': 'Generated',
  'PatchStatus.FAILED': 'Failed',
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
        <div style={{ fontSize: 16 }}>No AI patches yet.</div>
        <div style={{ fontSize: 13, marginTop: 8 }}>
          Run the analysis pipeline to generate patches.
        </div>
      </div>
    )
  }

  return (
    <div>
      <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 16 }}>
        AI Fix Suggestions ({patches.length})
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
              {/* Header */}
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
                    textTransform: 'uppercase',
                  }}>
                    {STATUS_LABELS[p.status] || status}
                  </span>
                </div>
              </div>

              {/* Detail */}
              {isOpen && (
                <div style={{ padding: '0 20px 20px', borderTop: '1px solid #334155' }}>
                  {/* Explanation */}
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

                  {/* Original vs Fixed Code */}
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
                          🤖 AI Suggested Fix
                        </span>
                        {p.syntax_valid && (
                          <span style={{ fontSize: 11, padding: '4px 8px', background: '#22c55e15', color: '#22c55e', borderRadius: 6 }}>
                            ✓ Syntax Valid
                          </span>
                        )}
                        {p.test_passed && (
                          <span style={{ fontSize: 11, padding: '4px 8px', background: '#3b82f615', color: '#3b82f6', borderRadius: 6 }}>
                            ✓ Tests Passed
                          </span>
                        )}
                      </div>

                      {/* Original code */}
                      {p.original_code && (
                        <>
                          <div style={{ fontSize: 12, color: '#ef4444', fontWeight: 600, marginBottom: 4, marginTop: 12 }}>
                            Original (vulnerable):
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

                      {/* Fixed code */}
                      <div style={{ fontSize: 12, color: '#22c55e', fontWeight: 600, marginBottom: 4, marginTop: 12 }}>
                        Fixed:
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
