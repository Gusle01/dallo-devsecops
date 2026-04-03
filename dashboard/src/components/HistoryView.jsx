import React, { useState, useEffect } from 'react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Legend, LineChart, Line } from 'recharts'

const API = window.location.origin

export default function HistoryView() {
  const [sessions, setSessions] = useState([])
  const [selected, setSelected] = useState(null)
  const [detail, setDetail] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch(`${API}/api/sessions`)
      .then(r => r.json())
      .then(d => {
        setSessions(d.sessions || [])
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }, [])

  const loadDetail = async (sessionId) => {
    if (selected === sessionId) {
      setSelected(null)
      setDetail(null)
      return
    }
    setSelected(sessionId)
    try {
      const r = await fetch(`${API}/api/sessions/${sessionId}`)
      const d = await r.json()
      setDetail(d)
    } catch {
      setDetail(null)
    }
  }

  // 트렌드 차트 데이터 (시간순 정렬)
  const trendData = [...sessions].reverse().map(s => ({
    name: s.session_id.replace('session_', '').slice(0, 8),
    total: s.total_issues,
    high: s.high_count,
    medium: s.medium_count,
    low: s.low_count,
    patches: s.patches_generated,
    verified: s.patches_verified,
  }))

  if (loading) {
    return <div style={{ padding: 60, textAlign: 'center', color: '#64748b' }}>불러오는 중...</div>
  }

  return (
    <div>
      <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 20 }}>
        분석 이력 ({sessions.length}개 세션)
      </h2>

      {/* 트렌드 차트 */}
      {sessions.length > 1 && (
        <div style={{
          display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 24,
        }}>
          {/* 취약점 추이 */}
          <div style={{
            background: '#1e293b', border: '1px solid #334155', borderRadius: 12, padding: 20,
          }}>
            <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 16, color: '#94a3b8' }}>
              취약점 추이
            </h3>
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={trendData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} allowDecimals={false} />
                <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 8 }} />
                <Bar dataKey="high" fill="#ef4444" name="HIGH" stackId="a" />
                <Bar dataKey="medium" fill="#eab308" name="MEDIUM" stackId="a" />
                <Bar dataKey="low" fill="#3b82f6" name="LOW" stackId="a" />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* 패치 성공률 추이 */}
          <div style={{
            background: '#1e293b', border: '1px solid #334155', borderRadius: 12, padding: 20,
          }}>
            <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 16, color: '#94a3b8' }}>
              AI 수정안 성공률
            </h3>
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={trendData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} allowDecimals={false} />
                <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 8 }} />
                <Line type="monotone" dataKey="patches" stroke="#3b82f6" name="생성됨" strokeWidth={2} dot={{ r: 4 }} />
                <Line type="monotone" dataKey="verified" stroke="#22c55e" name="검증 통과" strokeWidth={2} dot={{ r: 4 }} />
                <Legend wrapperStyle={{ fontSize: 12 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* 세션 목록 테이블 */}
      <div style={{
        background: '#1e293b', border: '1px solid #334155', borderRadius: 12, overflow: 'hidden',
      }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid #334155' }}>
              {['세션', '저장소', '취약점', '높음', '중간', '낮음', '수정안', '검증', '소요시간', '날짜'].map(h => (
                <th key={h} style={{
                  padding: '12px 14px', textAlign: 'left', fontSize: 11,
                  fontWeight: 600, color: '#64748b', textTransform: 'uppercase',
                }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sessions.map((s, i) => (
              <React.Fragment key={i}>
                <tr
                  onClick={() => loadDetail(s.session_id)}
                  style={{
                    borderBottom: '1px solid #0f172a',
                    cursor: 'pointer',
                    background: selected === s.session_id ? '#0f172a' : 'transparent',
                  }}
                  onMouseOver={e => e.currentTarget.style.background = '#0f172a'}
                  onMouseOut={e => {
                    if (selected !== s.session_id) e.currentTarget.style.background = 'transparent'
                  }}
                >
                  <td style={{ padding: '10px 14px', fontFamily: 'monospace', fontSize: 12, color: '#60a5fa' }}>
                    {s.session_id.replace('session_', '').slice(0, 15)}
                  </td>
                  <td style={{ padding: '10px 14px', fontSize: 13 }}>{s.repo}</td>
                  <td style={{ padding: '10px 14px', fontSize: 14, fontWeight: 600 }}>{s.total_issues}</td>
                  <td style={{ padding: '10px 14px', color: '#ef4444', fontWeight: 600 }}>{s.high_count}</td>
                  <td style={{ padding: '10px 14px', color: '#eab308', fontWeight: 600 }}>{s.medium_count}</td>
                  <td style={{ padding: '10px 14px', color: '#3b82f6', fontWeight: 600 }}>{s.low_count}</td>
                  <td style={{ padding: '10px 14px', color: '#22c55e' }}>{s.patches_generated}</td>
                  <td style={{ padding: '10px 14px', color: '#a855f7' }}>{s.patches_verified}</td>
                  <td style={{ padding: '10px 14px', fontSize: 12, color: '#94a3b8' }}>
                    {s.duration_seconds ? `${s.duration_seconds.toFixed(1)}s` : '-'}
                  </td>
                  <td style={{ padding: '10px 14px', fontSize: 12, color: '#64748b' }}>
                    {s.started_at ? s.started_at.slice(0, 16).replace('T', ' ') : '-'}
                  </td>
                </tr>
                {/* 세션 상세 (클릭 시 펼침) */}
                {selected === s.session_id && detail && (
                  <tr>
                    <td colSpan={10} style={{ padding: 0, background: '#0f172a' }}>
                      <div style={{ padding: 16 }}>
                        {/* 취약점 목록 */}
                        {detail.vulnerabilities && detail.vulnerabilities.length > 0 && (
                          <div style={{ marginBottom: 12 }}>
                            <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8, color: '#94a3b8' }}>
                              취약점 ({detail.vulnerabilities.length}건)
                            </div>
                            {detail.vulnerabilities.map((v, vi) => (
                              <div key={vi} style={{
                                padding: '8px 12px', background: '#1e293b', borderRadius: 6,
                                marginBottom: 4, fontSize: 12, display: 'flex', gap: 10, alignItems: 'center',
                              }}>
                                <span style={{ color: {HIGH:'#ef4444',MEDIUM:'#eab308',LOW:'#3b82f6'}[v.severity] || '#64748b' }}>
                                  {v.severity}
                                </span>
                                <span style={{ fontFamily: 'monospace', color: '#94a3b8' }}>{v.rule_id}</span>
                                <span>{v.title}</span>
                                <span style={{ marginLeft: 'auto', color: '#64748b', fontFamily: 'monospace' }}>
                                  {(v.file_path || '').split('/').pop()}:{v.line_number}
                                </span>
                              </div>
                            ))}
                          </div>
                        )}
                        {/* 패치 목록 */}
                        {detail.patches && detail.patches.filter(p => p.fixed_code).length > 0 && (
                          <div>
                            <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8, color: '#94a3b8' }}>
                              AI 수정안 ({detail.patches.filter(p => p.fixed_code).length}건)
                            </div>
                            {detail.patches.filter(p => p.fixed_code).map((p, pi) => (
                              <div key={pi} style={{
                                padding: '8px 12px', background: '#1e293b', borderRadius: 6,
                                marginBottom: 4, fontSize: 12,
                              }}>
                                <span style={{
                                  padding: '2px 8px', borderRadius: 4, fontSize: 11,
                                  background: p.status?.includes('verified') || p.status?.includes('VERIFIED') ? '#22c55e20' : '#3b82f620',
                                  color: p.status?.includes('verified') || p.status?.includes('VERIFIED') ? '#22c55e' : '#3b82f6',
                                }}>
                                  {p.status?.includes('verified') || p.status?.includes('VERIFIED') ? '검증 완료' : '생성됨'}
                                </span>
                                <span style={{ marginLeft: 8, color: '#94a3b8' }}>{p.vulnerability_id}</span>
                              </div>
                            ))}
                          </div>
                        )}
                        {!detail.vulnerabilities?.length && (
                          <div style={{ color: '#64748b', fontSize: 13 }}>상세 정보 없음</div>
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>

        {sessions.length === 0 && (
          <div style={{ padding: 40, textAlign: 'center', color: '#64748b' }}>
            분석 이력이 없습니다. 코드 분석 탭에서 분석을 실행해주세요.
          </div>
        )}
      </div>
    </div>
  )
}
