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
    return <div style={{ padding: 60, textAlign: 'center', color: '#64748b' }}>Loading...</div>
  }

  return (
    <div>
      <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 20 }}>
        Analysis History ({sessions.length} sessions)
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
              Vulnerability Trend
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
              AI Patch Success Rate
            </h3>
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={trendData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} allowDecimals={false} />
                <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 8 }} />
                <Line type="monotone" dataKey="patches" stroke="#3b82f6" name="Generated" strokeWidth={2} dot={{ r: 4 }} />
                <Line type="monotone" dataKey="verified" stroke="#22c55e" name="Verified" strokeWidth={2} dot={{ r: 4 }} />
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
              {['Session', 'Repo', 'Issues', 'HIGH', 'MED', 'LOW', 'Patches', 'Verified', 'Duration', 'Date'].map(h => (
                <th key={h} style={{
                  padding: '12px 14px', textAlign: 'left', fontSize: 11,
                  fontWeight: 600, color: '#64748b', textTransform: 'uppercase',
                }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sessions.map((s, i) => (
              <tr
                key={i}
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
            ))}
          </tbody>
        </table>

        {sessions.length === 0 && (
          <div style={{ padding: 40, textAlign: 'center', color: '#64748b' }}>
            No analysis sessions yet. Run an analysis from the Analyze tab.
          </div>
        )}
      </div>
    </div>
  )
}
