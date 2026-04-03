import React from 'react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer, CartesianGrid } from 'recharts'

export default function FileChart({ data }) {
  const chartData = data.map(d => ({
    name: d.file.split('/').pop(),
    HIGH: d.high,
    MEDIUM: d.medium,
    LOW: d.low,
  }))

  return (
    <div style={{
      background: '#1e293b',
      border: '1px solid #334155',
      borderRadius: 12,
      padding: 24,
    }}>
      <h3 style={{ fontSize: 15, fontWeight: 600, marginBottom: 20, color: '#e2e8f0' }}>
        파일별 취약점 분포
      </h3>
      {chartData.length === 0 ? (
        <div style={{ padding: 40, textAlign: 'center', color: '#64748b' }}>데이터 없음</div>
      ) : (
        <ResponsiveContainer width="100%" height={280}>
          <BarChart data={chartData} margin={{ left: -10 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
            <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} angle={-20} textAnchor="end" height={60} />
            <YAxis tick={{ fill: '#94a3b8', fontSize: 12 }} allowDecimals={false} />
            <Tooltip
              contentStyle={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 8 }}
              labelStyle={{ color: '#e2e8f0' }}
            />
            <Legend wrapperStyle={{ fontSize: 12 }} />
            <Bar dataKey="HIGH" fill="#ef4444" radius={[4, 4, 0, 0]} />
            <Bar dataKey="MEDIUM" fill="#eab308" radius={[4, 4, 0, 0]} />
            <Bar dataKey="LOW" fill="#3b82f6" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  )
}
