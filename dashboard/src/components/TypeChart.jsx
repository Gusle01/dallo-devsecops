import React from 'react'
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts'

const COLORS = ['#ef4444', '#f97316', '#eab308', '#22c55e', '#3b82f6', '#8b5cf6', '#ec4899', '#06b6d4']

export default function TypeChart({ data }) {
  const chartData = data.map(d => ({
    name: d.rule_id,
    fullName: d.name,
    value: d.count,
  }))

  return (
    <div style={{
      background: '#1e293b',
      border: '1px solid #334155',
      borderRadius: 12,
      padding: 24,
    }}>
      <h3 style={{ fontSize: 15, fontWeight: 600, marginBottom: 20, color: '#e2e8f0' }}>
        Vulnerabilities by Type
      </h3>
      {chartData.length === 0 ? (
        <div style={{ padding: 40, textAlign: 'center', color: '#64748b' }}>No data</div>
      ) : (
        <ResponsiveContainer width="100%" height={280}>
          <PieChart>
            <Pie
              data={chartData}
              cx="50%"
              cy="50%"
              innerRadius={55}
              outerRadius={90}
              paddingAngle={3}
              dataKey="value"
              label={({ name, value }) => `${name} (${value})`}
            >
              {chartData.map((_, i) => (
                <Cell key={i} fill={COLORS[i % COLORS.length]} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 8 }}
              formatter={(value, name, entry) => [value, entry.payload.fullName]}
            />
          </PieChart>
        </ResponsiveContainer>
      )}
    </div>
  )
}
