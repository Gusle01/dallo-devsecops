import React from 'react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer, CartesianGrid } from 'recharts'
import { SEVERITY, COLORS } from '../colors'

const tt = {
  background: COLORS.bgDeep,
  border: `1px solid ${COLORS.phosphor}`,
  borderRadius: 0,
  boxShadow: 'none',
  padding: '8px 12px',
  fontSize: 11,
  fontFamily: 'JetBrains Mono, monospace',
  color: COLORS.ink,
  textTransform: 'uppercase',
  letterSpacing: '0.04em',
}

export default function FileChart({ data }) {
  const chartData = data.map(d => ({
    name: d.file.split('/').pop(),
    HIGH: d.high,
    MED: d.medium,
    LOW: d.low,
  }))

  return (
    <div className="glass glass-card">
      <div style={{ marginBottom: 18 }}>
        <span className="chapter-label">FIG.01</span>
        <h3 className="section-title">findings_per_file</h3>
        <p className="text-subtitle"># count by source path</p>
      </div>

      {chartData.length === 0 ? (
        <div className="empty-state" style={{ padding: 60 }}>
          <div className="empty-state__description">no data on file</div>
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={300}>
          <BarChart data={chartData} margin={{ left: -10, right: 8, top: 8 }}>
            <CartesianGrid strokeDasharray="2 2" stroke={COLORS.rule} vertical={false} />
            <XAxis
              dataKey="name"
              tick={{ fill: COLORS.inkDim, fontSize: 10, fontFamily: 'JetBrains Mono, monospace' }}
              angle={-18}
              textAnchor="end"
              height={64}
              axisLine={{ stroke: COLORS.ruleHot }}
              tickLine={{ stroke: COLORS.ruleHot }}
            />
            <YAxis
              tick={{ fill: COLORS.inkDim, fontSize: 10, fontFamily: 'JetBrains Mono, monospace' }}
              allowDecimals={false}
              axisLine={{ stroke: COLORS.ruleHot }}
              tickLine={{ stroke: COLORS.ruleHot }}
            />
            <Tooltip
              contentStyle={tt}
              labelStyle={{ color: COLORS.phosphor, fontWeight: 700, fontFamily: 'JetBrains Mono, monospace' }}
              cursor={{ fill: 'rgba(158, 255, 125, 0.06)' }}
            />
            <Legend
              wrapperStyle={{
                fontSize: 10,
                paddingTop: 12,
                fontFamily: 'JetBrains Mono, monospace',
                color: COLORS.inkDim,
                textTransform: 'uppercase',
                letterSpacing: '0.14em',
              }}
              iconType="square"
            />
            <Bar dataKey="HIGH" fill={SEVERITY.HIGH}   animationDuration={500} animationBegin={0} />
            <Bar dataKey="MED"  fill={SEVERITY.MEDIUM} animationDuration={500} animationBegin={120} />
            <Bar dataKey="LOW"  fill={SEVERITY.LOW}    animationDuration={500} animationBegin={240} />
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  )
}
