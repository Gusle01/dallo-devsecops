import React from 'react'
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts'
import { CHART_PALETTE, COLORS } from '../colors'

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

export default function TypeChart({ data }) {
  const chartData = data.map(d => ({
    name: d.rule_id,
    fullName: d.name,
    value: d.count,
  }))
  const total = chartData.reduce((s, d) => s + d.value, 0)

  return (
    <div className="glass glass-card">
      <div style={{ marginBottom: 18 }}>
        <span className="chapter-label">FIG.02</span>
        <h3 className="section-title">findings_per_class</h3>
        <p className="text-subtitle"># taxonomy of defects</p>
      </div>

      {chartData.length === 0 ? (
        <div className="empty-state" style={{ padding: 60 }}>
          <div className="empty-state__description">no data on file</div>
        </div>
      ) : (
        <div style={{ position: 'relative' }}>
          <ResponsiveContainer width="100%" height={280}>
            <PieChart>
              <Pie
                data={chartData}
                cx="50%"
                cy="50%"
                innerRadius={70}
                outerRadius={108}
                paddingAngle={1}
                dataKey="value"
                stroke={COLORS.bg}
                strokeWidth={2}
                animationDuration={700}
                animationBegin={150}
              >
                {chartData.map((_, i) => (
                  <Cell key={i} fill={CHART_PALETTE[i % CHART_PALETTE.length]} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={tt}
                formatter={(value, name, entry) => [value, entry.payload.fullName]}
              />
            </PieChart>
          </ResponsiveContainer>

          {/* Center total */}
          <div style={{
            position: 'absolute',
            top: '50%',
            left: '50%',
            transform: 'translate(-50%, -50%)',
            textAlign: 'center',
            pointerEvents: 'none',
          }}>
            <div className="display-number" style={{
              fontSize: 44,
              color: COLORS.phosphor,
              textShadow: '0 0 18px rgba(158, 255, 125, 0.4)',
            }}>
              {String(total).padStart(2, '0')}
            </div>
            <div style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 9,
              color: 'var(--ink-dim)',
              marginTop: 6,
              textTransform: 'uppercase',
              letterSpacing: '0.18em',
            }}>
              total · n
            </div>
          </div>
        </div>
      )}

      {/* Legend */}
      {chartData.length > 0 && (
        <div style={{
          marginTop: 22,
          paddingTop: 14,
          borderTop: '1px dashed var(--rule-hot)',
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          columnGap: 18,
          rowGap: 6,
        }}>
          {chartData.slice(0, 6).map((item, i) => (
            <div key={i} style={{
              display: 'flex',
              alignItems: 'center',
              gap: 10,
              fontSize: 10,
              fontFamily: 'var(--font-mono)',
              padding: '4px 0',
              borderBottom: '1px dashed var(--rule)',
              textTransform: 'uppercase',
              letterSpacing: '0.04em',
            }}>
              <span style={{
                width: 9,
                height: 9,
                background: CHART_PALETTE[i % CHART_PALETTE.length],
                flexShrink: 0,
              }} />
              <span style={{
                color: 'var(--ink-dim)',
                flex: 1,
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}>
                {item.name}
              </span>
              <span style={{
                color: 'var(--phosphor)',
                fontWeight: 700,
              }}>
                {String(item.value).padStart(2, '0')}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
