// 의존성 없는 라인 단위 diff (LCS 기반)
// GitHub PR diff처럼 원본/수정 코드의 추가·삭제·유지 라인을 계산합니다.

// 두 라인 배열의 최장 공통 부분수열(LCS) 길이 테이블을 만든다.
function lcsTable(a, b) {
  const n = a.length
  const m = b.length
  // (n+1) x (m+1) 테이블
  const dp = Array.from({ length: n + 1 }, () => new Int32Array(m + 1))
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      if (a[i] === b[j]) dp[i][j] = dp[i + 1][j + 1] + 1
      else dp[i][j] = Math.max(dp[i + 1][j], dp[i][j + 1])
    }
  }
  return dp
}

// 통합(unified) diff 행 목록을 만든다.
// 각 행: { type: 'equal'|'add'|'del', text, oldNumber, newNumber }
export function diffLines(originalText, fixedText) {
  const a = String(originalText ?? '').split('\n')
  const b = String(fixedText ?? '').split('\n')
  const dp = lcsTable(a, b)

  const rows = []
  let i = 0
  let j = 0
  let oldNo = 1
  let newNo = 1

  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) {
      rows.push({ type: 'equal', text: a[i], oldNumber: oldNo++, newNumber: newNo++ })
      i++; j++
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      rows.push({ type: 'del', text: a[i], oldNumber: oldNo++, newNumber: null })
      i++
    } else {
      rows.push({ type: 'add', text: b[j], oldNumber: null, newNumber: newNo++ })
      j++
    }
  }
  while (i < a.length) {
    rows.push({ type: 'del', text: a[i], oldNumber: oldNo++, newNumber: null })
    i++
  }
  while (j < b.length) {
    rows.push({ type: 'add', text: b[j], oldNumber: null, newNumber: newNo++ })
    j++
  }
  return rows
}

// 좌우 분할(split) diff 행 목록을 만든다.
// 삭제/추가가 연속되면 같은 행에 좌(삭제)·우(추가)로 짝지어 보여준다.
// 각 행: { left: {text, number, type}|null, right: {text, number, type}|null }
export function diffSplit(originalText, fixedText) {
  const unified = diffLines(originalText, fixedText)
  const rows = []
  let buffer = { dels: [], adds: [] }

  const flush = () => {
    const max = Math.max(buffer.dels.length, buffer.adds.length)
    for (let k = 0; k < max; k++) {
      rows.push({
        left: buffer.dels[k]
          ? { text: buffer.dels[k].text, number: buffer.dels[k].oldNumber, type: 'del' }
          : null,
        right: buffer.adds[k]
          ? { text: buffer.adds[k].text, number: buffer.adds[k].newNumber, type: 'add' }
          : null,
      })
    }
    buffer = { dels: [], adds: [] }
  }

  for (const row of unified) {
    if (row.type === 'del') {
      buffer.dels.push(row)
    } else if (row.type === 'add') {
      buffer.adds.push(row)
    } else {
      flush()
      rows.push({
        left: { text: row.text, number: row.oldNumber, type: 'equal' },
        right: { text: row.text, number: row.newNumber, type: 'equal' },
      })
    }
  }
  flush()
  return rows
}

// diff 통계 (추가/삭제 라인 수)
export function diffStats(originalText, fixedText) {
  const rows = diffLines(originalText, fixedText)
  let added = 0
  let removed = 0
  for (const r of rows) {
    if (r.type === 'add') added++
    else if (r.type === 'del') removed++
  }
  return { added, removed }
}
