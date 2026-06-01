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

// LCS 행렬을 너무 크게 만들지 않기 위한 상한 (셀 수). 초과 시 정렬 없이
// 단순 삭제→추가로 폴백해 메인 스레드 프리즈를 방지한다.
const _MAX_MATRIX_CELLS = 2_000_000

// 변경 영역(prefix/suffix를 제외한 가운데 슬라이스)만 LCS로 정렬해 rows에 push.
// 거대 변경 영역은 폴백(전부 del 후 전부 add)으로 처리한다.
function _diffMiddle(aMid, bMid, rows, startOld, startNew) {
  let oldNo = startOld
  let newNo = startNew

  if (aMid.length * bMid.length > _MAX_MATRIX_CELLS) {
    for (let i = 0; i < aMid.length; i++) rows.push({ type: 'del', text: aMid[i], oldNumber: oldNo++, newNumber: null })
    for (let j = 0; j < bMid.length; j++) rows.push({ type: 'add', text: bMid[j], oldNumber: null, newNumber: newNo++ })
    return
  }

  const dp = lcsTable(aMid, bMid)
  let i = 0
  let j = 0
  while (i < aMid.length && j < bMid.length) {
    if (aMid[i] === bMid[j]) {
      rows.push({ type: 'equal', text: aMid[i], oldNumber: oldNo++, newNumber: newNo++ })
      i++; j++
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      rows.push({ type: 'del', text: aMid[i], oldNumber: oldNo++, newNumber: null })
      i++
    } else {
      rows.push({ type: 'add', text: bMid[j], oldNumber: null, newNumber: newNo++ })
      j++
    }
  }
  while (i < aMid.length) { rows.push({ type: 'del', text: aMid[i], oldNumber: oldNo++, newNumber: null }); i++ }
  while (j < bMid.length) { rows.push({ type: 'add', text: bMid[j], oldNumber: null, newNumber: newNo++ }); j++ }
}

// 통합(unified) diff 행 목록을 만든다.
// 각 행: { type: 'equal'|'add'|'del', text, oldNumber, newNumber }
//
// 성능: 공통 prefix/suffix를 먼저 잘라내고 가운데 변경 영역에만 O(n·m) LCS를
// 적용한다. 패치는 보통 함수 하나만 바꾸므로 위·아래가 거의 동일 → 실측 비용이
// 파일 전체 길이가 아니라 변경부 크기에 비례한다.
export function diffLines(originalText, fixedText) {
  const a = String(originalText ?? '').split('\n')
  const b = String(fixedText ?? '').split('\n')
  const n = a.length
  const m = b.length

  // 공통 prefix
  let p = 0
  while (p < n && p < m && a[p] === b[p]) p++
  // 공통 suffix (prefix와 겹치지 않게)
  let s = 0
  while (s < n - p && s < m - p && a[n - 1 - s] === b[m - 1 - s]) s++

  const rows = []
  let oldNo = 1
  let newNo = 1
  for (let i = 0; i < p; i++) rows.push({ type: 'equal', text: a[i], oldNumber: oldNo++, newNumber: newNo++ })

  _diffMiddle(a.slice(p, n - s), b.slice(p, m - s), rows, oldNo, newNo)

  // 가운데에서 소비된 줄 수만큼 번호를 이어서 suffix 처리
  oldNo = (n - s) + 1
  newNo = (m - s) + 1
  for (let k = n - s; k < n; k++) rows.push({ type: 'equal', text: a[k], oldNumber: oldNo++, newNumber: newNo++ })

  return rows
}

// 좌우 분할(split) diff 행 목록을 만든다.
// 삭제/추가가 연속되면 같은 행에 좌(삭제)·우(추가)로 짝지어 보여준다.
// 각 행: { left: {text, number, type}|null, right: {text, number, type}|null }
export function diffSplit(originalText, fixedText) {
  return splitFromLines(diffLines(originalText, fixedText))
}

// 이미 계산된 unified diff 행을 좌우 분할 행으로 변환한다. (LCS 재계산 없음)
export function splitFromLines(unified) {
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

// 패치(fixed_code — 보통 "함수 단위 + 상단 import 추가" 형태)를 전체 원본에
// 합성해 "전체 수정 파일"을 만든다. line_number로 취약 함수 블록을 찾아 교체하고,
// 새로 추가된 top-level import는 파일 상단으로 끌어올린다.
//
// 휴리스틱이므로 단일 함수 수정에 최적화돼 있다. 함수 블록을 못 찾으면 해당
// 라인 1줄만 교체하는 방식으로 폴백한다. (들여쓰기 기반 — Python 중심)
const _DEF_RE = /^(\s*)(async\s+def|def|class)\b/
const _IMPORT_RE = /^(import |from )\S/
const _indentOf = (s) => (s.match(/^(\s*)/)[1] || '').length
const _isBlank = (s) => s.trim() === ''

export function buildFixedFile(originalSource, fixedCode, lineNumber) {
  const src = String(originalSource ?? '')
  const fix = String(fixedCode ?? '')
  if (!src.trim()) return fix
  if (!fix.trim()) return src

  const lines = src.split('\n')

  // 1) fixedCode를 (상단 import) + (본문 함수/블록)으로 분리
  const fixLines = fix.split('\n')
  const bodyStart = fixLines.findIndex(l => _DEF_RE.test(l))
  let newImports = []
  let replacement = fixLines
  if (bodyStart > 0) {
    newImports = fixLines.slice(0, bodyStart).filter(l => _IMPORT_RE.test(l.trim()))
    replacement = fixLines.slice(bodyStart)
  }
  // bodyStart === 0 → import 없음(전체가 본문), -1 → def/class 없음(전체를 본문 취급)

  // 2) 원본에서 교체할 블록(취약 함수) 찾기
  const idx = Math.min(Math.max((Number(lineNumber) || 1) - 1, 0), lines.length - 1)
  let headerIdx = -1
  for (let i = idx; i >= 0; i--) {
    if (_DEF_RE.test(lines[i]) && _indentOf(lines[i]) <= _indentOf(lines[idx])) {
      headerIdx = i
      break
    }
  }

  let start, end, headerIndent
  if (headerIdx === -1) {
    // 함수 블록 못 찾음 → 해당 라인 1줄만 교체 (폴백)
    start = idx
    end = idx + 1
    headerIndent = _indentOf(lines[idx])
  } else {
    headerIndent = _indentOf(lines[headerIdx])
    start = headerIdx
    // 블록 끝: 헤더보다 깊은 들여쓰기(또는 빈 줄)가 이어지는 동안
    let lastNonBlank = headerIdx
    for (let j = headerIdx + 1; j < lines.length; j++) {
      if (_isBlank(lines[j])) continue
      if (_indentOf(lines[j]) > headerIndent) { lastNonBlank = j; continue }
      break
    }
    end = lastNonBlank + 1
  }

  // 3) 교체 본문을 원본 블록 들여쓰기에 맞게 재정렬
  let repl = replacement
  const replBaseIndent = repl.length ? _indentOf(repl[0]) : 0
  const shift = headerIndent - replBaseIndent
  if (shift > 0) {
    const pad = ' '.repeat(shift)
    repl = repl.map(l => (_isBlank(l) ? l : pad + l))
  } else if (shift < 0) {
    const cut = -shift
    repl = repl.map(l => (_isBlank(l) ? l : l.slice(Math.min(cut, _indentOf(l)))))
  }

  // 4) 블록 교체
  const merged = [...lines.slice(0, start), ...repl, ...lines.slice(end)]

  // 5) 새 import 끌어올리기 (이미 있는 건 제외)
  const existing = new Set(merged.map(l => l.trim()))
  const toAdd = newImports.filter(l => l.trim() && !existing.has(l.trim()))
  if (toAdd.length) {
    let insertAt = 0
    for (let i = 0; i < merged.length; i++) {
      if (_IMPORT_RE.test(merged[i].trim())) insertAt = i + 1
      else if (_DEF_RE.test(merged[i])) break
    }
    merged.splice(insertAt, 0, ...toAdd)
  }

  return merged.join('\n')
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
