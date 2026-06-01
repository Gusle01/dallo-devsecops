"""
분석 결과 리포트 생성기.

대시보드의 open_report 및 /api/report/{generate,preview} 엔드포인트가 사용하는
Markdown/HTML 보안 리포트를 생성합니다.

HTML 리포트는 대시보드와 동일한 라이트 테마(Pretendard/Fraunces/JetBrains Mono,
에메랄드 악센트)이며, 취약점 표에 CWE/CVE/CVSS를, 블루팀 수정에 수정 전/후 diff를
포함합니다.
"""

from __future__ import annotations

import difflib
import html
import os
from datetime import datetime

SEV_KO = {"CRITICAL": "심각", "HIGH": "높음", "MEDIUM": "중간", "LOW": "낮음"}
SEV_COLOR = {"CRITICAL": "#b21f16", "HIGH": "#d23a2c", "MEDIUM": "#b9740b", "LOW": "#2563c9"}
RISK_KO = {"GREEN": "양호", "AMBER": "주의", "RED": "위험", "CRITICAL": "심각"}
RISK_COLOR = {"GREEN": "#0a7d56", "AMBER": "#b9740b", "RED": "#d23a2c", "CRITICAL": "#b21f16"}

_FIX_TYPE_KO = {"minimal": "최소 수정", "recommended": "권장 수정", "structural": "구조 개선"}

REPORT_CSS = """
  *{margin:0;padding:0;box-sizing:border-box}
  :root{
    --bg:#f4f3ee;--card:#ffffff;--soft:#faf9f6;
    --ink:#232019;--ink-dim:#6b6557;--ink-faint:#9c958a;
    --rule:#e7e3da;--rule-hot:#d8d3c8;
    --emerald:#0a7d56;--emerald-dim:#0a6646;--amber:#b9740b;--blood:#d23a2c;--blue:#2563c9;
    --sans:'Pretendard',-apple-system,BlinkMacSystemFont,system-ui,sans-serif;
    --serif:'Fraunces','Pretendard',Georgia,serif;
    --mono:'JetBrains Mono',ui-monospace,Consolas,monospace;
  }
  html,body{background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:14px;line-height:1.6;-webkit-font-smoothing:antialiased}
  body{padding:0 0 80px;min-height:100vh}
  .wrap{max-width:980px;margin:0 auto;padding:0 56px}
  a{color:var(--emerald);text-decoration:underline;text-underline-offset:2px;text-decoration-color:rgba(10,125,86,.35)}
  a:hover{color:var(--emerald-dim)}
  code{font-family:var(--mono);font-size:.88em;color:var(--blue);background:none}
  .dim{color:var(--ink-faint)} .red{color:var(--blood)} .blue{color:var(--blue)}
  strong{color:var(--ink);font-weight:700}
  pre{font-family:var(--mono);background:var(--soft);color:var(--ink);padding:14px 18px;font-size:12px;line-height:1.7;overflow-x:auto;border:1px solid var(--rule);border-radius:8px;margin:12px 0;white-space:pre-wrap;overflow-wrap:anywhere}
  pre code{background:none;padding:0;color:inherit;font-size:inherit}
  .statusbar{display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap;max-width:980px;margin:0 auto;padding:12px 56px;font-family:var(--mono);font-size:11px;color:var(--ink-faint);border-bottom:1px solid var(--rule)}
  .statusbar .pill{padding:1px 9px;border-radius:999px;color:#fff;font-weight:600}
  .masthead{padding-top:40px;margin-bottom:30px;padding-bottom:20px;border-bottom:1px solid var(--rule);position:relative}
  .masthead::after{content:'';position:absolute;left:0;bottom:-1px;width:56px;height:2px;background:var(--emerald);border-radius:2px}
  .wordmark{font-family:var(--serif);font-size:42px;font-weight:600;letter-spacing:-.02em;line-height:1}
  .wordmark .accent{color:var(--emerald)} .wordmark .dot{color:var(--ink-faint);font-weight:400}
  .tagline{font-size:13px;color:var(--ink-dim);margin-top:10px}
  .meta{display:flex;gap:22px;font-family:var(--mono);font-size:11px;color:var(--ink-faint);margin-top:16px;flex-wrap:wrap}
  .meta strong{color:var(--emerald);font-weight:600}
  h1{font-family:var(--serif);font-size:40px;font-weight:600;line-height:1.05;letter-spacing:-.02em;margin:36px 0 12px}
  h1 em{font-style:normal;color:var(--emerald)}
  .deck{font-size:14px;color:var(--ink-dim);max-width:80ch;line-height:1.65;margin-bottom:24px}
  h2{font-family:var(--serif);font-size:24px;font-weight:600;letter-spacing:-.01em;margin:52px 0 4px;color:var(--ink)}
  .h2-deck{font-size:13px;color:var(--ink-dim);margin-bottom:20px;border-bottom:1px solid var(--rule);padding-bottom:12px}
  .figures{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin:22px 0 30px}
  .fig{padding:14px 16px;border:1px solid var(--rule);border-top:2px solid;border-radius:10px;background:var(--card);box-shadow:0 1px 2px rgba(40,34,20,.05)}
  .fig__label{font-size:11px;font-weight:600;color:var(--ink-dim);display:flex;justify-content:space-between;margin-bottom:10px}
  .fig__label .k{color:var(--ink-faint);font-family:var(--mono);font-size:9px;letter-spacing:.1em}
  .fig__value{font-family:var(--serif);font-size:40px;font-weight:600;line-height:.9;letter-spacing:-.03em}
  .verdict{padding:18px 22px;background:var(--card);border:1px solid var(--rule);border-left:3px solid var(--emerald);border-radius:10px;margin:18px 0;font-size:14px;line-height:1.75;box-shadow:0 1px 2px rgba(40,34,20,.05)}
  .verdict strong{color:var(--emerald)}
  .level{display:inline-block;padding:2px 11px;border-radius:999px;border:1px solid;font-weight:700;font-size:12px}
  table{width:100%;border-collapse:collapse;margin:14px 0 32px;font-size:13px;background:var(--card);border:1px solid var(--rule);border-radius:10px;overflow:hidden}
  th{font-family:var(--sans);font-size:11px;color:var(--ink-dim);text-align:left;padding:11px 12px;border-bottom:1px solid var(--rule-hot);font-weight:700;background:var(--soft);text-transform:uppercase;letter-spacing:.04em}
  td{padding:10px 12px;border-bottom:1px solid var(--rule);color:var(--ink-dim);vertical-align:top}
  tr:last-child td{border-bottom:none}
  td.num{color:var(--ink-faint);font-family:var(--mono);font-weight:600}
  td.title{color:var(--ink)} td.rt{text-align:right;font-family:var(--mono)} td.cve{font-size:11px}
  .sev{font-weight:700;font-size:11px;padding:2px 9px;border:1px solid;border-radius:999px;display:inline-block;white-space:nowrap}
  .entry,.remedy{margin:18px 0;padding:22px 24px;border:1px solid var(--rule);border-radius:12px;background:var(--card);box-shadow:0 1px 2px rgba(40,34,20,.05)}
  .remedy{border-left:3px solid var(--emerald)}
  .entry__head,.remedy__head{display:flex;gap:12px;align-items:baseline;margin-bottom:8px}
  .entry__num,.remedy__num{font-family:var(--mono);font-size:13px;font-weight:700;color:var(--emerald)}
  .entry__title,.remedy__title{font-family:var(--serif);font-size:20px;font-weight:600;letter-spacing:-.01em;line-height:1.2;color:var(--ink)}
  .remedy__title .dim{color:var(--ink-faint);font-weight:400;font-family:var(--sans)}
  .entry__meta,.remedy__meta{font-size:12px;color:var(--ink-dim);margin-bottom:12px}
  .entry__body{font-size:13.5px;line-height:1.7;color:var(--ink);max-width:80ch;margin:10px 0;padding-left:14px;border-left:2px solid var(--rule-hot)}
  .entry__locus{font-family:var(--mono);font-size:12px;color:var(--blue);margin:10px 0}
  .remedy__body{font-size:13.5px;line-height:1.7;color:var(--ink-dim);max-width:80ch;margin:8px 0 4px}
  .diff{border:1px solid var(--rule-hot);border-radius:10px;overflow:hidden;margin:14px 0;background:var(--card)}
  .diff__head{display:flex;justify-content:space-between;align-items:center;padding:9px 14px;background:var(--soft);border-bottom:1px solid var(--rule);font-family:var(--mono);font-size:11px;color:var(--ink-dim)}
  .diff__head .add-c{color:var(--emerald);font-weight:700} .diff__head .del-c{color:var(--blood);font-weight:700}
  .diff__body{font-family:var(--mono);font-size:12px;line-height:1.7;overflow-x:auto}
  .diff__only{margin:0;border:none;border-radius:0}
  .dl{display:grid;grid-template-columns:18px 1fr;white-space:pre-wrap;overflow-wrap:anywhere}
  .dl--add{background:rgba(10,125,86,.10)} .dl--del{background:rgba(210,58,44,.10)}
  .dl--hunk{background:var(--soft);color:var(--ink-faint)}
  .dls{text-align:center;user-select:none;color:var(--ink-faint)}
  .dl--add .dls{color:var(--emerald)} .dl--del .dls{color:var(--blood)}
  .dlc{padding-right:12px;color:var(--ink)}
  .witness{margin-top:14px;font-size:12px;padding:9px 14px;border:1px solid;border-radius:8px;font-weight:600}
  .witness--passed{color:var(--emerald);border-color:rgba(10,125,86,.4);background:rgba(10,125,86,.07)}
  .witness--failed{color:var(--blood);border-color:rgba(210,58,44,.4);background:rgba(210,58,44,.07)}
  .colophon{margin-top:56px;padding-top:16px;border-top:1px solid var(--rule);display:flex;justify-content:space-between;font-family:var(--mono);font-size:11px;color:var(--ink-faint);flex-wrap:wrap;gap:12px}
  *{-webkit-print-color-adjust:exact;print-color-adjust:exact}
  @media print{html,body{background:#fff}.wrap,.statusbar{padding-left:12px;padding-right:12px}.fig,.entry,.remedy,.verdict,table,.diff{box-shadow:none;break-inside:avoid}}
"""


class ReportGenerator:
    def save_report(self, data: dict, output_dir: str = "reports", fmt: str = "both", include_deps: dict | None = None) -> dict:
        os.makedirs(output_dir, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        files = {}

        if fmt in {"md", "markdown", "both"}:
            md_path = os.path.join(output_dir, f"dallo_report_{stamp}.md")
            with open(md_path, "w", encoding="utf-8") as f:
                f.write(self.generate_markdown(data, include_deps))
            files["markdown"] = md_path

        if fmt in {"html", "both"}:
            html_path = os.path.join(output_dir, f"dallo_report_{stamp}.html")
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(self.generate_html(data, include_deps))
            files["html"] = html_path

        return files

    # ---------- helpers ----------
    @staticmethod
    def _esc(text) -> str:
        return html.escape(str(text if text is not None else ""))

    @staticmethod
    def _cvss_color(score) -> str:
        try:
            s = float(score or 0)
        except (TypeError, ValueError):
            s = 0.0
        if s >= 9:
            return "#b21f16"
        if s >= 7:
            return "#d23a2c"
        if s >= 4:
            return "#b9740b"
        if s > 0:
            return "#2563c9"
        return "#9c958a"

    def _cwe_link(self, cwe) -> str:
        if not cwe:
            return "--"
        num = str(cwe).replace("CWE-", "")
        return f'<a href="https://cwe.mitre.org/data/definitions/{num}.html" target="_blank">{self._esc(cwe)}</a>'

    def _cve_links(self, ids) -> str:
        ids = ids or []
        if not ids:
            return "--"
        first = ids[0]
        more = f" +{len(ids) - 1}" if len(ids) > 1 else ""
        return (f'<a href="https://nvd.nist.gov/vuln/detail/{self._esc(first)}" target="_blank" '
                f'title="{self._esc(", ".join(map(str, ids)))}">{self._esc(first)}{more}</a>')

    def _diff_block(self, original, fixed) -> str:
        orig = str(original or "")
        fix = str(fixed or "")
        if not orig.strip():
            return ('<div class="diff"><div class="diff__head"><span>수정 코드</span>'
                    '<span class="dim">// 비교할 원본 없음</span></div>'
                    f'<pre class="diff__only">{self._esc(fix)}</pre></div>')
        added = removed = 0
        rows = []
        for ln in difflib.unified_diff(orig.splitlines(), fix.splitlines(), lineterm="", n=3):
            if ln.startswith("+++") or ln.startswith("---"):
                continue
            if ln.startswith("@@"):
                rows.append(f'<div class="dl dl--hunk"><span class="dls"></span><span class="dlc">{self._esc(ln)}</span></div>')
            elif ln.startswith("+"):
                added += 1
                rows.append(f'<div class="dl dl--add"><span class="dls">+</span><span class="dlc">{self._esc(ln[1:])}</span></div>')
            elif ln.startswith("-"):
                removed += 1
                rows.append(f'<div class="dl dl--del"><span class="dls">-</span><span class="dlc">{self._esc(ln[1:])}</span></div>')
            else:
                txt = ln[1:] if ln.startswith(" ") else ln
                rows.append(f'<div class="dl"><span class="dls"> </span><span class="dlc">{self._esc(txt)}</span></div>')
        head = ('<div class="diff__head"><span>수정 전 / 후 <span class="dim">// 레드 → 블루</span></span>'
                f'<span><span class="add-c">+{added}</span> <span class="del-c">−{removed}</span></span></div>')
        return f'<div class="diff">{head}<div class="diff__body">{"".join(rows)}</div></div>'

    # ---------- HTML ----------
    def generate_html(self, data: dict, deps_data: dict | None = None) -> str:
        summary = data.get("summary") or {}
        vulns = data.get("vulnerabilities") or []
        patches = data.get("patches") or []
        red_blue = data.get("red_blue_summary") or {}
        red = red_blue.get("red_team") or {}
        blue = red_blue.get("blue_team") or {}
        cmp = red_blue.get("comparison") or {}

        total = summary.get("total", len(vulns))
        high = summary.get("high", 0)
        medium = summary.get("medium", 0)
        low = summary.get("low", 0)
        patch_gen = summary.get("patches_generated", len([p for p in patches if p.get("fixed_code")]))
        patch_ver = summary.get("patches_verified",
                                len([p for p in patches if "verified" in str(p.get("status", "")).lower()]))
        risk_score = high * 10 + medium * 5 + low * 1
        risk_level = "GREEN" if risk_score < 10 else "AMBER" if risk_score < 30 else "RED" if risk_score < 60 else "CRITICAL"
        risk_color = RISK_COLOR[risk_level]
        fix_rate = round(patch_ver / total * 100) if total and patch_ver else 0
        now = datetime.now()
        date_str = now.strftime("%Y-%m-%d %H:%M:%S")
        issue_id = now.strftime("%Y%m%d-%H%M")

        # 취약점 id -> vuln (패치의 CWE/CVE/원본코드 연결용)
        vmap = {}
        for v in vulns:
            for key in (v.get("id"), v.get("vulnerability_id")):
                if key is not None:
                    vmap[str(key)] = v

        def fig(k, label, value, color):
            return (f'<div class="fig" style="border-top-color:{color}">'
                    f'<div class="fig__label"><span style="color:{color}">{label}</span><span class="k">{k}</span></div>'
                    f'<div class="fig__value" style="color:{color}">{str(value).zfill(2)}</div></div>')

        figures = "".join([
            fig("TOT", "전체", total, "#232019"),
            fig("HIG", "높음", high, "#d23a2c"),
            fig("MED", "중간", medium, "#b9740b"),
            fig("LOW", "낮음", low, "#2563c9"),
            fig("GEN", "초안", patch_gen, "#2563c9"),
            fig("VER", "검증", patch_ver, "#0a7d56"),
        ])

        # 탐지 표
        rows = []
        for i, v in enumerate(vulns, 1):
            sev = v.get("severity", "LOW")
            sc = SEV_COLOR.get(sev, "#6b6557")
            cvss = v.get("cvss_score")
            cvss_txt = f'{float(cvss):.1f}' if cvss not in (None, "", 0, 0.0) else "--"
            rows.append(
                f'<tr><td class="num">{str(i).zfill(2)}</td>'
                f'<td><span class="sev" style="color:{sc};border-color:{sc}">{SEV_KO.get(sev, sev)}</span></td>'
                f'<td class="rt" style="color:{self._cvss_color(cvss)};font-weight:700">{cvss_txt}</td>'
                f'<td><code>{self._esc(v.get("rule_id") or "--")}</code></td>'
                f'<td class="title">{self._esc(v.get("title") or "--")}</td>'
                f'<td><code>{self._esc((v.get("file_path") or "").split("/")[-1])}</code></td>'
                f'<td class="rt">:{v.get("line_number", "?")}</td>'
                f'<td>{self._cwe_link(v.get("cwe_id"))}</td>'
                f'<td class="cve">{self._cve_links(v.get("cve_ids"))}</td></tr>'
            )
        table = ("".join(rows)) if rows else '<tr><td colspan="9" class="dim">탐지 항목이 없습니다.</td></tr>'

        # 상세
        details = []
        for i, v in enumerate(vulns, 1):
            sev = v.get("severity", "LOW")
            sc = SEV_COLOR.get(sev, "#6b6557")
            cvss = v.get("cvss_score")
            cvss_meta = f'&nbsp;·&nbsp; CVSS <strong>{float(cvss):.1f}</strong>' if cvss not in (None, "", 0, 0.0) else ""
            snippet = f'<pre><code>{self._esc(v.get("code_snippet"))}</code></pre>' if v.get("code_snippet") else ""
            attack = f'<p class="entry__body"><strong class="red">[공격]</strong> {self._esc(v.get("attack_scenario"))}</p>' if v.get("attack_scenario") else ""
            defense = f'<p class="entry__body"><strong class="blue">[방어]</strong> {self._esc(v.get("blue_team_strategy"))}</p>' if v.get("blue_team_strategy") else ""
            cwe_meta = f'&nbsp;·&nbsp; {self._cwe_link(v.get("cwe_id"))}' if v.get("cwe_id") else ""
            cve_meta = f'&nbsp;·&nbsp; {self._cve_links(v.get("cve_ids"))}' if v.get("cve_ids") else ""
            details.append(
                f'<article class="entry"><header class="entry__head">'
                f'<span class="entry__num">{str(i).zfill(2)}</span>'
                f'<h3 class="entry__title">{self._esc(v.get("title") or "")}</h3></header>'
                f'<p class="entry__meta"><span class="sev" style="color:{sc};border-color:{sc}">{SEV_KO.get(sev, sev)}</span>'
                f'&nbsp; <code>{self._esc(v.get("rule_id") or "")}</code>{cwe_meta}{cve_meta}{cvss_meta}</p>'
                f'<p class="entry__body">{self._esc(v.get("description") or "--")}</p>{attack}{defense}'
                f'<p class="entry__locus">@ {self._esc(v.get("file_path") or "")}:{v.get("line_number", "?")}</p>{snippet}</article>'
            )

        # 수정 (diff 포함)
        valid_patches = [p for p in patches if p.get("fixed_code")]
        remedies = []
        for i, p in enumerate(valid_patches, 1):
            pv = vmap.get(str(p.get("vulnerability_id"))) or {}
            type_label = _FIX_TYPE_KO.get(p.get("fix_type"), "패치")
            exp = (p.get("explanation") or "").split("\n\n✅")[0].split("\n\n❌")[0].strip()
            tags = []
            if pv.get("cwe_id"):
                tags.append(self._cwe_link(pv.get("cwe_id")))
            if pv.get("cve_ids"):
                tags.append(self._cve_links(pv.get("cve_ids")))
            if pv.get("cvss_score") not in (None, "", 0, 0.0):
                tags.append(f'CVSS <strong>{float(pv["cvss_score"]):.1f}</strong>')
            tags_html = "&nbsp;·&nbsp; ".join(tags) if tags else f'<span class="dim">{self._esc(p.get("vulnerability_id") or "")}</span>'

            original = (p.get("original_code") or p.get("source_full")
                        or pv.get("original_code") or pv.get("function_code") or pv.get("code_snippet") or "")
            diff_html = self._diff_block(original, p.get("fixed_code"))

            sec = p.get("security_revalidation") or {}
            if sec.get("passed"):
                witness = (f'<p class="witness witness--passed">✓ 보안 재검증 통과 · 취약점 '
                           f'{sec.get("original_vuln_count", 0)} → {sec.get("fixed_vuln_count", 0)} '
                           f'({sec.get("removed_count", 0)}건 제거)</p>')
            elif sec.get("introduced_count", 0) > 0:
                witness = f'<p class="witness witness--failed">✕ 재검증에서 새 취약점 {sec.get("introduced_count")}건 발생</p>'
            else:
                witness = ""
            exp_html = f'<p class="remedy__body">{self._esc(exp)}</p>' if exp else ""
            remedies.append(
                f'<article class="remedy"><header class="remedy__head">'
                f'<span class="remedy__num">{str(i).zfill(2)}</span>'
                f'<h3 class="remedy__title">{type_label} <span class="dim">/ {self._esc(pv.get("title") or p.get("vulnerability_id") or "--")}</span></h3></header>'
                f'<p class="remedy__meta">{tags_html}</p>{exp_html}{diff_html}{witness}</article>'
            )

        verdict_action = {
            "GREEN": "즉각적인 조치가 필요하지 않습니다. 정기적인 점검을 유지하세요.",
            "AMBER": "주의가 필요합니다. 다음 배포 전에 높음 등급 항목을 처리하세요.",
        }.get(risk_level, "즉시 조치가 필요합니다. 심각 항목이 수정될 때까지 릴리스를 보류하세요.")

        findings_section = ""
        if vulns:
            findings_section = (
                '<h2>탐지 — 레드팀</h2>'
                '<div class="h2-deck">전체 공격 관점 목록 · 심각도 → 파일 순 · CWE/CVE/CVSS 포함</div>'
                '<table><thead><tr><th>번호</th><th>심각도</th><th class="rt">CVSS</th><th>규칙</th>'
                '<th>제목</th><th>파일</th><th class="rt">라인</th><th>CWE</th><th>CVE</th></tr></thead>'
                f'<tbody>{table}</tbody></table>'
                '<h2>상세 — 공격 분석</h2>'
                '<div class="h2-deck">코드 발췌와 방어 전략을 포함한 레드팀 항목</div>'
                f'{"".join(details)}'
            )

        remedy_section = ""
        if valid_patches:
            witnessed = "재분석으로 검증됨" if patch_ver > 0 else "검증 대기"
            remedy_section = (
                '<h2>수정 — 블루팀</h2>'
                f'<div class="h2-deck">LLM 작성 방어 · {witnessed} · 수정 전/후 diff 포함</div>'
                f'{"".join(remedies)}'
            )

        deps_note = ('<h2>의존성</h2><div class="h2-deck">의존성 스캔 데이터가 포함되었습니다.</div>'
                     if deps_data else "")

        return f"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>dallo.sec / 보안 리포트 {issue_id}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://cdn.jsdelivr.net/gh/orioncactus/pretendard@v1.3.9/dist/web/static/pretendard.css" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Fraunces:ital,opsz,wght@0,9..144,500..800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>{REPORT_CSS}</style>
</head>
<body>
  <div class="statusbar">
    <span>dallo.sec · 보안 리포트</span>
    <span>{date_str}</span>
    <span>ID {issue_id}</span>
    <span>위험도 <span class="pill" style="background:{risk_color}">{RISK_KO[risk_level]}</span></span>
    <span>이슈 {total}건</span>
  </div>
  <div class="wrap">
    <header class="masthead">
      <div class="wordmark">dallo<span class="dot">.</span><span class="accent">sec</span></div>
      <div class="tagline">레드팀 스캔 · 블루팀 방어 · 수정 전/후 근거</div>
      <div class="meta">
        <span>리포트 <strong>{issue_id}</strong></span>
        <span>생성 <strong>{date_str}</strong></span>
        <span>세션 <strong>{self._esc(data.get("session_id") or "-")}</strong></span>
      </div>
    </header>

    <h1>공격·방어 보안 <em>리포트</em></h1>
    <p class="deck">레드팀 탐지 {total}건 · 블루팀 조치 {patch_gen}건 · 위험 등급 {RISK_KO[risk_level]}{f' · 수정률 {fix_rate}%' if fix_rate else ''}</p>

    <h2>요약 — 레드 · 블루</h2>
    <div class="h2-deck">공격 표면, 수정 근거, 그리고 수정 전/후 보안 상태</div>
    <div class="figures">{figures}</div>

    <div class="verdict">
      레드팀: <strong>{red.get("total_findings", total)}</strong>건 탐지 · <strong>{red.get("affected_files", 0)}</strong>개 파일 영향 · 고유 CWE <strong>{red.get("unique_cwe", 0)}</strong><br/>
      블루팀: <strong>{blue.get("patches_generated", patch_gen)}</strong>건 초안 · <strong>{blue.get("patches_verified", patch_ver)}</strong>건 검증 · 위험 감소 <strong>{cmp.get("risk_reduction_percent", 0)}%</strong>
    </div>
    <div class="verdict">
      위험 등급 <span class="level" style="color:{risk_color};border-color:{risk_color}">{RISK_KO[risk_level]}</span>
      &nbsp; · &nbsp; 가중 점수 <strong>{risk_score}</strong>{f'&nbsp; · &nbsp; 수정률 <strong>{fix_rate}%</strong>' if fix_rate else ''}
      <br/><br/>{verdict_action}
    </div>

    {findings_section}
    {remedy_section}
    {deps_note}

    <footer class="colophon">
      <span>리포트 끝 · dallo.sec</span>
      <span>생성 {date_str}</span>
    </footer>
  </div>
</body>
</html>"""

    # ---------- Markdown ----------
    def generate_markdown(self, data: dict, deps_data: dict | None = None) -> str:
        summary = data.get("summary") or {}
        vulns = data.get("vulnerabilities") or []
        patches = data.get("patches") or []
        audit = data.get("llm_audit") or {}
        red_blue = data.get("red_blue_summary") or {}

        vmap = {}
        for v in vulns:
            for key in (v.get("id"), v.get("vulnerability_id")):
                if key is not None:
                    vmap[str(key)] = v

        lines = [
            "# Dallo DevSecOps 보안 리포트",
            "",
            f"- 세션: `{data.get('session_id', '')}`",
            f"- 모드: `{data.get('analysis_mode', 'red_blue')}`",
            f"- 소요: `{data.get('duration_seconds', 0)}` 초",
            "",
            "## 요약",
            "",
            f"- 전체 탐지: {summary.get('total', len(vulns))}",
            f"- 높음: {summary.get('high', 0)} · 중간: {summary.get('medium', 0)} · 낮음: {summary.get('low', 0)}",
            f"- 패치 초안: {summary.get('patches_generated', len(patches))} · 검증: {summary.get('patches_verified', 0)}",
            "",
        ]

        if audit:
            lines += [
                "## LLM 정밀점검",
                "",
                f"- 상태: `{audit.get('status', 'reviewed')}`",
                f"- 요약: {audit.get('summary', '')}",
                f"- 놓친 항목: {len(audit.get('findings') or [])}",
                "",
            ]

        lines += [
            "## 레드 · 블루",
            "",
            f"- 공격 경로: {len(red_blue.get('attack_paths') or [])}",
            f"- 위험 감소: {(red_blue.get('comparison') or {}).get('risk_reduction_percent', 0)}%",
            "",
            "## 탐지 — 레드팀",
            "",
        ]

        if not vulns:
            lines.append("탐지 항목이 없습니다.")
        else:
            lines += [
                "| 번호 | 심각도 | CVSS | 규칙 | 제목 | 파일 | 라인 | CWE | CVE |",
                "|---:|------|---:|------|------|------|---:|-----|-----|",
            ]
            for i, v in enumerate(vulns, 1):
                cvss = v.get("cvss_score")
                cvss_txt = f"{float(cvss):.1f}" if cvss not in (None, "", 0, 0.0) else "--"
                cve = " ".join(map(str, v.get("cve_ids") or [])) or "--"
                lines.append(
                    f"| {str(i).zfill(2)} | {SEV_KO.get(v.get('severity'), v.get('severity', '?'))} | {cvss_txt} | "
                    f"`{v.get('rule_id', '')}` | {v.get('title', '')} | `{(v.get('file_path') or '').split('/')[-1]}` | "
                    f":{v.get('line_number', '?')} | {v.get('cwe_id') or '--'} | {cve} |"
                )
            lines.append("")

        valid_patches = [p for p in patches if p.get("fixed_code")]
        if valid_patches:
            lines += ["## 수정 — 블루팀", ""]
            for i, p in enumerate(valid_patches, 1):
                pv = vmap.get(str(p.get("vulnerability_id"))) or {}
                type_label = _FIX_TYPE_KO.get(p.get("fix_type"), "패치")
                ref = " · ".join([x for x in (pv.get("cwe_id"), " ".join(map(str, pv.get("cve_ids") or []))) if x])
                lines.append(f"### [{str(i).zfill(2)}] {type_label} / {pv.get('title') or p.get('vulnerability_id') or '--'}")
                lines.append("")
                if ref:
                    lines += [f"> {ref}", ""]
                if p.get("explanation"):
                    lines += [p["explanation"].split("\n\n✅")[0].split("\n\n❌")[0].strip(), ""]
                original = (p.get("original_code") or p.get("source_full")
                            or pv.get("original_code") or pv.get("function_code") or pv.get("code_snippet") or "")
                if str(original).strip():
                    diff = difflib.unified_diff(str(original).splitlines(), str(p["fixed_code"]).splitlines(), lineterm="", n=3)
                    body = "\n".join(l for l in diff if not (l.startswith("+++") or l.startswith("---")))
                    lines += ["```diff", body, "```", ""]
                else:
                    lines += ["```", str(p["fixed_code"]), "```", ""]
                sec = p.get("security_revalidation") or {}
                if sec.get("passed"):
                    lines += [f"> ✓ 보안 재검증 통과 · {sec.get('original_vuln_count', 0)} → {sec.get('fixed_vuln_count', 0)} ({sec.get('removed_count', 0)}건 제거)", ""]

        if deps_data:
            lines += ["## 의존성", "", "의존성 스캔 데이터가 포함되었습니다.", ""]

        lines += ["---", "", "리포트 끝 · dallo.sec"]
        return "\n".join(lines)
