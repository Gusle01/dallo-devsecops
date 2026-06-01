"""
파일 분류 모듈 (shared/file_classifier.py)

분석 결과를 "실제 서비스 코드"와 "외부 라이브러리 / vendor / minified 자산"으로
구분합니다. 외부 라이브러리(jquery, bootstrap 등)나 빌드 산출물에서 나온 취약점은
개발자가 직접 고칠 수 없는 경우가 많으므로 기본 결과에서 분리합니다.

분류 결과는 다음 중 하나입니다:
  - "service":  실제 서비스(애플리케이션) 소스코드 — 기본 표시 대상
  - "external": 외부 라이브러리 / vendor / minified / 빌드 산출물 — 별도 영역

판별은 (1) 경로, (2) 파일명, (3) 코드 내용 휴리스틱을 종합합니다.
"""

from __future__ import annotations

import os
import re

# 외부 라이브러리/vendor 디렉토리 (경로 세그먼트로 매칭)
_VENDOR_DIR_SEGMENTS = {
    "node_modules", "bower_components", "vendor", "vendors", "third_party",
    "third-party", "site-packages", "dist-packages", "jspm_packages",
    "dist", "build", "out", "target", "bin", "obj", ".next", ".nuxt",
    "static/vendor", "assets/vendor", "wwwroot/lib", "public/vendor",
    "webroot", "bundles", ".venv", "venv", "env", "egg-info",
}

# 잘 알려진 외부 라이브러리 파일명 패턴 (소문자 비교)
_VENDOR_FILE_PATTERNS = [
    re.compile(r"^jquery([.\-].*)?\.js$"),
    re.compile(r"^bootstrap([.\-].*)?\.(js|css)$"),
    re.compile(r"^angular([.\-].*)?\.js$"),
    re.compile(r"^react(-dom)?(\.production|\.development)?([.\-].*)?\.js$"),
    re.compile(r"^vue([.\-].*)?\.js$"),
    re.compile(r"^lodash([.\-].*)?\.js$"),
    re.compile(r"^moment([.\-].*)?\.js$"),
    re.compile(r"^underscore([.\-].*)?\.js$"),
    re.compile(r"^popper([.\-].*)?\.js$"),
    re.compile(r"^d3([.\-].*)?\.js$"),
    re.compile(r"^three([.\-].*)?\.js$"),
    re.compile(r"^axios([.\-].*)?\.js$"),
    re.compile(r"^modernizr([.\-].*)?\.js$"),
    re.compile(r"^chart([.\-].*)?\.js$"),
    re.compile(r"^select2([.\-].*)?\.js$"),
    re.compile(r"^datatables([.\-].*)?\.js$"),
    re.compile(r"^swiper([.\-].*)?\.js$"),
    re.compile(r"^tinymce([.\-].*)?\.js$"),
    re.compile(r"^ckeditor([.\-].*)?\.js$"),
    re.compile(r"^polyfill([.\-].*)?\.js$"),
]

# minified / 번들 산출물 파일명 패턴
_MINIFIED_PATTERNS = [
    re.compile(r"\.min\.(js|css)$"),
    re.compile(r"\.bundle\.(js|css)$"),
    re.compile(r"\.chunk\.js$"),
    re.compile(r"-min\.(js|css)$"),
    re.compile(r"\.pack\.js$"),
]

# 내용 휴리스틱 임계값
_MINIFIED_AVG_LINE = 400      # 평균 라인 길이가 이 이상이면 minified로 추정
_MINIFIED_MAX_LINE = 2000     # 단일 라인이 이 이상이면 minified로 추정


def _normalize(path: str) -> str:
    return (path or "").replace("\\", "/").lower()


def _match_vendor_dir(path_lower: str) -> str | None:
    segments = [s for s in path_lower.split("/") if s]
    for seg in segments[:-1]:  # 마지막(파일명) 제외
        if seg in _VENDOR_DIR_SEGMENTS:
            return seg
    # "static/vendor" 같은 복합 세그먼트
    for compound in ("static/vendor", "assets/vendor", "wwwroot/lib", "public/vendor"):
        if compound in path_lower:
            return compound
    return None


def _match_vendor_file(filename_lower: str) -> bool:
    return any(p.match(filename_lower) for p in _VENDOR_FILE_PATTERNS)


def _match_minified_name(filename_lower: str) -> bool:
    return any(p.search(filename_lower) for p in _MINIFIED_PATTERNS)


def _looks_minified(code: str) -> bool:
    if not code:
        return False
    lines = code.split("\n")
    if not lines:
        return False
    max_len = max((len(ln) for ln in lines), default=0)
    if max_len >= _MINIFIED_MAX_LINE:
        return True
    # 평균 라인 길이 (빈 줄 제외)
    non_empty = [ln for ln in lines if ln.strip()]
    if non_empty:
        avg = sum(len(ln) for ln in non_empty) / len(non_empty)
        # 줄 수가 적고 라인이 매우 긴 경우만 minified로 판단 (오탐 방지)
        if avg >= _MINIFIED_AVG_LINE and len(non_empty) <= 50:
            return True
    return False


def classify_file(path: str, code: str = "") -> dict:
    """
    파일 하나를 분류합니다.

    Args:
        path: 파일 경로 (webkitRelativePath 등)
        code: 파일 내용 (선택 — 내용 휴리스틱에 사용)

    Returns:
        {
          "category": "service" | "external",
          "is_external": bool,
          "reason": str,          # 분리 사유 (external일 때)
        }
    """
    path_lower = _normalize(path)
    filename_lower = os.path.basename(path_lower)

    vendor_dir = _match_vendor_dir(path_lower)
    if vendor_dir:
        return _external(f"vendor directory: {vendor_dir}")

    if _match_vendor_file(filename_lower):
        return _external(f"known library file: {filename_lower}")

    if _match_minified_name(filename_lower):
        return _external(f"minified/bundled asset: {filename_lower}")

    if _looks_minified(code):
        return _external("minified content (very long lines)")

    return {"category": "service", "is_external": False, "reason": ""}


def _external(reason: str) -> dict:
    return {"category": "external", "is_external": True, "reason": reason}


def is_external_file(path: str, code: str = "") -> bool:
    """경로/내용으로 외부 라이브러리 여부만 빠르게 판단합니다."""
    return classify_file(path, code)["is_external"]
