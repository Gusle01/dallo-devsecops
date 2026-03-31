"""
크로스 사이트 스크립팅(XSS) 취약점 샘플 코드
- 사용자 입력을 이스케이프 없이 HTML에 삽입
- OWASP: A03:2021 Injection (XSS)
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs


class VulnerableHandler(BaseHTTPRequestHandler):
    """XSS에 취약한 HTTP 핸들러"""

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path == "/search":
            keyword = params.get("q", [""])[0]

            # [취약] 사용자 입력을 이스케이프 없이 HTML에 직접 삽입
            html = f"""
            <html>
            <body>
                <h1>검색 결과</h1>
                <p>검색어: {keyword}</p>
                <form action="/search" method="GET">
                    <input name="q" value="{keyword}">
                    <button type="submit">검색</button>
                </form>
            </body>
            </html>
            """

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html.encode())

        elif parsed.path == "/profile":
            username = params.get("name", ["Guest"])[0]
            bio = params.get("bio", [""])[0]

            # [취약] 프로필 정보를 이스케이프 없이 렌더링
            html = f"""
            <html>
            <body>
                <h1>{username}의 프로필</h1>
                <div class="bio">{bio}</div>
            </body>
            </html>
            """

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html.encode())


def render_comment(user_input: str) -> str:
    """취약: 댓글 내용을 이스케이프 없이 HTML로 변환"""
    # [취약] 사용자 입력 직접 삽입
    return f"<div class='comment'><p>{user_input}</p></div>"


def build_error_page(error_msg: str) -> str:
    """취약: 에러 메시지에 사용자 입력이 포함될 경우 XSS"""
    return f"<html><body><h1>오류 발생</h1><p>{error_msg}</p></body></html>"
