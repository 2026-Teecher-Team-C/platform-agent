"""브라우저에 보여 줄 다운로드 차단 안내 페이지.

한 장짜리 정적 HTML이다. CSS·SVG는 전부 인라인이고 JavaScript·외부 리소스는 없다(CSP가 막는다).
넣는 값은 전부 `html.escape`를 거친다. 파일명·URL처럼 공격자가 정한 값은 받지도 않는다.
색·글꼴·모서리·간격은 관리 콘솔(platform-server/console/src/index.css)의 토큰을 따른다.
"""

from html import escape

CONTENT_SECURITY_POLICY = "default-src 'none'; style-src 'unsafe-inline'; img-src data:"

# 콘솔 토큰: --surface/--border/--text/--muted, 대시보드 --dash-danger·--dash-warning, 사이드바 색(어두운 테마).
_STYLE = """
:root {
  color-scheme: light dark;
  --bg: #f4f6f8;
  --surface: #ffffff;
  --surface-muted: #f8fafc;
  --border: #dce2e8;
  --text: #18212f;
  --muted: #667085;
  --tone: #b42318;
  --tone-soft: #fef3f2;
}
:root.fail-close {
  --tone: #b54708;
  --tone-soft: #fffaeb;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #101827;
    --surface: #1b2638;
    --surface-muted: #162032;
    --border: #263449;
    --text: #e8edf5;
    --muted: #aebbc9;
    --tone: #f97066;
    --tone-soft: rgb(249 112 102 / 12%);
  }
  :root.fail-close {
    --tone: #fdb022;
    --tone-soft: rgb(253 176 34 / 12%);
  }
}
* { box-sizing: border-box; }
html, body { margin: 0; min-height: 100%; }
body {
  min-height: 100vh;
  display: grid;
  place-items: center;
  padding: 24px 16px;
  background: var(--bg);
  color: var(--text);
  font-family: Inter, Pretendard, -apple-system, BlinkMacSystemFont, "Segoe UI", "Apple SD Gothic Neo",
    "Malgun Gothic", sans-serif;
  font-synthesis: none;
  text-rendering: optimizeLegibility;
  -webkit-font-smoothing: antialiased;
  line-height: 1.6;
  word-break: keep-all;
}
main {
  width: 100%;
  max-width: 520px;
  overflow: hidden;
  border: 1px solid var(--border);
  border-radius: 14px;
  background: var(--surface);
  box-shadow: 0 12px 36px rgb(15 23 42 / 7%);
}
header { padding: 28px 24px 24px; border-bottom: 1px solid var(--border); }
.icon {
  width: 40px;
  height: 40px;
  display: grid;
  place-items: center;
  margin-bottom: 18px;
  border-radius: 10px;
  background: var(--tone-soft);
  color: var(--tone);
}
.icon svg { width: 22px; height: 22px; }
h1 { margin: 0 0 8px; font-size: 20px; line-height: 1.4; letter-spacing: -0.01em; }
header p { margin: 0; color: var(--muted); font-size: 14px; }
dl { margin: 0; }
dl > div { padding: 16px 24px; border-bottom: 1px solid var(--border); }
dt { margin-bottom: 6px; color: var(--muted); font-size: 12px; font-weight: 700; }
dd { margin: 0; font-size: 14px; overflow-wrap: anywhere; }
code {
  display: block;
  padding: 10px 12px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--surface-muted);
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 13px;
  line-height: 1.6;
  overflow-wrap: anywhere;
  user-select: all;
  -webkit-user-select: all;
}
.next {
  margin: 20px 24px 24px;
  padding: 10px 14px;
  border-left: 3px solid var(--tone);
  border-radius: 0 8px 8px 0;
  background: var(--tone-soft);
  font-size: 13px;
}
"""

_SVG_OPEN = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
    'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
)
# 방패 안의 X — 위험 판정으로 막음
_ICON_BLOCKED = (
    _SVG_OPEN + '<path d="M12 3 5 6v5c0 4.4 3 8.3 7 9.5 4-1.2 7-5.1 7-9.5V6z"/><path d="m9.5 9.5 5 5m0-5-5 5"/></svg>'
)
# 방패 안의 느낌표 — 판정을 받지 못해 막음
_ICON_FAIL_CLOSE = (
    _SVG_OPEN + '<path d="M12 3 5 6v5c0 4.4 3 8.3 7 9.5 4-1.2 7-5.1 7-9.5V6z"/><path d="M12 8v4.5"/>'
    '<path d="M12 16h.01"/></svg>'
)

_BLOCKED = {
    "title": "다운로드를 차단했습니다",
    "lead": "보안 검사에서 위험한 파일로 판정되어 이 PC로 내려받지 않았습니다.",
    "next": "업무에 꼭 필요한 파일이라면 보안 담당자에게 위 이벤트 ID를 알려 주세요.",
    "icon": _ICON_BLOCKED,
    "class": "blocked",
}
_FAIL_CLOSE = {
    "title": "검사 서버에 연결하지 못해 다운로드를 막았습니다",
    "lead": "검사를 마치지 못한 파일은 안전을 위해 내려받지 않습니다. 잠시 뒤 다시 시도해 주세요.",
    "next": "계속 같은 화면이 나오면 보안 담당자에게 위 이벤트 ID를 알려 주세요.",
    "icon": _ICON_FAIL_CLOSE,
    "class": "fail-close",
}
FAIL_CLOSE_REASON = "검사 서버의 판정을 받지 못했습니다 (fail-close)"


def render(*, fail_close: bool, reason: str, event_id: str) -> str:
    """차단 안내 HTML을 만든다. reason·event_id는 여기서 이스케이프한다."""
    copy = _FAIL_CLOSE if fail_close else _BLOCKED
    shown_reason = FAIL_CLOSE_REASON if fail_close else (reason or "(없음)")
    return f"""<!doctype html>
<html lang="ko" class="{copy["class"]}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>{escape(copy["title"])}</title>
<style>{_STYLE}</style>
</head>
<body>
<main>
<header>
<div class="icon">{copy["icon"]}</div>
<h1>{escape(copy["title"])}</h1>
<p>{escape(copy["lead"])}</p>
</header>
<dl>
<div><dt>사유</dt><dd>{escape(shown_reason)}</dd></div>
<div><dt>이벤트 ID</dt><dd><code>{escape(event_id)}</code></dd></div>
</dl>
<p class="next">{escape(copy["next"])}</p>
</main>
</body>
</html>
"""
