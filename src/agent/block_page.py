"""브라우저에 보여 줄 다운로드 차단 안내 페이지.

한 장짜리 정적 HTML이다. CSS·SVG는 전부 인라인이고 JavaScript·외부 리소스는 없다(CSP가 막는다).
넣는 값은 전부 `html.escape`를 거친다. 파일명·URL처럼 공격자가 정한 값은 받지도 않는다.
서버가 판정 근거(VerdictEvidence)를 주면 위협 이름과 판정 방식을 말로 보여 주고, 거리·SHA·심각도 같은
숫자는 접힌 "자세히"(`<details>`, JS 없음)에만 둔다. 근거가 없으면(구버전 서버) 사유 한 줄 그대로다.
색·글꼴·모서리·간격은 관리 콘솔(platform-server/console/src/index.css)의 토큰을 따른다.
"""

from dataclasses import dataclass
from html import escape

from teecher.verdict.v1 import verdict_pb2

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
.threat { display: block; margin-bottom: 2px; font-size: 16px; font-weight: 700; color: var(--text); }
.why { margin: 0; color: var(--muted); }
details { margin-top: 12px; font-size: 13px; }
summary {
  width: fit-content;
  color: var(--muted);
  font-size: 12px;
  font-weight: 700;
  cursor: pointer;
}
summary:hover { color: var(--text); }
summary:focus-visible { outline: 2px solid var(--tone); outline-offset: 2px; border-radius: 4px; }
details dl {
  margin-top: 10px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--surface-muted);
}
details dl > div { padding: 10px 12px; }
details dl > div:last-child { border-bottom: 0; }
details dt { margin-bottom: 2px; }
details dd { font-size: 13px; }
details code { padding: 0; border: 0; background: none; font-size: 12px; }
details ul { margin: 0; padding: 0; list-style: none; }
details li + li { margin-top: 2px; }
.sev { margin-left: 6px; color: var(--muted); font-size: 11px; font-weight: 700; letter-spacing: 0.02em; }
.unit { color: var(--muted); }
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


MAX_RULES = 5
_DISTANCE_HINT = "낮을수록 비슷함"


@dataclass(frozen=True)
class _Detail:
    label: str
    html: str  # 이미 이스케이프한 값
    plain: str


@dataclass(frozen=True)
class _Explained:
    threat: str
    sentence: str
    details: tuple[_Detail, ...]


def _one_line(value: str) -> str:
    # text/plain에 서버 값이 줄바꿈·제어 문자로 가짜 줄을 만들지 못하게 한다.
    return "".join(ch if ch.isprintable() else " " for ch in value)


def _rules(evidence: verdict_pb2.VerdictEvidence) -> _Detail:
    shown = list(evidence.rules)[:MAX_RULES]
    rest = len(evidence.rules) - len(shown)
    items = "".join(
        f"<li>{escape(r.name)}" + (f'<span class="sev">{escape(r.severity)}</span>' if r.severity else "") + "</li>"
        for r in shown
    )
    plain = ", ".join(f"{r.name} ({r.severity})" if r.severity else r.name for r in shown)
    if rest > 0:
        items += f'<li class="unit">외 {rest}개</li>'
        plain += f" 외 {rest}개"
    return _Detail("탐지 규칙", f"<ul>{items}</ul>", plain)


def _explain(evidence: verdict_pb2.VerdictEvidence | None) -> _Explained | None:
    """설계 3-3 표. 근거가 없거나 모르는 종류면 None(사유 한 줄 화면)."""
    if evidence is None:
        return None
    kind = evidence.kind
    if kind == verdict_pb2.EVIDENCE_KIND_BLACKLIST:
        return _Explained(
            evidence.family or "알려진 악성 파일",
            "보안 위협 목록에 등록된 파일과 똑같은 파일입니다.",
            (_Detail("등록 사유", escape(evidence.label or "(없음)"), evidence.label or "(없음)"),),
        )
    if kind == verdict_pb2.EVIDENCE_KIND_SIMILARITY:
        known = f"알려진 악성코드({evidence.family})" if evidence.family else "알려진 악성코드"
        details = [
            _Detail(
                "유사도 거리",
                f'{evidence.tlsh_distance} <span class="unit">({_DISTANCE_HINT})</span>',
                f"{evidence.tlsh_distance} ({_DISTANCE_HINT})",
            )
        ]
        if evidence.matched_sample_sha256:
            sha = evidence.matched_sample_sha256
            details.append(_Detail("비교한 샘플 SHA-256", f"<code>{escape(sha)}</code>", sha))
        return _Explained(
            evidence.family or "알려진 악성코드 변종",
            f"{known}와 매우 비슷한 파일입니다. 일부만 바꾼 변종일 수 있습니다.",
            tuple(details),
        )
    if kind == verdict_pb2.EVIDENCE_KIND_YARA:
        first = evidence.rules[0].name if evidence.rules else ""
        return _Explained(
            first or "악성코드 탐지 규칙",
            "악성코드 탐지 규칙에 걸렸습니다.",
            (_rules(evidence),) if evidence.rules else (),
        )
    if kind == verdict_pb2.EVIDENCE_KIND_CACHE:
        previous = evidence.previous_verdict or "(없음)"
        return _Explained(
            "이전 검사 결과",
            "이전에 악성으로 판정된 파일입니다.",
            (_Detail("이전 판정", escape(previous), previous),),
        )
    return None


def plain_lines(evidence: verdict_pb2.VerdictEvidence | None) -> list[str]:
    """text/plain 403에 덧붙일 줄. 위협 이름·설명 한 줄, 숫자 한 줄. 근거가 없으면 빈 목록."""
    explained = _explain(evidence)
    if explained is None:
        return []
    lines = [f"위협: {explained.threat} — {explained.sentence}"]
    if explained.details:
        lines.append("자세히: " + ", ".join(f"{d.label} {d.plain}" for d in explained.details))
    return [_one_line(line) for line in lines]


def _evidence_row(explained: _Explained) -> str:
    details = ""
    if explained.details:
        rows = "".join(f"<div><dt>{escape(d.label)}</dt><dd>{d.html}</dd></div>" for d in explained.details)
        details = f"<details><summary>자세히</summary><dl>{rows}</dl></details>"
    return (
        f'<div><dt>판정 근거</dt><dd><strong class="threat">{escape(explained.threat)}</strong>'
        f'<p class="why">{escape(explained.sentence)}</p>{details}</dd></div>'
    )


def render(*, fail_close: bool, reason: str, event_id: str, evidence: verdict_pb2.VerdictEvidence | None = None) -> str:
    """차단 안내 HTML을 만든다. reason·event_id·근거 값은 여기서 이스케이프한다."""
    copy = _FAIL_CLOSE if fail_close else _BLOCKED
    shown_reason = FAIL_CLOSE_REASON if fail_close else (reason or "(없음)")
    explained = None if fail_close else _explain(evidence)
    if explained is None:
        first_row = f"<div><dt>사유</dt><dd>{escape(shown_reason)}</dd></div>"
    else:
        # 서버 사유(예: "TLSH distance: 12")는 숫자라 본문에 두지 않는다. 같은 정보가 "자세히"에 있다.
        first_row = _evidence_row(explained)
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
{first_row}
<div><dt>이벤트 ID</dt><dd><code>{escape(event_id)}</code></dd></div>
</dl>
<p class="next">{escape(copy["next"])}</p>
</main>
</body>
</html>
"""
