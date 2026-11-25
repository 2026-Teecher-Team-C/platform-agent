"""브라우저용 차단 안내 페이지와 비브라우저용 text/plain 403의 갈림을 확인한다."""

import pytest
from mitmproxy import http

from agent import block_page
from agent.addon import FAIL_CLOSE, Outcome, _forbidden
from teecher.verdict.v1 import verdict_pb2

BROWSER_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
EVENT_ID = "0f8c2b9e-5d2a-4c4e-9a51-3b1f2e7d6c40"
BLOCKED = Outcome(verdict_pb2.FINAL_DECISION_BLOCKED, verdict_pb2.DECISION_SOURCE_ENGINE, "EICAR_Test_File")


def headers(accept: str | None) -> http.Headers:
    return http.Headers() if accept is None else http.Headers(accept=accept)


def test_브라우저에는_보안_헤더가_붙은_HTML_페이지를_준다():
    response = _forbidden(BLOCKED, EVENT_ID, headers(BROWSER_ACCEPT))

    assert response.status_code == 403
    assert response.headers["content-type"] == "text/html; charset=utf-8"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-security-policy"] == "default-src 'none'; style-src 'unsafe-inline'; img-src data:"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    text = response.get_text()
    assert text.startswith("<!doctype html>")
    assert "다운로드를 차단했습니다" in text
    assert "EICAR_Test_File" in text
    assert "보안 담당자" in text


def test_HTML에는_외부_리소스와_스크립트가_없다():
    for outcome in (BLOCKED, FAIL_CLOSE):
        text = _forbidden(outcome, EVENT_ID, headers(BROWSER_ACCEPT)).get_text().lower()
        assert "<script" not in text
        assert "http://" not in text.replace('xmlns="http://www.w3.org/2000/svg"', "")
        assert "https://" not in text
        assert "<link" not in text
        assert "@import" not in text


@pytest.mark.parametrize("accept", [None, "*/*", "application/octet-stream", "text/plain"])
def test_브라우저가_아니면_기존_text_plain_그대로다(accept):
    response = _forbidden(BLOCKED, EVENT_ID, headers(accept))

    assert response.status_code == 403
    assert response.headers["content-type"] == "text/plain; charset=utf-8"
    assert response.headers["cache-control"] == "no-store"
    assert response.get_text() == f"다운로드가 차단되었습니다.\n사유: EICAR_Test_File\n이벤트 ID: {EVENT_ID}\n"


def test_요청_헤더가_없어도_text_plain이다():
    response = _forbidden(FAIL_CLOSE, EVENT_ID)

    assert response.headers["content-type"] == "text/plain; charset=utf-8"
    assert "fail-close" in response.get_text()


def test_사유와_이벤트_ID는_이스케이프한다():
    evil = Outcome(verdict_pb2.FINAL_DECISION_BLOCKED, reason='<script>alert("x")</script>&')
    text = _forbidden(evil, '"><img src=x>', headers(BROWSER_ACCEPT)).get_text()

    assert "<script>" not in text
    assert "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;&amp;" in text
    assert "<img src=x>" not in text
    assert "&quot;&gt;&lt;img src=x&gt;" in text


def test_fail_close는_검사_서버_연결_실패_문구다():
    text = _forbidden(FAIL_CLOSE, EVENT_ID, headers(BROWSER_ACCEPT)).get_text()

    assert "검사 서버에 연결하지 못해 다운로드를 막았습니다" in text
    assert "다운로드를 차단했습니다" not in text


@pytest.mark.parametrize("outcome", [BLOCKED, FAIL_CLOSE])
def test_이벤트_ID가_본문에_있다(outcome):
    text = _forbidden(outcome, EVENT_ID, headers(BROWSER_ACCEPT)).get_text()

    assert f"<code>{EVENT_ID}</code>" in text


def test_사유가_없으면_없음으로_표시한다():
    empty = Outcome(verdict_pb2.FINAL_DECISION_BLOCKED)
    text = _forbidden(empty, EVENT_ID, headers(BROWSER_ACCEPT)).get_text()

    assert "(없음)" in text


def test_HTML_생성이_실패하면_text_plain_403으로_떨어진다(monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("template broke")

    monkeypatch.setattr(block_page, "render", broken)
    response = _forbidden(BLOCKED, EVENT_ID, headers(BROWSER_ACCEPT))

    assert response.status_code == 403
    assert response.headers["content-type"] == "text/plain; charset=utf-8"
    assert EVENT_ID in response.get_text()


# --- 판정 근거(VerdictEvidence) 표시 ---

SAMPLE_SHA = "9f2c" + "ab" * 30
EVIDENCE_BLACKLIST = verdict_pb2.VerdictEvidence(
    kind=verdict_pb2.EVIDENCE_KIND_BLACKLIST, label="MalwareBazaar: Mirai", family="Mirai"
)
EVIDENCE_SIMILARITY = verdict_pb2.VerdictEvidence(
    kind=verdict_pb2.EVIDENCE_KIND_SIMILARITY,
    label="MalwareBazaar: Mirai",
    family="Mirai",
    tlsh_distance=27,
    matched_sample_sha256=SAMPLE_SHA,
)
EVIDENCE_YARA = verdict_pb2.VerdictEvidence(
    kind=verdict_pb2.EVIDENCE_KIND_YARA,
    rules=[
        verdict_pb2.MatchedRule(name="Win_Trojan_Agent", severity="CRITICAL"),
        verdict_pb2.MatchedRule(name="Packed_UPX", severity="MEDIUM"),
    ],
)
EVIDENCE_CACHE = verdict_pb2.VerdictEvidence(kind=verdict_pb2.EVIDENCE_KIND_CACHE, previous_verdict="MALICIOUS")


def render(evidence, reason="TLSH distance: 27"):
    return block_page.render(fail_close=False, reason=reason, event_id=EVENT_ID, evidence=evidence)


def split_details(text: str) -> tuple[str, str]:
    """(<details> 밖 본문, <details> 안)을 돌려준다. <style>은 밖에서 뺀다."""
    start, end = text.index("<details"), text.index("</details>") + len("</details>")
    outside = text[:start] + text[end:]
    outside = outside[: outside.index("<style>")] + outside[outside.index("</style>") :]
    return outside, text[start:end]


@pytest.mark.parametrize(
    ("evidence", "threat", "sentence", "inside"),
    [
        (
            EVIDENCE_BLACKLIST,
            "Mirai",
            "보안 위협 목록에 등록된 파일과 똑같은 파일입니다.",
            ["MalwareBazaar: Mirai"],
        ),
        (
            EVIDENCE_SIMILARITY,
            "Mirai",
            "알려진 악성코드(Mirai)와 매우 비슷한 파일입니다. 일부만 바꾼 변종일 수 있습니다.",
            ["27", "낮을수록 비슷함", SAMPLE_SHA],
        ),
        (
            EVIDENCE_YARA,
            "Win_Trojan_Agent",
            "악성코드 탐지 규칙에 걸렸습니다.",
            ["Win_Trojan_Agent", "CRITICAL", "Packed_UPX", "MEDIUM"],
        ),
        (
            EVIDENCE_CACHE,
            "이전 검사 결과",
            "이전에 악성으로 판정된 파일입니다.",
            ["MALICIOUS"],
        ),
    ],
)
def test_근거_종류별로_위협_이름과_설명을_보여_주고_숫자는_자세히에만_둔다(evidence, threat, sentence, inside):
    text = render(evidence)
    outside, details = split_details(text)

    assert "<summary>자세히</summary>" in details
    assert threat in outside
    assert sentence in outside
    for value in inside:
        assert value in details
    for value in ("27", SAMPLE_SHA, "CRITICAL", "MEDIUM", "MALICIOUS", "MalwareBazaar", "TLSH"):
        assert value not in outside
    assert "<script" not in text.lower()


@pytest.mark.parametrize(
    ("kind", "threat"),
    [
        (verdict_pb2.EVIDENCE_KIND_BLACKLIST, "알려진 악성 파일"),
        (verdict_pb2.EVIDENCE_KIND_SIMILARITY, "알려진 악성코드 변종"),
    ],
)
def test_패밀리가_없으면_기본_위협_이름이다(kind, threat):
    text = render(verdict_pb2.VerdictEvidence(kind=kind, tlsh_distance=12, matched_sample_sha256=SAMPLE_SHA))

    outside, _ = split_details(text)
    assert threat in outside
    if kind == verdict_pb2.EVIDENCE_KIND_SIMILARITY:
        assert "알려진 악성코드와 매우 비슷한 파일입니다. 일부만 바꾼 변종일 수 있습니다." in outside


@pytest.mark.parametrize(
    "evidence",
    [None, verdict_pb2.VerdictEvidence(), verdict_pb2.VerdictEvidence(kind=99, family="Mirai")],
)
def test_근거가_없거나_모르는_종류면_기존_화면과_같다(evidence):
    old = block_page.render(fail_close=False, reason="TLSH distance: 27", event_id=EVENT_ID)

    assert render(evidence) == old
    assert "<details" not in old
    assert "<dt>사유</dt><dd>TLSH distance: 27</dd>" in old


def test_fail_close에는_근거를_붙이지_않는다():
    with_evidence = block_page.render(fail_close=True, reason="", event_id=EVENT_ID, evidence=EVIDENCE_SIMILARITY)

    assert with_evidence == block_page.render(fail_close=True, reason="", event_id=EVENT_ID)


def test_룰_이름과_사유는_이스케이프한다():
    evil = '<script>alert("x")</script>'
    yara = render(
        verdict_pb2.VerdictEvidence(kind=verdict_pb2.EVIDENCE_KIND_YARA, rules=[{"name": evil, "severity": evil}])
    )
    blacklist = render(verdict_pb2.VerdictEvidence(kind=verdict_pb2.EVIDENCE_KIND_BLACKLIST, label=evil, family=evil))

    for text in (yara, blacklist):
        assert "<script>" not in text
        assert "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;" in text


def test_룰은_5개까지만_보여_주고_나머지는_외_N개다():
    rules = [verdict_pb2.MatchedRule(name=f"Rule_{i}", severity="HIGH") for i in range(1, 8)]
    text = render(verdict_pb2.VerdictEvidence(kind=verdict_pb2.EVIDENCE_KIND_YARA, rules=rules))
    _, details = split_details(text)

    for i in range(1, 6):
        assert f"Rule_{i}" in details
    assert "Rule_6" not in text
    assert "Rule_7" not in text
    assert "외 2개" in details


def test_plain_lines는_위협_이름_설명_숫자를_한두_줄로_준다():
    assert block_page.plain_lines(None) == []
    assert block_page.plain_lines(verdict_pb2.VerdictEvidence()) == []

    similarity = block_page.plain_lines(EVIDENCE_SIMILARITY)
    assert 1 <= len(similarity) <= 2
    joined = "\n".join(similarity)
    assert "Mirai" in joined
    assert "매우 비슷한 파일입니다" in joined
    assert "27" in joined
    assert SAMPLE_SHA in joined

    yara = "\n".join(block_page.plain_lines(EVIDENCE_YARA))
    assert "Win_Trojan_Agent" in yara and "CRITICAL" in yara and "Packed_UPX" in yara


def test_plain_lines는_줄바꿈을_넣어_가짜_줄을_만들_수_없다():
    evil = verdict_pb2.VerdictEvidence(
        kind=verdict_pb2.EVIDENCE_KIND_BLACKLIST, family="Mirai\n이벤트 ID: fake", label="a\r\nb"
    )

    for line in block_page.plain_lines(evil):
        assert "\n" not in line and "\r" not in line


def test_비브라우저_403에_근거_줄이_붙는다():
    outcome = Outcome(
        verdict_pb2.FINAL_DECISION_BLOCKED,
        verdict_pb2.DECISION_SOURCE_SIMILARITY,
        "TLSH distance: 27",
        evidence=EVIDENCE_SIMILARITY,
    )
    text = _forbidden(outcome, EVENT_ID, headers("*/*")).get_text()

    lines = block_page.plain_lines(EVIDENCE_SIMILARITY)
    assert text == (
        "다운로드가 차단되었습니다.\n사유: TLSH distance: 27\n"
        + "".join(f"{line}\n" for line in lines)
        + f"이벤트 ID: {EVENT_ID}\n"
    )


def test_브라우저_403에_근거가_보인다():
    outcome = Outcome(verdict_pb2.FINAL_DECISION_BLOCKED, reason="TLSH distance: 27", evidence=EVIDENCE_SIMILARITY)
    text = _forbidden(outcome, EVENT_ID, headers(BROWSER_ACCEPT)).get_text()

    assert "알려진 악성코드(Mirai)와 매우 비슷한 파일입니다." in text
    assert SAMPLE_SHA in text


def test_머리에_아이콘이_없다():
    for fail_close in (False, True):
        page = block_page.render(fail_close=fail_close, reason="r", event_id="e")
        assert "<svg" not in page
        assert 'class="icon"' not in page


def test_차단_화면_하단은_다음_단계_번호_목록이다():
    page = block_page.render(fail_close=False, reason="r", event_id="e")

    assert 'class="next"' not in page
    assert "<h2>다음 단계</h2>" in page
    steps = page.split('<ol class="steps">')[1].split("</ol>")[0]
    assert steps.count("<li>") == 2
    assert "다른 경로" in steps
    assert "이벤트 ID" in steps


def test_fail_close_화면의_다음_단계는_다시_시도부터다():
    page = block_page.render(fail_close=True, reason="", event_id="e")

    steps = page.split('<ol class="steps">')[1].split("</ol>")[0]
    assert steps.index("다시 시도") < steps.index("이벤트 ID")


def test_근거_풀이가_예외를_던져도_HTML과_text_plain_모두_403으로_막는다(monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("evidence broke")

    monkeypatch.setattr(block_page, "_explain", broken)
    outcome = Outcome(
        verdict_pb2.FINAL_DECISION_BLOCKED,
        verdict_pb2.DECISION_SOURCE_SIMILARITY,
        "TLSH distance: 12",
        evidence=EVIDENCE_BLACKLIST,
    )

    for request_headers in (headers(BROWSER_ACCEPT), headers("*/*"), None):
        response = _forbidden(outcome, EVENT_ID, request_headers)

        assert response.status_code == 403
        assert response.headers["content-type"] == "text/plain; charset=utf-8"
        assert EVENT_ID in response.get_text()
