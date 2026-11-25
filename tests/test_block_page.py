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
