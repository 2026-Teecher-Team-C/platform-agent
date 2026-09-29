import pytest
from mitmproxy.http import Headers as MitmHeaders

from agent.detection import DownloadCheck, filename_of, is_download

KB = 1024
MB = 1024 * KB


@pytest.mark.parametrize(
    ("request_headers", "response_headers", "expected"),
    [
        # navigate — Content-Disposition 신뢰, 전 규칙 적용
        pytest.param(
            {"Sec-Fetch-Mode": "navigate"},
            {"Content-Disposition": "attachment; filename=a.exe"},
            DownloadCheck(True, "navigate", "content_disposition"),
            id="navigate+CD_attachment",
        ),
        # cors — 다운로드 MIME만 인정
        pytest.param(
            {"Sec-Fetch-Mode": "cors"},
            {"Content-Type": "application/zip"},
            DownloadCheck(True, "cors", "mime"),
            id="cors+zip",
        ),
        pytest.param(
            {"Sec-Fetch-Mode": "cors"},
            {"Content-Disposition": "attachment", "Content-Type": "text/html"},
            DownloadCheck(False, "cors", ""),
            id="cors+CD_attachment+html_아님",
        ),
        # no-cors — Google anti-XSSI 오탐 방지: CD 단독 신호 불신
        pytest.param(
            {"Sec-Fetch-Mode": "no-cors"},
            {"Content-Disposition": "attachment", "Content-Type": "application/json"},
            DownloadCheck(False, "no-cors", ""),
            id="no-cors+CD_attachment+json_아님",
        ),
        # Sec-Fetch 헤더 자체가 없음 (curl 등) — 폴백, CD 신뢰
        pytest.param(
            {},
            {"Content-Disposition": "attachment; filename=a.txt"},
            DownloadCheck(True, "fallback", "content_disposition"),
            id="no_sec-fetch+CD_attachment",
        ),
        pytest.param(
            {},
            {"Content-Type": "application/octet-stream"},
            DownloadCheck(True, "fallback", "mime"),
            id="no_sec-fetch+octet-stream",
        ),
        # 크기 폴백 제외 MIME — Content-Length가 커도 다운로드 아님
        pytest.param(
            {"Sec-Fetch-Mode": "navigate"},
            {"Content-Type": "text/html", "Content-Length": str(MB)},
            DownloadCheck(False, "navigate", ""),
            id="navigate+html_1MB_제외MIME",
        ),
        pytest.param(
            {"Sec-Fetch-Mode": "navigate"},
            {"Content-Type": "image/png", "Content-Length": str(MB)},
            DownloadCheck(False, "navigate", ""),
            id="navigate+png_1MB_제외MIME",
        ),
        # 크기 폴백(규칙 3) — Content-Length 있고 임계값 이상, 제외 MIME 아님
        pytest.param(
            {"Sec-Fetch-Mode": "navigate"},
            {"Content-Type": "application/x-foo", "Content-Length": str(100 * KB)},
            DownloadCheck(True, "navigate", "size_fallback"),
            id="navigate+unknown_mime+100KB_크기폴백",
        ),
        # chunked(Content-Length 없음) — 크기 폴백 적용 불가, 신호 없으면 다운로드 아님
        pytest.param(
            {"Sec-Fetch-Mode": "navigate"},
            {"Content-Type": "application/x-foo"},
            DownloadCheck(False, "navigate", ""),
            id="navigate+unknown_mime+chunked_아님",
        ),
        # Content-Length 파싱 불가 — 있는 것으로 치지 않는다
        pytest.param(
            {"Sec-Fetch-Mode": "navigate"},
            {"Content-Type": "application/x-foo", "Content-Length": "abc"},
            DownloadCheck(False, "navigate", ""),
            id="navigate+unknown_mime+잘못된_content-length",
        ),
        # MIME 파라미터·대소문자 처리
        pytest.param(
            {"Sec-Fetch-Mode": "cors"},
            {"Content-Type": "Application/ZIP; charset=x"},
            DownloadCheck(True, "cors", "mime"),
            id="MIME_파라미터와_대소문자",
        ),
        # 헤더 이름 대소문자 무관 — 첫 케이스와 동일 결과여야 함
        pytest.param(
            {"sec-fetch-mode": "navigate"},
            {"content-disposition": "attachment; filename=a.exe"},
            DownloadCheck(True, "navigate", "content_disposition"),
            id="헤더_이름_소문자",
        ),
        pytest.param(
            {"SEC-FETCH-MODE": "navigate"},
            {"CONTENT-DISPOSITION": "attachment; filename=a.exe"},
            DownloadCheck(True, "navigate", "content_disposition"),
            id="헤더_이름_대문자",
        ),
        # Sec-Fetch-Mode가 navigate/cors 외 값 — no-cors와 동일하게 서브리소스 취급
        pytest.param(
            {"Sec-Fetch-Mode": "same-origin"},
            {"Content-Disposition": "attachment", "Content-Type": "application/octet-stream"},
            DownloadCheck(True, "same-origin", "mime"),
            id="same-origin+CD는_불신하지만_mime은_신뢰",
        ),
    ],
)
def test_다운로드_판별(request_headers, response_headers, expected):
    assert is_download(request_headers, response_headers) == expected


@pytest.mark.parametrize(
    ("request_url", "response_headers", "expected"),
    [
        pytest.param(
            "https://example.com/download",
            {"Content-Disposition": 'attachment; filename="report.pdf"'},
            "report.pdf",
            id="CD_따옴표",
        ),
        pytest.param(
            "https://example.com/download",
            {"Content-Disposition": "attachment; filename=report.pdf"},
            "report.pdf",
            id="CD_따옴표없음",
        ),
        pytest.param(
            "https://example.com/path/to/file.exe?x=1",
            {},
            "file.exe",
            id="URL_폴백",
        ),
        pytest.param(
            "https://example.com/",
            {},
            "(no name)",
            id="빈_이름",
        ),
        pytest.param(
            "https://example.com/download",
            {"Content-Disposition": 'attachment; filename="../../evil.exe"'},
            "....evil.exe",
            id="경로_탈출_슬래시",
        ),
        pytest.param(
            "https://example.com/download",
            {"Content-Disposition": 'attachment; filename="..\\evil.exe"'},
            "..evil.exe",
            id="경로_탈출_역슬래시",
        ),
        pytest.param(
            "https://example.com/download",
            {"Content-Disposition": "attachment; filename*=UTF-8''%ED%95%9C%EA%B8%80.txt"},
            "한글.txt",
            id="filename_star_UTF-8",
        ),
    ],
)
def test_파일명_추출(request_url, response_headers, expected):
    assert filename_of(request_url, response_headers) == expected


def test_파일명은_경로_구분자를_포함하지_않는다():
    name = filename_of(
        "https://example.com/download",
        {"Content-Disposition": 'attachment; filename="../../etc/evil.exe"'},
    )
    assert "/" not in name
    assert "\\" not in name


# 조작된 filename* charset — 실제로 존재하는 codec 이름이지만 임의 percent-decode 바이트에
# 적용하면 예외를 던지는 것들(idna→UnicodeError, undefined→LookupError,
# punycode→UnicodeDecodeError). 허용 목록(utf-8/iso-8859-1) 밖이면 charset을 무시하고
# 순수 percent-decode로 대체해야 하며, filename_of는 어떤 경우에도 예외를 던지면 안 된다.
@pytest.mark.parametrize(
    "content_disposition",
    [
        pytest.param("attachment; filename*=idna''%E9", id="idna_charset"),
        pytest.param("attachment; filename*=undefined''x", id="undefined_charset"),
        pytest.param("attachment; filename*=punycode''%E9", id="punycode_charset"),
    ],
)
def test_조작된_filename_star_charset은_예외를_던지지_않는다(content_disposition):
    name = filename_of("https://example.com/download", {"Content-Disposition": content_disposition})
    assert isinstance(name, str)
    assert name  # 최소한 빈 문자열은 아니어야 한다 ("(no name)" 포함 허용)


@pytest.mark.parametrize(
    ("content_disposition", "expected"),
    [
        # 파라미터 이름 접두어 겹침 — "myfilename"이 "filename"으로 오인되면 안 된다
        pytest.param(
            "attachment; myfilename=x; filename=real.exe",
            "real.exe",
            id="파라미터_이름_접두어_겹침",
        ),
        # 따옴표 안의 "filename="이 실제 filename 파라미터로 오인되면 안 된다
        pytest.param(
            'attachment; name="filename=evil.exe"',
            None,
            id="따옴표_안의_filename_문자열",
        ),
        # 따옴표 안의 세미콜론은 파라미터 경계가 아니다
        pytest.param(
            'attachment; filename="a;b.exe"',
            "a;b.exe",
            id="따옴표_안의_세미콜론",
        ),
        # 이스케이프된 따옴표 — quoted-pair 처리
        pytest.param(
            'attachment; filename="a\\"b.exe"',
            'a"b.exe',
            id="이스케이프된_따옴표",
        ),
    ],
)
def test_Content_Disposition_파라미터_파싱(content_disposition, expected):
    name = filename_of("https://example.com/download", {"Content-Disposition": content_disposition})
    if expected is None:
        # filename 파라미터가 없으므로 URL 폴백 — 원래 문자열이 그대로 나오면 안 된다
        assert name == "download"
    else:
        assert name == expected


def test_filename_star가_filename보다_우선한다():
    cd = "attachment; filename=fallback.txt; filename*=UTF-8''real.exe"
    assert filename_of("https://example.com/download", {"Content-Disposition": cd}) == "real.exe"


def test_유니코드_서식_문자는_제거된다():
    # RLO(U+202E)로 확장자를 반대로 보이게 하는 스푸핑 — "invoice<RLO>gpj.exe"는
    # 렌더링 시 "invoiceexe.jpg"처럼 보인다. 서식 문자를 제거하면 실제 순서(.exe로 끝남)가 보존된다.
    spoofed = "invoice‮gpj.exe"
    name = filename_of(
        "https://example.com/download",
        {"Content-Disposition": f'attachment; filename="{spoofed}"'},
    )
    assert "‮" not in name
    assert name == "invoicegpj.exe"
    assert name.endswith(".exe")


def test_실제_mitmproxy_Headers_중복_헤더는_콤마로_합쳐진다():
    # mitmproxy Headers는 중복 헤더를 ", "로 합쳐서 노출한다(RFC 7230 §3.2.2). 합쳐진 문자열
    # 안에도 "attachment"와 filename 파라미터가 정상적으로 인식되어야 한다.
    request_headers = MitmHeaders([(b"Sec-Fetch-Mode", b"navigate")])
    response_headers = MitmHeaders(
        [
            (b"Content-Disposition", b"inline"),
            (b"Content-Disposition", b"attachment; filename=dup.exe"),
        ]
    )

    result = is_download(request_headers, response_headers)
    assert result.is_download is True
    assert result.fired_rule == "content_disposition"
    assert filename_of("https://example.com/x", response_headers) == "dup.exe"
