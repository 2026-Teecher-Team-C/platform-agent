"""다운로드 판별 — `responseheaders` 시점(본문 수신 전)에 내리는 최종 결정.

헤더가 브라우저로 나가면 그 뒤에는 보류·차단이 불가능하므로(제품 설계 6장), 여기서 내리는
판정을 나중에 "역시 다운로드였다"며 승격할 수 없다. 입력은 요청의 `Sec-Fetch-*`와 응답의
`Content-Disposition`/`Content-Type`/`Content-Length`뿐이며 본문은 보지 않는다.
"""

import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import unquote, urlparse

# 다운로드로 볼 MIME (제품 설계 3장 "다운로드 판별")
DOWNLOAD_MIMES = (
    "application/octet-stream",
    "application/zip",
    "application/x-msdownload",
    "application/x-apple-diskimage",
    "application/vnd.microsoft.portable-executable",
)
MIN_DOWNLOAD_BYTES = 64 * 1024

# 크기 폴백(규칙 3) 제외 MIME — 브라우저가 자체 렌더링/해석하는 것들
_SIZE_FALLBACK_EXCLUDED_MIMES = {
    "text/html",
    "text/css",
    "text/javascript",
    "application/javascript",
    "application/json",
    "text/plain",
}
_SIZE_FALLBACK_EXCLUDED_PREFIXES = ("image/", "video/", "font/")

_CONTROL_CHARS = "".join(chr(c) for c in range(0x20)) + chr(0x7F)
_FILENAME_STRIP_CHARS = "/\\" + _CONTROL_CHARS

# RFC 5987 ext-value(filename*)에서 실제로 디코드해 줄 charset. 그 외(idna, punycode,
# undefined 등 공격자가 넣을 수 있는 임의 값)는 charset을 무시하고 순수 percent-decode로 대체한다
# — 일부 codec은 잘못된 입력에서 LookupError가 아닌 UnicodeError를 던지므로 화이트리스트가 필요하다
_RFC5987_CHARSETS = {"utf-8", "iso-8859-1"}


@dataclass(frozen=True)
class DownloadCheck:
    is_download: bool
    context: str  # "navigate" / "cors" / "no-cors" / 그 외 실측값 / "fallback"
    fired_rule: str  # "content_disposition" / "mime" / "size_fallback" / ""


def _lower_keys(headers: Mapping[str, str]) -> dict[str, str]:
    # mitmproxy의 Headers는 이미 대소문자 무관이지만, 테스트의 평범한 dict는 아니므로 정규화한다.
    return {k.lower(): v for k, v in headers.items()}


def _size_fallback_excluded(mime: str) -> bool:
    if mime in _SIZE_FALLBACK_EXCLUDED_MIMES:
        return True
    return any(mime.startswith(p) for p in _SIZE_FALLBACK_EXCLUDED_PREFIXES)


def is_download(request_headers: Mapping[str, str], response_headers: Mapping[str, str]) -> DownloadCheck:
    req = _lower_keys(request_headers)
    res = _lower_keys(response_headers)

    sec_fetch_mode = req.get("sec-fetch-mode")
    has_sec_fetch = "sec-fetch-mode" in req

    is_attachment = "attachment" in res.get("content-disposition", "").lower()
    mime = res.get("content-type", "").split(";")[0].strip().lower()
    is_download_mime = mime in DOWNLOAD_MIMES

    cl_present = "content-length" in res
    try:
        cl_value = int(res.get("content-length", "0")) if cl_present else 0
    except ValueError:
        cl_present, cl_value = False, 0

    size_hit = cl_present and not _size_fallback_excluded(mime) and cl_value >= MIN_DOWNLOAD_BYTES

    if has_sec_fetch and sec_fetch_mode == "navigate":
        # 다운로드 후보(링크 클릭, <a download>, CD-only 파일). 전 규칙 적용
        context = "navigate"
        cd_trusted = True
        cors_only_mime = False
    elif has_sec_fetch and sec_fetch_mode == "cors":
        # XHR/fetch — 다운로드 MIME일 때만 인정(CD·크기 신호 배제)
        context = "cors"
        cd_trusted = False
        cors_only_mime = True
    elif has_sec_fetch:
        # no-cors 및 그 외(same-origin 등) — 서브리소스 취급. Content-Disposition 단독 신호는
        # 신뢰하지 않는다(Google anti-XSSI 오탐이 여기 해당)
        context = sec_fetch_mode
        cd_trusted = False
        cors_only_mime = False
    else:
        # Sec-Fetch 헤더 없음 — 비브라우저 클라이언트/평문 HTTP 오리진. 기존 규칙으로 폴백
        context = "fallback"
        cd_trusted = True
        cors_only_mime = False

    if cors_only_mime:
        return DownloadCheck(is_download_mime, context, "mime" if is_download_mime else "")

    cd_signal = is_attachment and cd_trusted
    if cd_signal:
        fired_rule = "content_disposition"
    elif is_download_mime:
        fired_rule = "mime"
    elif size_hit:
        fired_rule = "size_fallback"
    else:
        fired_rule = ""

    return DownloadCheck(bool(fired_rule), context, fired_rule)


def _split_disposition_segments(header_value: str) -> list[str]:
    """세미콜론으로 파라미터를 나누되, 따옴표 안의 세미콜론(`filename="a;b.exe"`)은 보존한다."""
    segments: list[str] = []
    buf: list[str] = []
    in_quotes = False
    escape = False
    for ch in header_value:
        if escape:
            buf.append(ch)
            escape = False
        elif ch == "\\" and in_quotes:
            buf.append(ch)
            escape = True
        elif ch == '"':
            in_quotes = not in_quotes
            buf.append(ch)
        elif ch == ";" and not in_quotes:
            segments.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    segments.append("".join(buf))
    return segments


def _unescape_quoted(value: str) -> str:
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return re.sub(r"\\(.)", r"\1", value[1:-1])
    return value


def _parse_disposition_params(header_value: str) -> dict[str, str]:
    """Content-Disposition 파라미터를 이름 기준으로 파싱한다(따옴표·이스케이프 인식).

    첫 세그먼트(disposition-type)는 건너뛴다. `myfilename=` 같은 접두어 겹침이나
    `name="filename=evil.exe"` 같은 따옴표 안의 문자열이 `filename`으로 오인되지 않도록
    파라미터 이름을 `=` 앞부분과 정확히 비교한다. 중복 파라미터는 먼저 나온 값을 쓴다.
    """
    params: dict[str, str] = {}
    for segment in _split_disposition_segments(header_value)[1:]:
        if "=" not in segment:
            continue
        name, _, value = segment.partition("=")
        name = name.strip().lower()
        if name and name not in params:
            params[name] = _unescape_quoted(value.strip())
    return params


def _decode_ext_value(raw: str) -> str:
    """RFC 5987 ext-value(`charset'lang'value`)를 디코드한다.

    charset이 허용 목록(_RFC5987_CHARSETS) 밖이면 — idna/punycode/undefined처럼 존재는
    하지만 임의 바이트에 적용하면 LookupError가 아닌 UnicodeError를 던지는 codec도 있으므로 —
    charset을 무시하고 순수 percent-decode(errors="replace")로 대체해 절대 예외를 던지지 않는다.
    """
    raw = _unescape_quoted(raw.strip())
    parts = raw.split("'", 2)
    if len(parts) == 3:
        charset, _lang, value = parts
        if charset.lower() in _RFC5987_CHARSETS:
            try:
                return unquote(value, encoding=charset.lower())
            except (LookupError, UnicodeError):
                pass
        return unquote(value)
    return unquote(raw)


def _filename_from_disposition(content_disposition: str) -> str | None:
    params = _parse_disposition_params(content_disposition)
    if "filename*" in params:
        return _decode_ext_value(params["filename*"])
    if "filename" in params:
        return params["filename"]
    return None


def _sanitize_filename(name: str) -> str:
    # 경로 구분자·제어 문자와 유니코드 서식 문자(예: U+202E RLO)를 제거한다. RLO 등은 확장자를
    # 반대로 보이게 해 "invoice<RLO>gpj.exe"를 "invoiceexe.jpg"처럼 위장하는 데 쓰인다.
    stripped = name.translate(str.maketrans("", "", _FILENAME_STRIP_CHARS))
    return "".join(ch for ch in stripped if unicodedata.category(ch) != "Cf")


def filename_of(request_url: str, response_headers: Mapping[str, str]) -> str:
    """다운로드 파일명을 뽑는다. 공격자가 직접 채우는 값이므로 디스크 경로에는 절대 쓰지 않는다.

    표시/전송 전용 값이라 헤더가 아무리 기형이어도 예외를 던져 판별 파이프라인을 막으면 안
    된다 — 개별 단계에서 방어했더라도 마지막 안전장치로 전체를 감싼다.
    """
    try:
        res = _lower_keys(response_headers)
        name = _filename_from_disposition(res.get("content-disposition", ""))
        if name is None:
            name = urlparse(request_url).path.rsplit("/", 1)[-1]
        return _sanitize_filename(name) or "(no name)"
    except Exception:
        return "(no name)"
