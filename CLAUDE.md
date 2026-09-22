# CLAUDE.md

프록시 기반 악성코드 다운로드 탐지 플랫폼의 로컬 에이전트. 설계 근거는 설계 레포
(2026-Teecher-Team-C/project)에 있다.

## 명령

```bash
./scripts/gen_proto.sh                       # proto submodule → src/teecher (커밋 안 함)
uv run --group dev pytest
uv run --group dev ruff check . && uv run --group dev ruff format --check .
docker compose -f compose.dev.yml up --build # 개발용 프록시 :8080
```

## 되돌리면 안 되는 결정

- **파일 내용을 파싱하지 않는다.** PE 헤더·엔트로피·압축 해제·YARA는 전부 검사 서버 몫이다. 에이전트는
  응답 헤더(`Content-Disposition`, MIME, 크기, `Sec-Fetch-Mode`)만 보고, 본문은 해시하고 스풀할 뿐이다
- **fail-close 고정.** 검사 서버에 닿지 못하면 차단한다. fail-open, 재시도·서킷 브레이커·로컬 캐시 폴백을
  만들지 않는다
- **영속 저장소를 두지 않는다.** 판정 캐시(SQLite)도 스풀 상태 DB도 없다. 스풀 상태는 메모리에만
- **스풀 파일은 무해해야 한다**: `UUID.tmp` 이름, `0600`·실행 비트 없음, XOR 인코딩, 인덱싱 제외.
  원본 파일명을 디스크 경로에 쓰지 않는다. 이 규칙은 `src/agent/platform/`에만 구현한다
- **응답 보류는 헤더가 브라우저로 나가기 전에.** 헤더가 나가면 차단 응답을 만들 수 없다
- 사용자 신원·MAC 주소를 수집하지 않는다
- 비대응 범위(QUIC, 피닝 앱, 시스템 프록시를 안 보는 프로그램, Range 분할 다운로드)는 "고치지" 않는다

## 구조

- `src/agent/platform/` — OS 의존 코드 전부. 다른 모듈은 `sys.platform`을 보지 않는다
- `proto/` — platform-server submodule. 직접 수정하지 않는다. 계약을 바꾸려면 서버 레포에 PR
