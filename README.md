# platform-agent

사용자 PC에서 도는 **로컬 에이전트(프록시)**. 다운로드 응답을 브라우저에 넘기기 전에 붙잡고, 검사 서버의
판정을 받아 통과시키거나 403으로 막는다.

| 레포 | 내용 |
|---|---|
| **platform-agent** (여기) | 로컬 에이전트 (Python 3.12 · mitmproxy) |
| [platform-server](https://github.com/2026-Teecher-Team-C/platform-server) | 검사 서버 · 콘솔 · 인프라 · gRPC 계약 원본 |
| [project](https://github.com/2026-Teecher-Team-C/project) | 설계 문서 |

## 시작

```bash
git clone --recurse-submodules https://github.com/2026-Teecher-Team-C/platform-agent.git
# 이미 clone 했다면: git submodule update --init
```

`proto/`는 platform-server 레포를 `proto-v*` 태그로 고정한 submodule이다. 계약 파일은 `proto/proto/teecher/verdict/v1/`.

## 개발

**Docker** — 판별·보류·서버 통신 같은 파이프라인 로직

```bash
docker compose -f compose.dev.yml up --build     # 프록시 localhost:8080
```

서버 스택은 platform-server에서 `make dev`로 띄운다. 에이전트 컨테이너는 `host.docker.internal:80`(nginx)으로 붙는다.

**호스트(uv)** — OS에 붙는 부분. 스풀 보호 규칙, 시스템 프록시, CA 신뢰 등록은 컨테이너로 검증되지 않는다

```bash
./scripts/gen_proto.sh
uv run --group dev pytest
```

OS에 의존하는 코드는 `src/agent/platform/`(linux / macos / windows)에만 둔다. CI는 세 OS에서 모두 테스트한다.

## 환경변수

| 환경변수 | 기본값 | 설명 |
|---|---|---|
| `VERDICT_SERVER_ADDRESS` | `localhost:9090` | 검사 서버 gRPC 주소 (VerdictService·AgentService 공용) |
| `VERDICT_SERVER_TLS` | `false` | gRPC TLS |
| `ENROLLMENT_TOKEN` | (없음) | 1회용 등록 토큰. 키체인에 자격 증명이 없거나, 저장된 토큰이 거부·만료됐을 때 쓴다 |
| `AGENT_TOKEN` | (없음) | 개발용 수동 주입. 있으면 등록·토큰 갱신을 건너뛴다 |
| `CREDENTIAL_STORE` | `keyring` | `keyring`(OS 키체인) 또는 `memory`(키체인 없는 개발 환경) |
| `HEARTBEAT_INTERVAL_SECONDS` | `60` | 하트비트·토큰 갱신 확인 주기 |
| `POLICY_REFRESH_SECONDS` | `300` | 정책 재수신 주기 |
| `HOLD_TIMEOUT_SECONDS` | `120` | 보류 최대 시간 |
| `RPC_TIMEOUT_SECONDS` | `10` | 단건 RPC 타임아웃 |
| `BODY_SIZE_LIMIT` | `500m` | 검사 대상 본문 상한 (초과는 차단) |

## 배포

설치 파일은 `build` 워크플로가 만든다. 수동 실행(`workflow_dispatch`, 워크플로가 기본 브랜치에 있어야 한다)과 `v*` 태그에서 돌고,
`packaging/`·`src/`·`pyproject.toml`·`uv.lock`·`build.yml`을 바꾸는 PR에서도 돈다.

| OS | 파일 | 설치 | 제거 |
|---|---|---|---|
| Windows x64 | `teecher-agent-setup.exe` | 실행 → SmartScreen "추가 정보 → 실행" → 등록 토큰 입력 | 설정 → 앱 → Teecher Agent |
| macOS arm64 | `teecher-agent.pkg` | 우클릭 → 열기 → 등록 토큰 입력(대화상자) | `"/Applications/Teecher Agent/uninstall.sh"` |

설치하면 전용 CA 신뢰, 시스템 프록시(`127.0.0.1:18080`), 로그인 시 자동 실행, 에이전트 등록이 끝난다.
상태 확인: `teecher-agent status`. 설치 기록: Windows `%TEMP%\teecher-install.log`, macOS `~/Library/Logs/teecher-install.log`.
서버 주소는 설치 폴더의 `agent.conf`에 있고, 같은 이름의 환경변수가 있으면 그 값이 우선한다.

- **macOS 제거:** `sudo` 없이 실행한다. 관리자 암호가 필요한 곳에서 스스로 묻는다. 하나라도 실패하면 앱 폴더를 남기므로 다시 실행할 수 있다
- **macOS 등록 토큰:** 대화상자 입력은 가려진다. `sudo`가 명령 인자를 시스템 로그에 남기므로 `postinstall`은 토큰을 표준 입력(`install --enrollment-token-stdin`)으로 넘긴다
- **Windows 무인 설치:** `/SUPPRESSMSGBOXES`가 필요하다. 토큰은 설치 파라미터로 넘기므로 Inno 자체 로그는 꺼 두었다. `/LOG`를 주면 로그가 다시 켜져 토큰 파라미터가 기록되니 쓰지 않는다. 단계 기록은 `--log-file`로 `%TEMP%\teecher-install.log`에 남는다
- **업그레이드:** 실행 중인 에이전트를 먼저 내리고(Windows는 `PrepareToInstall`에서 작업 종료, macOS는 `postinstall`에서 `kr.teecher.agent` bootout) 파일을 덮은 뒤 새 바이너리를 띄운다. 키체인에 자격 증명이 있으면 토큰을 비워 둘 수 있다
- **실패 시 되돌리기:** 이번 실행에서 끝난 단계만 역순으로 되돌린다. 실패한 단계는 자기 하위 작업을 스스로 되돌린다. 18080 포트를 다른 프로그램이 쓰고 있으면 CA 생성·등록 전에(1회용 토큰을 쓰기 전에) 실패한다. 업그레이드가 `trust`·`activate`에서 실패하면 `prepare`도 되돌려 저장된 자격 증명이 지워지므로 새 토큰이 필요하다
- 설치 전에 다른 프록시가 켜져 있으면 경고를 로그에 남기고 덮어쓴다

로컬 빌드: `uv run --group build pyinstaller --noconfirm --distpath dist --workpath build packaging/teecher-agent.spec`
빌드 결과 확인: `dist/teecher-agent/teecher-agent self-test`(Windows는 `teecher-agent.exe`) (`OK self-test (keyring: <backend>)`)

## proto 올리기

```bash
cd proto && git fetch --tags && git checkout proto-vX.Y.Z && cd ..
git add proto && git commit -m "Bump proto to proto-vX.Y.Z"
```

## 브랜치

`develop`이 기본 브랜치. 기능 브랜치(`feat/…`, `fix/…`)는 `develop`으로 PR, 승인 1명 + CI 통과 필요.
