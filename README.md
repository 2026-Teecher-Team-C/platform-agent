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

## 배포

최종 배포는 설치 파일(PyInstaller → `.pkg` / `.msi`)이다. 설치 시 CA 등록, 시스템 프록시 설정, 서비스 등록을
한다 — 설치 파일은 아직 만들지 않았다.

## proto 올리기

```bash
cd proto && git fetch --tags && git checkout proto-vX.Y.Z && cd ..
git add proto && git commit -m "Bump proto to proto-vX.Y.Z"
```

## 브랜치

`develop`이 기본 브랜치. 기능 브랜치(`feat/…`, `fix/…`)는 `develop`으로 PR, 승인 1명 + CI 통과 필요.
