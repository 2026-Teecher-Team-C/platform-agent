"""teecher-agent 명령. 설치본(PyInstaller)의 진입점이다.

  run                         에이전트 실행 (자동 실행이 부른다)
  install   --phase P         설치 단계 하나. OS 설치 파일이 권한에 맞게 prepare → trust → activate 순서로 부른다
            [--enrollment-token T | --enrollment-token-stdin]
  uninstall --phase P         제거 단계 하나. activate → trust → prepare 순서
  status                      CA 신뢰, 등록, 자동 실행, 포트, 프록시 상태
  self-test                   설치본에 빠진 모듈이 없는지 확인 (빌드 CI용)

--home은 macOS 관리자 단계(root)에서 콘솔 사용자의 홈을 가리킬 때 쓴다.
"""

import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path

from agent.ca import load_ca
from agent.conf_file import apply_conf, default_conf_path
from agent.config import Config
from agent.credentials import make_store, secure_backend_name
from agent.enroll import enroll
from agent.installer import (
    InstallContext,
    InstallError,
    Phase,
    build_steps,
    install_phase,
    port_open,
    uninstall_phase,
    wait_port,
)
from agent.platform import PROXY_HOST, PROXY_PORT, UnsupportedPlatformError, agent_run_command, app_dirs, os_integration

logger = logging.getLogger(__name__)


def load_conf() -> None:
    path = default_conf_path()
    if path is not None:
        apply_conf(path, os.environ)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="teecher-agent")
    parser.add_argument("--home", type=Path, default=Path.home())
    parser.add_argument("--log-file", type=Path)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run")
    install = sub.add_parser("install")
    install.add_argument("--phase", type=Phase, choices=list(Phase), required=True)
    token = install.add_mutually_exclusive_group()
    token.add_argument("--enrollment-token", default="")
    # sudo는 명령 인자를 시스템 로그에 남긴다 — macOS 설치 파일은 토큰을 표준 입력 한 줄로 넘긴다
    token.add_argument("--enrollment-token-stdin", action="store_true")
    uninstall = sub.add_parser("uninstall")
    uninstall.add_argument("--phase", type=Phase, choices=list(Phase), required=True)
    sub.add_parser("status")
    sub.add_parser("self-test")
    return parser


def _log_to(path: Path | None) -> logging.Handler | None:
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    if path is None:
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(path, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    root.addHandler(handler)
    return handler


def _context(args, dirs, integration) -> InstallContext:
    config = Config.from_env()
    store = make_store(config.credential_store)
    token = getattr(args, "enrollment_token", "")
    if getattr(args, "enrollment_token_stdin", False):
        token = sys.stdin.readline().strip()
    token = token or config.enrollment_token

    def do_enroll() -> None:
        if not token:
            raise RuntimeError("등록 토큰이 없다 — 관리 콘솔에서 발급한 토큰을 설치 화면에 입력한다")
        try:
            asyncio.run(enroll(config, token, store))
        except Exception as exc:
            # 서버 오류 문구에 토큰이 들어갈 일은 없지만, 넘기는 메시지는 예외 종류와 서버 상태만 둔다
            raise RuntimeError(f"서버 등록 실패: {type(exc).__name__}: {exc}".replace(token, "***")) from None

    return InstallContext(
        dirs=dirs,
        integration=integration,
        store=store,
        enroll=do_enroll,
        run_command=agent_run_command(),
        port_open=lambda: port_open(PROXY_HOST, PROXY_PORT),
        wait_port=lambda: wait_port(PROXY_HOST, PROXY_PORT),
    )


def _status(ctx: InstallContext) -> int:
    ca = load_ca(ctx.dirs.ca)
    creds = ctx.store.load()
    rows = [
        ("CA", ca is not None, str(ctx.dirs.ca) if ca else "없음"),
        ("CA 신뢰", ca is not None and ctx.integration.ca_trusted(ca), f"SHA-1 {ca.sha1}" if ca else "-"),
        ("등록", creds is not None, f"agent_id={creds.agent_id}" if creds else "없음"),
        ("자동 실행", ctx.integration.autostart_installed(), ""),
        (f"에이전트 포트 {PROXY_HOST}:{PROXY_PORT}", ctx.port_open(), ""),
        ("시스템 프록시", ctx.integration.proxy_is_ours(), ""),
    ]
    for name, ok, detail in rows:
        print(f"{'OK ' if ok else '-- '}{name}{': ' + detail if detail else ''}")
    return 0 if all(ok for _, ok, _ in rows) else 1


def _self_test() -> int:
    import teecher.agent.v1.agent_pb2  # noqa: F401 — 생성 코드가 실행 파일에 들어갔는지
    from agent.runner import build_master

    async def build() -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            master, _ = build_master(Path(tmp), port=0)
            master.shutdown()

    asyncio.run(build())
    backend = secure_backend_name()
    if backend is None:
        print("-- OS 보안 저장소 keyring 백엔드를 찾지 못했다", file=sys.stderr)
        return 1
    print(f"OK self-test (keyring: {backend})")
    return 0


def main(argv: list[str] | None = None, integration_factory=os_integration) -> int:
    args = _parser().parse_args(argv)
    load_conf()
    if args.command == "self-test":
        return _self_test()
    dirs = app_dirs(args.home)
    if args.command == "run":
        from agent.runner import serve, setup_logging

        setup_logging(dirs.logs)
        asyncio.run(serve(dirs))
        return 0
    handler = _log_to(args.log_file)
    try:
        return _dispatch(args, dirs, integration_factory)
    finally:
        # 떼지 않으면 Windows에서 파일이 열린 채 남고, 다음 호출에 같은 줄이 겹쳐 찍힌다
        if handler is not None:
            logging.getLogger().removeHandler(handler)
            handler.close()


def _dispatch(args, dirs, integration_factory) -> int:
    try:
        integration = integration_factory(dirs, args.home)
    except UnsupportedPlatformError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    ctx = _context(args, dirs, integration)
    if args.command == "status":
        return _status(ctx)
    steps = build_steps(ctx)
    if args.command == "install":
        try:
            install_phase(steps, args.phase)
        except InstallError as exc:
            print(f"설치 실패: {exc}", file=sys.stderr)
            return 1
        return 0
    leftovers = uninstall_phase(steps, args.phase)
    if leftovers:
        print(f"되돌리지 못한 항목: {', '.join(leftovers)}", file=sys.stderr)
        return 1
    return 0
