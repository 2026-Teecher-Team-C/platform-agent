# uv run --group build pyinstaller --noconfirm --distpath dist --workpath build packaging/teecher-agent.spec
import os
import sys

from PyInstaller.utils.hooks import collect_dynamic_libs, collect_submodules, copy_metadata

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))
SRC = os.path.join(ROOT, "src")

# keyring은 백엔드를 entry point로 찾는다 — 메타데이터가 빠지면 OS 키체인을 못 찾는다(스펙 5.3)
hiddenimports = [
    "keyring.backends.macOS",
    "keyring.backends.Windows",
    *collect_submodules("mitmproxy.addons"),
    *collect_submodules("teecher"),
]
datas = copy_metadata("keyring") + copy_metadata("mitmproxy")
binaries = collect_dynamic_libs("mitmproxy_rs")

a = Analysis(
    [os.path.join(SRC, "agent", "__main__.py")],
    pathex=[SRC],
    hiddenimports=hiddenimports,
    datas=datas,
    binaries=binaries,
)
pyz = PYZ(a.pure)
exes = [EXE(pyz, a.scripts, [], exclude_binaries=True, name="teecher-agent", console=True)]
if sys.platform == "win32":
    # 작업 스케줄러가 띄우는 쪽 — 콘솔 창 없음(스펙 5.2)
    exes.append(EXE(pyz, a.scripts, [], exclude_binaries=True, name="teecher-agentw", console=False))
coll = COLLECT(*exes, a.binaries, a.datas, name="teecher-agent")
