#!/usr/bin/env sh
# proto/ (platform-server submodule)에서 Python 코드를 생성한다. 결과(src/teecher/)는 커밋하지 않는다.
set -eu
cd "$(dirname "$0")/.."
PROTO_ROOT=proto/proto
if [ ! -d "$PROTO_ROOT" ]; then
    echo "proto submodule이 비어 있습니다: git submodule update --init" >&2
    exit 1
fi
uv run --group dev python -m grpc_tools.protoc \
    -I "$PROTO_ROOT" \
    --python_out=src --pyi_out=src --grpc_python_out=src \
    $(find "$PROTO_ROOT/teecher/verdict" "$PROTO_ROOT/teecher/agent" -name '*.proto')
find src/teecher -type d -exec touch {}/__init__.py \;
