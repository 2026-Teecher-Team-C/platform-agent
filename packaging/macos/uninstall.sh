#!/bin/bash
# packaging/macos/uninstall.sh — 사용법: "/Applications/Teecher Agent/uninstall.sh" (관리자 암호를 묻는다)
set -u
[ "$(id -u)" -eq 0 ] && { echo "sudo 없이 실행하세요 — 필요한 곳에서만 관리자 암호를 묻는다" >&2; exit 1; }
APP="/Applications/Teecher Agent/teecher-agent"
LOG="$HOME/Library/Logs/teecher-uninstall.log"
mkdir -p "$HOME/Library/Logs" && touch "$LOG"
status=0
sudo "$APP" --home "$HOME" --log-file "$LOG" uninstall --phase activate || status=1
sudo "$APP" --home "$HOME" --log-file "$LOG" uninstall --phase trust || status=1
"$APP" --log-file "$LOG" uninstall --phase prepare || status=1
# 일부라도 실패했으면 앱 폴더를 남겨 다시 시도할 수 있게 한다
if [ "$status" -eq 0 ]; then
  sudo rm -rf "/Applications/Teecher Agent"
  sudo pkgutil --forget kr.teecher.agent >/dev/null 2>&1 || true
  echo "제거 완료"
else
  echo "일부 항목을 되돌리지 못했다. 다시 실행하세요. 기록: $LOG"
fi
exit "$status"
