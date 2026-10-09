#!/bin/bash
# packaging/macos/uninstall.sh — 사용법: "/Applications/Teecher Agent/uninstall.sh" (관리자 암호를 묻는다)
set -u
APP="/Applications/Teecher Agent/teecher-agent"
LOG="$HOME/Library/Logs/teecher-uninstall.log"
mkdir -p "$HOME/Library/Logs" && touch "$LOG"
status=0
sudo "$APP" --home "$HOME" --log-file "$LOG" uninstall --phase activate || status=1
sudo "$APP" --home "$HOME" --log-file "$LOG" uninstall --phase trust || status=1
"$APP" --log-file "$LOG" uninstall --phase prepare || status=1
sudo rm -rf "/Applications/Teecher Agent"
sudo pkgutil --forget kr.teecher.agent >/dev/null 2>&1 || true
[ "$status" -eq 0 ] && echo "제거 완료" || echo "일부 항목을 되돌리지 못했다. 기록: $LOG"
exit "$status"
