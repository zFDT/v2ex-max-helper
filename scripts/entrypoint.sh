#!/bin/sh
set -eu

echo "[entrypoint] Starting v2ex-max-helper..."

# 确保数据目录存在
DATA_DIR="${V2EX_DATA_DIR:-/app/data}"
export V2EX_DATA_DIR="$DATA_DIR"
mkdir -p "$V2EX_DATA_DIR"

# 将 V2EX_COOKIE 环境变量写入文件（供模块读取）。
# 如果 volume 里已有 cookie，则保留已续期/已通过 Bot 更新的版本。
if [ -n "${V2EX_COOKIE:-}" ]; then
  PROFILE="${V2EX_PROFILE:-default}"
  if [ "$PROFILE" = "default" ]; then
    COOKIE_TARGET="${V2EX_DATA_DIR}/.v2ex_cookie"
  else
    COOKIE_TARGET="${V2EX_DATA_DIR}/.v2ex_cookie.${PROFILE}"
  fi

  if [ ! -s "$COOKIE_TARGET" ]; then
    echo "[entrypoint] Writing cookie from env to ${COOKIE_TARGET}"
    printf '%s' "$V2EX_COOKIE" > "$COOKIE_TARGET"
    chmod 600 "$COOKIE_TARGET"
  else
    echo "[entrypoint] Cookie file already exists, keeping persisted cookie: ${COOKIE_TARGET}"
  fi
fi

# Docker 下禁用 bot.js 内置的 HTTP 铁墙（由 server.js 统一提供）
export DISABLE_HTTP_WALL=1

# 后台启动 HTTP 健康检查服务
node server.js &
SERVER_PID=$!
echo "[entrypoint] health server started (PID: $SERVER_PID)"

# 后台启动 Telegram Bot（常驻，内置每日定时签到/阅读调度器）
node reader/bot.js &
BOT_PID=$!
echo "[entrypoint] bot started (PID: $BOT_PID)"

cleanup() {
  echo "[entrypoint] shutting down..."
  kill "$BOT_PID" "$SERVER_PID" 2>/dev/null || true
  wait "$BOT_PID" "$SERVER_PID" 2>/dev/null || true
}

trap 'cleanup; exit 143' INT TERM

set +e
wait "$BOT_PID"
BOT_STATUS=$?
set -e

echo "[entrypoint] bot exited with status ${BOT_STATUS}; stopping health server"
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
exit "$BOT_STATUS"
