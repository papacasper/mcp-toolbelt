#!/usr/bin/env bash
# Deploy mcp/ (mcp-toolbelt) to papacasper.com: push git, install deps, restart, health-check.
set -euo pipefail

REMOTE_HOST="papacasper.com"
REMOTE_DIR="/var/www/papacasper.com/mcp"
SERVICE="mcp-toolbelt.service"

echo "==> pushing master to $REMOTE_HOST"
git push origin master

echo "==> installing deps on $REMOTE_HOST"
ssh "$REMOTE_HOST" "export PATH=\$HOME/.bun/bin:\$PATH && cd $REMOTE_DIR && bun install"

echo "==> restarting $SERVICE"
ssh -t "$REMOTE_HOST" "sudo systemctl restart $SERVICE"

echo "==> health check"
ssh "$REMOTE_HOST" "sleep 1 && systemctl is-active $SERVICE && curl -s http://127.0.0.1:3457/health"
echo

echo "==> deploy complete"
