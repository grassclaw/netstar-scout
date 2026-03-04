#!/usr/bin/env bash
#
# Deploy Server and Scoring Engine to a remote host via SSH.
# Uses your SSH keys. Uses tar-over-SSH so the remote does not need rsync.
#
# Usage:
#   ./deploy.sh                    # deploy using defaults
#   ./deploy.sh user@host          # deploy to user@host
#   REMOTE_PATH=/opt/app ./deploy.sh
#
# Set these for your environment (or pass user@host as first argument):
set -e

# --- Configuration (override with env or first argument) ---
REMOTE_USER="${REMOTE_USER:-}"
REMOTE_HOST="${REMOTE_HOST:-}"
REMOTE_PATH="${REMOTE_PATH:-/home/zxdev/capstone}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/capstone_ed25519}"

if [[ -n "$1" ]]; then
  if [[ "$1" == *"@"* ]]; then
    REMOTE_USER="${1%%@*}"
    REMOTE_HOST="${1##*@}"
  else
    REMOTE_HOST="$1"
  fi
fi

if [[ -z "$REMOTE_HOST" ]]; then
  echo "Usage: $0 [user@]hostname"
  echo "   or set REMOTE_USER, REMOTE_HOST, and optionally REMOTE_PATH"
  echo "   Example: $0 deploy@myserver.example.com"
  exit 1
fi

REMOTE="${REMOTE_USER:+$REMOTE_USER@}$REMOTE_HOST"
SSH_CMD="ssh"
[[ -n "$SSH_KEY" ]] && SSH_CMD="ssh -i $SSH_KEY"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Deploying to $REMOTE:$REMOTE_PATH"

# Create remote base path
$SSH_CMD "$REMOTE" "mkdir -p '$REMOTE_PATH'"

# Deploy Server (Node.js) — exclude node_modules; run npm install on server
# Use tar-over-SSH so remote does not need rsync
echo "Syncing Server..."
$SSH_CMD "$REMOTE" "mkdir -p '$REMOTE_PATH/Server'"
tar cf - --exclude='node_modules' --exclude='.git' --exclude='.DS_Store' -C ./Server . \
  | $SSH_CMD "$REMOTE" "cd '$REMOTE_PATH/Server' && tar xf -"

# Deploy Scoring Engine (Python) — exclude cache and bytecode
echo "Syncing Scoring Engine..."
$SSH_CMD "$REMOTE" "mkdir -p '$REMOTE_PATH/Scoring Engine'"
tar cf - --exclude='__pycache__' --exclude='*.pyc' --exclude='.git' --exclude='.DS_Store' -C "./Scoring Engine" . \
  | $SSH_CMD "$REMOTE" "cd '$REMOTE_PATH/Scoring Engine' && tar xf -"

# Install Node dependencies on the server (so the server can run)
echo "Installing Server dependencies on remote..."
$SSH_CMD "$REMOTE" "cd '$REMOTE_PATH/Server' && npm install --production"

echo "Deploy complete. Server: $REMOTE_PATH/Server  |  Scoring Engine: $REMOTE_PATH/Scoring Engine"
echo "To start the server: ssh $REMOTE 'cd $REMOTE_PATH/Server && node server.js'"
