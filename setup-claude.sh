#!/bin/bash
# Restore Claude Code config files from the claude-config branch.
# Run this after cloning: ./setup-claude.sh (or: git checkout claude-config -- setup-claude.sh && ./setup-claude.sh)
set -euo pipefail

BRANCH="claude-config"

if ! git rev-parse --verify "$BRANCH" >/dev/null 2>&1; then
  echo "Fetching $BRANCH from origin..."
  git fetch origin "$BRANCH"
fi

echo "Restoring Claude config files from $BRANCH..."
git checkout "$BRANCH" -- CLAUDE.md .gitignore

echo "Done. Claude Code config restored."
