#!/usr/bin/env bash
set -euo pipefail

cd /mnt/c/Users/Soloman/university-management-system/University-Management-System

"/mnt/c/Program Files/Git/cmd/git.exe" add .
"/mnt/c/Program Files/Git/cmd/git.exe" commit -m "$(cat <<'EOF'
feat(sbom): add SBOM pipeline, signing workflows, and CI checks

EOF
)"
"/mnt/c/Program Files/Git/cmd/git.exe" status --porcelain=v1 -uall
