#!/usr/bin/env bash
# Remove AXguard skills/commands from agent harnesses.

set -euo pipefail

AGENT="${AXGUARD_AGENT:-claude}"
SCOPE="global"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Derived from the repo so these lists can never drift from what install.sh ships.
SKILLS=()
while IFS= read -r skill_md; do
  SKILLS+=("$(basename "$(dirname "$skill_md")")")
done < <(find "$ROOT" -mindepth 2 -maxdepth 2 -type f -name SKILL.md 2>/dev/null | sort)

COMMANDS=()
for cmd in "$ROOT"/commands/*.md; do
  [ -f "$cmd" ] || continue
  COMMANDS+=("$(basename "$cmd")")
done

while [ "$#" -gt 0 ]; do
  case "$1" in
    --agent) shift; AGENT="${1:?}" ;;
    --agent=*) AGENT="${1#*=}" ;;
    --global) SCOPE="global" ;;
    --project) SCOPE="project" ;;
    -h|--help)
      echo "Usage: ./uninstall.sh [--agent claude|cursor|opencode|codex|agents|all] [--global|--project]"
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

remove_named() {
  local dest="$1"
  shift
  local name
  for name in "$@"; do
    if [ -e "$dest/$name" ]; then
      rm -rf "$dest/$name"
      echo "removed $dest/$name"
    fi
  done
}

do_pair() {
  local root_skills="$1"
  local root_commands="$2"
  remove_named "$root_skills" "${SKILLS[@]}"
  remove_named "$root_commands" "${COMMANDS[@]}"
}

do_claude() {
  local root; if [ "$SCOPE" = "project" ]; then root=".claude"; else root="$HOME/.claude"; fi
  do_pair "$root/skills" "$root/commands"
}

do_cursor() {
  local root; if [ "$SCOPE" = "project" ]; then root=".cursor"; else root="$HOME/.cursor"; fi
  do_pair "$root/skills" "$root/commands"
}

do_opencode() {
  local root
  if [ "$SCOPE" = "project" ]; then root=".opencode"; else root="${OPENCODE_CONFIG_DIR:-$HOME/.config/opencode}"; fi
  do_pair "$root/skills" "$root/commands"
}

do_codex() {
  local root; if [ "$SCOPE" = "project" ]; then root=".codex"; else root="${CODEX_HOME:-$HOME/.codex}"; fi
  do_pair "$root/skills" "$root/commands"
}

do_agents() {
  local root; if [ "$SCOPE" = "project" ]; then root=".agents"; else root="$HOME/.agents"; fi
  remove_named "$root/skills" "${SKILLS[@]}"
}

case "$AGENT" in
  claude) do_claude ;;
  cursor) do_cursor ;;
  opencode) do_opencode ;;
  codex) do_codex ;;
  agents) do_agents ;;
  all) do_claude; do_cursor; do_opencode; do_codex; do_agents ;;
  *) echo "Unknown agent: $AGENT" >&2; exit 2 ;;
esac
