#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

for name in old new; do
  git init --quiet -b main "$tmp_dir/$name"
  git -C "$tmp_dir/$name" config user.name 'Source checkout fixture'
  git -C "$tmp_dir/$name" config user.email 'fixture@example.invalid'
  printf '%s\n' "$name" > "$tmp_dir/$name/source-marker"
  git -C "$tmp_dir/$name" add source-marker
  git -C "$tmp_dir/$name" commit --quiet -m "inert $name fixture"
done

for script in install.sh update.sh; do
  # Load only the checkout function, without running install/service operations.
  definition="$(awk '
    /^checkout_or_update\(\) \{/ { found = 1 }
    found { print }
    found && /^\}/ { exit }
  ' "$repo_root/$script")"
  test -n "$definition"
  eval "$definition"

  WORK_DIR="$tmp_dir/$script-checkout"
  BRANCH=main
  git clone --quiet "$tmp_dir/old" "$WORK_DIR"

  for selected in new new old; do
    REPO_URL="$tmp_dir/$selected"
    checkout_or_update > "$tmp_dir/$script.log" 2>&1
    test "$(git -C "$WORK_DIR" remote get-url origin)" = "$REPO_URL"
    test "$(git -C "$WORK_DIR" rev-parse HEAD)" = "$(git -C "$REPO_URL" rev-parse HEAD)"
    test "$(cat "$WORK_DIR/source-marker")" = "$selected"
  done

  # Fresh checkout must honor the selected source as well.
  WORK_DIR="$tmp_dir/$script-fresh"
  REPO_URL="$tmp_dir/new"
  checkout_or_update > "$tmp_dir/$script-fresh.log" 2>&1
  test "$(cat "$WORK_DIR/source-marker")" = new
  printf 'PASS %s source switch, repeat, override and fresh clone\n' "$script"
done
