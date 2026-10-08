#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

# Stand-in for cargo-audit 0.22, invoked as 'cargo-audit audit --json
# --file LOCK [--ignore ID]... [--deny KIND]...' or '--version'.
#
# It serves MOCK_AUDIT_REPORT, a report captured from the real tool,
# and behaves as the real tool was observed to: an ignored ID drops
# matching vulnerabilities and warnings, and the exit status is 1 when
# a vulnerability remains or a denied warning kind is present, else 0.
# MOCK_PROJECT_IGNORES imitates IDs a project's .cargo/audit.toml
# ignores; MOCK_AUDIT_EXIT and MOCK_AUDIT_STDOUT override the outcome,
# MOCK_AUDIT_STDERR adds a line of diagnostics, and MOCK_AUDIT_PLANT
# names a file to create first, as a rival writer would;
# MOCK_AUDIT_PLANT_TO makes it a symlink to that target instead.

set -euo pipefail
# shellcheck source=record.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/record.sh"

if [ "${1:-}" = "--version" ]; then
  record_call "$MOCK_VERSION_LOG" audit-version
  echo "cargo-audit ${MOCK_AUDIT_VERSION:-0.22.2}"
  exit 0
fi

record_call "$MOCK_TOOL_LOG" audit
printf '%s\n' "$@" > "$MOCK_AUDIT_ARGS"

[ "${1:-}" = "audit" ] || exit 90
shift
lockfile=""
ignores=()
denies=()
json="false"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --json) json="true" ;;
    --file)
      lockfile="$2"
      shift
      ;;
    --ignore)
      ignores+=("$2")
      shift
      ;;
    --deny)
      denies+=("$2")
      shift
      ;;
    *)
      echo "cargo-audit stand-in: unexpected argument: $1" >&2
      exit 90
      ;;
  esac
  shift
done
[ "$json" = "true" ] || exit 90

if [ -n "${MOCK_AUDIT_PLANT_TO:-}" ]; then
  ln -s -- "$MOCK_AUDIT_PLANT_TO" "$MOCK_AUDIT_PLANT"
elif [ -n "${MOCK_AUDIT_PLANT:-}" ]; then
  echo planted > "$MOCK_AUDIT_PLANT"
fi

echo "    Fetching advisory database from \`https://github.com/RustSec/advisory-db.git\`" >&2
if [ -n "${MOCK_AUDIT_STDERR:-}" ]; then
  printf '%s\n' "$MOCK_AUDIT_STDERR" >&2
fi
if [ ! -f "$lockfile" ]; then
  echo "error: not found: Couldn't load $lockfile" >&2
  exit 2
fi
echo "    Scanning $lockfile for vulnerabilities (12 crate dependencies)" >&2

if [ -n "${MOCK_AUDIT_STDOUT+set}" ]; then
  printf '%s' "$MOCK_AUDIT_STDOUT"
  exit "${MOCK_AUDIT_EXIT:-1}"
fi

read -r -a project <<< "${MOCK_PROJECT_IGNORES:-}"
ignore_list="${ignores[*]+${ignores[*]}} ${project[*]+${project[*]}}"
deny_list="${denies[*]+${denies[*]}}"
report="$(jq --arg ignore "$ignore_list" --arg deny "$deny_list" '
  ($ignore | split(" ") | map(select(length > 0))) as $ignored
  | ($deny | split(" ") | map(select(length > 0))) as $denied
  | def kept: (.advisory.id? // "") as $id | $ignored | index($id) | not;
  .settings.ignore = $ignored
  | .vulnerabilities.list |= map(select(kept))
  | .vulnerabilities.count = (.vulnerabilities.list | length)
  | .vulnerabilities.found = (.vulnerabilities.count > 0)
  | .warnings |= with_entries(.value |= map(select(kept)))
  | .warnings |= with_entries(select(.value | length > 0))
  | . as $r
  | .exit = (if $r.vulnerabilities.count > 0
      or any($denied[]; . as $k
        | if $k == "warnings" then ([$r.warnings[][]] | length) > 0
          else (($r.warnings[$k] // []) | length) > 0 end)
      then 1 else 0 end)
' < "$MOCK_AUDIT_REPORT")"

status="$(jq '.exit' <<< "$report")"
jq 'del(.exit)' <<< "$report"
exit "${MOCK_AUDIT_EXIT:-$status}"
