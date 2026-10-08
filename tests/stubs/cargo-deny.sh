#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

# Stand-in for cargo-deny 0.20, invoked as 'cargo-deny --format json
# --color never --manifest-path M --config C --locked check CHECK...' or
# '--version'.
#
# It replays MOCK_DENY_LOG, JSON lines captured from the real tool, to
# stderr, rewriting the summary record to the checks requested, and
# exits as cargo-deny does: a bitmask of the failed checks (advisories
# 1, bans 2, licenses 4, sources 8). MOCK_DENY_ERRORS ('check=N ...')
# sets error counts; MOCK_DENY_EXIT and MOCK_DENY_STDERR override.

set -euo pipefail
# shellcheck source=record.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/record.sh"

if [ "${1:-}" = "--version" ]; then
  record_call "$MOCK_VERSION_LOG" deny-version
  echo "cargo-deny ${MOCK_DENY_VERSION:-0.20.2}"
  exit 0
fi

record_call "$MOCK_TOOL_LOG" deny
printf '%s\n' "$@" > "$MOCK_DENY_ARGS"

checks=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --format | --color | --manifest-path | --config) shift ;;
    --locked) ;;
    check)
      shift
      checks=("$@")
      break
      ;;
    *)
      echo "cargo-deny stand-in: unexpected argument: $1" >&2
      exit 90
      ;;
  esac
  shift
done
if [ "${#checks[@]}" -eq 0 ]; then
  echo "error: no check named" >&2
  exit 2
fi

if [ -n "${MOCK_DENY_STDERR+set}" ]; then
  printf '%s' "$MOCK_DENY_STDERR" >&2
  exit "${MOCK_DENY_EXIT:-1}"
fi

summary="$(jq -n -c --arg checks "${checks[*]}" \
  --arg errors "${MOCK_DENY_ERRORS:-}" '
  ($errors | split(" ") | map(select(length > 0) | split("=")
    | {key: .[0], value: (.[1] | tonumber)}) | from_entries) as $set
  | {type: "summary", fields: ($checks | split(" ") | map({key: .,
      value: {errors: ($set[.] // 0), warnings: 0, notes: 0, helps: 0}})
    | from_entries)}')"

grep -v '"type":"summary"' "$MOCK_DENY_LOG" >&2 || true
printf '%s\n' "$summary" >&2

status="$(jq '[.fields | to_entries[] | select(.value.errors > 0)
  | {advisories: 1, bans: 2, licenses: 4, sources: 8}[.key]] | add // 0' \
  <<< "$summary")"
exit "${MOCK_DENY_EXIT:-$status}"
