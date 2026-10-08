#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

# Audit a Rust project's dependencies with cargo-audit and, optionally,
# cargo-deny.
#
# action.yaml runs this script twice:
#
#   rust-audit.sh check   Validate every input, the allow-list file
#                         included, before any tool installs, and name
#                         the tools for taiki-e/install-action.
#   rust-audit.sh audit   Validate again, then run the stages:
#                         Resolve toolchain -> Check tools
#                         -> Locate lockfile -> Audit with cargo-audit
#                         -> Check with cargo-deny
#
# Inputs arrive as INPUT_* environment variables. Nothing here compiles
# the project. Findings from both tools are gathered before the step
# fails, so a single run reports everything; a tool that cannot produce
# a report stops the run at its stage. The reports land in one
# directory, which action.yaml uploads as an artefact, also after a
# failure.

set -euo pipefail

readonly default_cargo_audit_version="0.22.2"
readonly default_cargo_deny_version="0.20.2"
readonly default_deny_checks="advisories bans licenses sources"
readonly advisory_id_re='^RUSTSEC-[0-9]{4}-[0-9]{4}$'
readonly alias_id_re='^(GHSA(-[a-z0-9]{4}){3}|CVE-[0-9]{4}-[0-9]{4,})$'
readonly version_re='^[0-9]+\.[0-9]+\.[0-9]+$'
readonly channel_re='^[A-Za-z0-9._+-]+$'
# A Rust release as cargo and rustc report it, pre-release tag allowed.
readonly rust_version_re='^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$'
# Every reason rustup appends to the toolchain it names, in parentheses.
# A path toolchain, and the file a reason quotes, may hold ' (' too.
readonly toolchain_reason_re='^(.+) \((default|(overridden by|environment override by|directory override for) .+)\)$'
readonly allow_list_max_bytes=1048576
# About four times the RustSec database (1,293 advisories at 0.22.2's
# release), and far inside Linux's argument limit for the --ignore
# pairs this becomes: 58,000 IDs fail with E2BIG under an 8 MiB stack.
readonly ignore_ids_max=5000
readonly table_row_limit=200
readonly default_artefact_name="rust-audit-results"
readonly artefact_name_re='^[A-Za-z0-9._-]+$'

# Variables no child process sees. Cargo reads a token for every
# registry, so each CARGO_REGISTRIES_<NAME>_TOKEN present goes as well
# (run_in finds them); the registries' other settings stay. Withholding
# the runner's command files keeps tool and project code from setting
# this step's outputs or the environment, PATH, state or summary of
# later steps. That is defence in depth, not a boundary: the files'
# paths are predictable, so code running as the same user can still
# find them. This script's own writes read the variables directly.
readonly -a scrubbed_variables=(
  CARGO_REGISTRY_TOKEN
  ACTIONS_ID_TOKEN_REQUEST_TOKEN
  ACTIONS_ID_TOKEN_REQUEST_URL
  ACTIONS_RUNTIME_TOKEN
  GITHUB_OUTPUT
  GITHUB_ENV
  GITHUB_PATH
  GITHUB_STATE
  GITHUB_STEP_SUMMARY
)

phase="${1:-}"
case "$phase" in
  check | audit) ;;
  *)
    echo "::error::usage: rust-audit.sh check|audit"
    exit 2
    ;;
esac

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=markdown.sh
source "$script_dir/markdown.sh"

# Empty path inputs fall back to their defaults; every other input must
# be set, so an empty boolean or version fails validation.
path_prefix="${INPUT_PATH_PREFIX:-.}"
manifest_path="${INPUT_MANIFEST_PATH:-Cargo.toml}"
lockfile_required="${INPUT_LOCKFILE_REQUIRED-false}"
permit_fail="${INPUT_PERMIT_FAIL-false}"
summary="${INPUT_SUMMARY-true}"
ignore_vulns="${INPUT_IGNORE_VULNS:-}"
allow_list_path="${INPUT_ALLOW_LIST_PATH:-}"
deny_warnings="${INPUT_DENY_WARNINGS:-}"
deny_enabled="${INPUT_DENY_ENABLED-false}"
deny_checks="${INPUT_DENY_CHECKS-$default_deny_checks}"
cargo_audit_version="${INPUT_CARGO_AUDIT_VERSION-$default_cargo_audit_version}"
cargo_deny_version="${INPUT_CARGO_DENY_VERSION-$default_cargo_deny_version}"
artefact_upload="${INPUT_ARTEFACT_UPLOAD-true}"
artefact_name="${INPUT_ARTEFACT_NAME-$default_artefact_name}"
artefact_path="${INPUT_ARTEFACT_PATH:-}"
toolchain_input="${INPUT_TOOLCHAIN:-}"

stage="Check inputs"
failure_reason=""
failures_permitted="false"
readonly install_failure_reason="The audit tools did not install; see the Install audit tools step log."
audit_outcome=""
audit_reason=""
deny_outcome="skipped"
deny_reason=""
deny_exceptions_cell=""
vulnerability_count=""
warning_count=""
vulnerability_ids=""
report_path=""
deny_report_path=""
artefact_dir=""
artefact_display=""
reports_cell=""
work_dir=""
manifest_display=""
lockfile_cell=""
toolchain=""
toolchain_kind=""
toolchain_pin=""
cargo_version=""
rustc_version=""
audit_cell="⏸️ Not reached"
vulnerability_cell="⏸️ Not reached"
warning_cell="⏸️ Not reached"
ignored_cell="➖ None"
if [ "$deny_enabled" = "true" ]; then
  deny_cell="⏸️ Not reached"
else
  deny_cell="➖ Not enabled"
fi

words=()
choices=()
ignore_ids=()
allow_list_count=0
denied_kinds=()
deny_check_list=()
notes=()
vulnerability_rows=()
warning_rows=()

# Annotations for audit failures are errors, or warnings once
# permit_fail applies, so a permitted run carries no error.
failure_level() {
  if [ "$failures_permitted" = "true" ]; then
    printf 'warning'
  else
    printf 'error'
  fi
}

fail() {
  failure_reason="$*"
  echo "::$(failure_level)::$(command_data "$*")"
  exit 1
}

# Record a warning for the job summary and annotate it.
warn() {
  notes+=("$1")
  annotate warning "" "$1"
}

# Print COUNT with the singular or plural noun: '1 package', '2 packages'.
count_of() {
  if [ "$1" -eq 1 ]; then
    printf '%s %s' "$1" "$2"
  else
    printf '%s %s' "$1" "$3"
  fi
}

set_output() {
  case "$2" in
    *$'\n'* | *$'\r'*)
      echo "::warning::Skipped output $1: its value spans lines"
      return 0
      ;;
  esac
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    printf '%s=%s\n' "$1" "$2" >> "$GITHUB_OUTPUT"
  fi
}

### Job summary ###

render_summary() {
  local status="$1" outcome text line
  if [ "$status" -eq 0 ]; then
    outcome="✅ Passed"
  elif [ "$failures_permitted" = "true" ]; then
    outcome="⚠️ Failed at $(md_text "$stage") (permitted)"
  else
    outcome="❌ Failed at $(md_text "$stage")"
  fi
  text="$(
    printf '\n## 🦀 Rust Dependency Audit\n\n### %s\n\n' "$outcome"
    if [ -n "$failure_reason" ]; then
      printf '%s\n\n' "$(md_text "$failure_reason")"
    fi
    if [ "$phase" = "audit" ]; then
      printf '| Check | Result |\n| --- | --- |\n'
      if [ -n "$manifest_display" ]; then
        printf '| Manifest | %s |\n' "$(md_code "$manifest_display")"
      fi
      case "$toolchain_kind" in
        channel)
          printf '| Toolchain | %s (cargo %s, rustc %s) |\n' \
            "$(md_code "$toolchain")" "$(md_text "${cargo_version:-unknown}")" \
            "$(md_text "${rustc_version:-unknown}")"
          ;;
        path)
          printf '| Toolchain | ⚠️ Path toolchain %s (cargo %s, rustc %s) |\n' \
            "$(md_code "$toolchain")" "$(md_text "${cargo_version:-unknown}")" \
            "$(md_text "${rustc_version:-unknown}")"
          ;;
        none)
          printf '| Toolchain | No rustup: %s from PATH (cargo %s, rustc %s) |\n' \
            "$(md_code cargo)" "$(md_text "${cargo_version:-unknown}")" \
            "$(md_text "${rustc_version:-unknown}")"
          ;;
      esac
      if [ -n "$lockfile_cell" ]; then
        printf '| Lockfile | %s |\n' "$lockfile_cell"
      fi
      printf '| cargo-audit | %s |\n' "$audit_cell"
      printf '| Vulnerabilities | %s |\n' "$vulnerability_cell"
      printf '| Warnings | %s |\n' "$warning_cell"
      printf '| Ignored | %s |\n' "$ignored_cell"
      printf '| cargo-deny | %s |\n' "$deny_cell"
      if [ -n "$reports_cell" ]; then
        printf '| Reports | %s in %s |\n' "$reports_cell" \
          "$(md_code "$artefact_display")"
        if [ "$artefact_upload" = "true" ]; then
          printf '| Artefact | 📦 %s, uploaded after this step |\n' \
            "$(md_code "$artefact_name")"
        else
          printf '| Artefact | ➖ Upload disabled |\n'
        fi
      fi
      if [ "${#vulnerability_rows[@]}" -gt 0 ]; then
        printf '\n### Vulnerabilities\n\n'
        printf '| ID | Crate | Version | Title | Patched versions |\n'
        printf '| --- | --- | --- | --- | --- |\n'
        printf '%s\n' "${vulnerability_rows[@]}"
      fi
      if [ "${#warning_rows[@]}" -gt 0 ]; then
        printf '\n### Crate warnings\n\n'
        printf '| Kind | ID | Crate | Version | Title |\n'
        printf '| --- | --- | --- | --- | --- |\n'
        printf '%s\n' "${warning_rows[@]}"
      fi
    fi
    if [ "${#notes[@]}" -gt 0 ]; then
      printf '\n**Warnings**\n\n'
      for line in "${notes[@]}"; do
        printf -- '- %s\n' "$(md_text "$line")"
      done
    fi
  )"
  # One simple command, so a failed redirection reaches the 'if'.
  if ! printf '%s\n' "$text" 2> /dev/null >> "$GITHUB_STEP_SUMMARY"; then
    echo "::warning::Could not write the job summary"
  fi
}

finish() {
  local status=$?
  trap - EXIT
  if [ "$status" -ne 0 ] && [ -z "$failure_reason" ]; then
    failure_reason="$stage failed with exit status $status; see the step log."
  fi
  if [ "$phase" = "check" ]; then
    # Fallbacks for when the audit step never runs, as after invalid
    # inputs. The audit step's own outcomes take precedence in
    # action.yaml.
    set_output audit_outcome failed
    set_output deny_outcome skipped
  else
    # audit_outcome reflects cargo-audit alone: anything short of a
    # completed, clean audit is a failure.
    if [ "$audit_outcome" != "passed" ]; then
      audit_outcome="failed"
    fi
    set_output audit_outcome "$audit_outcome"
    set_output deny_outcome "$deny_outcome"
    set_output toolchain "$toolchain"
    set_output toolchain_kind "$toolchain_kind"
    set_output cargo_version "$cargo_version"
    set_output rustc_version "$rustc_version"
    set_output vulnerability_count "$vulnerability_count"
    set_output warning_count "$warning_count"
    set_output vulnerability_ids "$vulnerability_ids"
    set_output report_path "$report_path"
    set_output deny_report_path "$deny_report_path"
    set_output artefact_path "$artefact_dir"
    # action.yaml uploads when this says so, after a failure too.
    if [ "$artefact_upload" = "true" ] && [ -n "$reports_cell" ]; then
      set_output artefact_name "$artefact_name"
      set_output upload_reports true
    else
      set_output upload_reports false
    fi
  fi
  if [ "$summary" = "true" ] && [ -n "${GITHUB_STEP_SUMMARY:-}" ] \
    && { [ "$phase" = "audit" ] || [ "$status" -ne 0 ]; }; then
    render_summary "$status"
  fi
  if [ "$status" -ne 0 ] && [ "$failures_permitted" = "true" ]; then
    echo "::warning::$(command_data "Failed at $stage; permit_fail is 'true', so the step reports success")"
    exit 0
  fi
  exit "$status"
}
trap finish EXIT

### Input validation ###

require_boolean() {
  case "$2" in
    true | false) ;;
    *) fail "$1 must be 'true' or 'false'" ;;
  esac
}

# Split a whitespace-separated list into the array 'words', without
# pathname expansion.
split_words() {
  words=()
  read -r -d '' -a words <<< "$1" || true
}

# Check one advisory ID from SOURCE (an input name, or an allow-list
# line) and add it to ignore_ids; dedupe_ignore_ids drops repeats.
# Rejected values are not echoed, except an alias, which has just
# matched a strict pattern.
add_ignore_id() {
  local source="$1" id="$2"
  if [[ ! "$id" =~ $advisory_id_re ]]; then
    if [[ "$id" =~ $alias_id_re ]]; then
      fail "$source: $id is an alias. cargo-audit matches ignores against RUSTSEC IDs alone, so name the RUSTSEC advisory that lists this alias"
    fi
    fail "$source: an entry is not a RUSTSEC advisory ID of the form RUSTSEC-YYYY-NNNN (upper case)"
  fi
  ignore_ids+=("$id")
}

# Keep the first of each ID in ignore_ids, in order. One pass, so a
# large allow-list stays fast.
dedupe_ignore_ids() {
  local id
  local -a unique=()
  if [ "${#ignore_ids[@]}" -gt 0 ]; then
    while IFS= read -r id; do
      unique+=("$id")
    done < <(printf '%s\n' "${ignore_ids[@]}" | awk '!seen[$0]++')
  fi
  ignore_ids=(${unique[@]+"${unique[@]}"})
  if [ "${#ignore_ids[@]}" -gt "$ignore_ids_max" ]; then
    fail "ignore_vulns and allow_list_path together name more than $ignore_ids_max distinct advisory IDs"
  fi
}

# Set 'choices' to the words of LIST, an input named NAME, once each
# and in order. Every word must appear in ALLOWED.
parse_choice_list() {
  local name="$1" allowed="$3" word kept
  choices=()
  split_words "$2"
  for word in ${words[@]+"${words[@]}"}; do
    case " $allowed " in
      *" $word "*) ;;
      *) fail "$name may contain only: $allowed" ;;
    esac
    for kept in ${choices[@]+"${choices[@]}"}; do
      if [ "$kept" = "$word" ]; then
        continue 2
      fi
    done
    choices+=("$word")
  done
}

resolve_against() {
  case "$2" in
    /*) printf '%s' "$2" ;;
    *) printf '%s/%s' "$1" "$2" ;;
  esac
}

require_within_workspace() {
  case "$2/" in
    "$workspace_real"/*) ;;
    *) fail "$1 must resolve within the workspace" ;;
  esac
}

# Resolve FILE, an input named NAME given relative to the project
# directory, to a canonical path in 'resolved_file'. It must be a
# regular file, not a symlink, inside the workspace.
resolve_project_file() {
  local name="$1" file="$2" dir
  case "$file" in
    /*) fail "$name must be relative to path_prefix" ;;
  esac
  file="$project_dir/$file"
  if [ -L "$file" ]; then
    fail "$name must not be a symlink"
  fi
  if [ ! -f "$file" ]; then
    fail "$name does not name a file below path_prefix"
  fi
  dir="$(cd -- "$(dirname -- "$file")" && pwd -P)"
  resolved_file="$dir/$(basename -- "$file")"
  require_within_workspace "$name" "$resolved_file"
}

# Read allow-list entries: one RUSTSEC ID per line. '#' opens a comment
# at the start of a line or after whitespace; elsewhere it stays part
# of the entry, which then fails validation. Blank lines, a UTF-8 byte
# order mark and CRLF line endings are accepted.
parse_allow_list() {
  local file="$1" line number=0 token before size
  size="$(wc -c < "$file" | tr -d ' ')"
  if [ "$size" -gt "$allow_list_max_bytes" ]; then
    fail "allow_list_path is larger than $allow_list_max_bytes bytes"
  fi
  before="${#ignore_ids[@]}"
  while IFS= read -r line || [ -n "$line" ]; do
    number=$((number + 1))
    line="${line%$'\r'}"
    if [ "$number" -eq 1 ]; then
      line="${line#$'\xef\xbb\xbf'}"
    fi
    case "$line" in
      \#*) continue ;;
    esac
    line="${line%%[[:space:]]#*}"
    split_words "$line"
    for token in ${words[@]+"${words[@]}"}; do
      allow_list_count=$((allow_list_count + 1))
      add_ignore_id "allow_list_path line $number" "$token"
    done
  done < "$file"
  dedupe_ignore_ids
  if [ "$allow_list_count" -eq 0 ]; then
    fail "allow_list_path holds no advisory IDs"
  fi
  echo "Allow-list: $(count_of "$allow_list_count" entry entries)," \
    "$((${#ignore_ids[@]} - before)) not already in ignore_vulns"
}

validate_inputs() {
  local word name
  require_boolean lockfile_required "$lockfile_required"
  require_boolean permit_fail "$permit_fail"
  require_boolean summary "$summary"
  require_boolean deny_enabled "$deny_enabled"
  require_boolean artefact_upload "$artefact_upload"
  if [[ ! "$artefact_name" =~ $artefact_name_re ]]; then
    fail "artefact_name must be non-empty and contain only A-Z a-z 0-9 . _ -"
  fi
  if [ -n "$toolchain_input" ] && [[ ! "$toolchain_input" =~ $channel_re ]]; then
    fail "toolchain must be a rustup channel name (A-Z a-z 0-9 . _ + -)"
  fi

  if [[ ! "$cargo_audit_version" =~ $version_re ]]; then
    fail "cargo_audit_version must be a release version such as $default_cargo_audit_version"
  fi
  if [[ ! "$cargo_deny_version" =~ $version_re ]]; then
    fail "cargo_deny_version must be a release version such as $default_cargo_deny_version"
  fi

  parse_choice_list deny_warnings "$deny_warnings" "unmaintained unsound yanked"
  denied_kinds=(${choices[@]+"${choices[@]}"})
  parse_choice_list deny_checks "$deny_checks" "advisories bans licenses sources"
  deny_check_list=(${choices[@]+"${choices[@]}"})
  if [ "$deny_enabled" = "true" ] && [ "${#deny_check_list[@]}" -eq 0 ]; then
    fail "deny_checks must name at least one check when deny_enabled is 'true'"
  fi

  split_words "$ignore_vulns"
  for word in ${words[@]+"${words[@]}"}; do
    add_ignore_id ignore_vulns "$word"
  done
  dedupe_ignore_ids

  # Checked before any $(...) can drop a trailing newline from a path.
  for name in path_prefix manifest_path allow_list_path artefact_path; do
    if [[ "${!name}" =~ [[:cntrl:]] ]]; then
      fail "$name must not contain control characters"
    fi
  done

  workspace="${GITHUB_WORKSPACE:-$PWD}"
  if ! workspace_real="$(cd -- "$workspace" 2> /dev/null && pwd -P)"; then
    fail "GITHUB_WORKSPACE is not a directory"
  fi
  project_dir="$(resolve_against "$workspace_real" "$path_prefix")"
  if ! project_dir="$(cd -- "$project_dir" 2> /dev/null && pwd -P)"; then
    fail "path_prefix is not a directory"
  fi
  require_within_workspace path_prefix "$project_dir"

  case "$manifest_path" in
    Cargo.toml | */Cargo.toml) ;;
    *) fail "manifest_path must name a Cargo.toml file" ;;
  esac
  resolve_project_file manifest_path "$manifest_path"
  manifest_abs="$resolved_file"
  manifest_dir="$(dirname -- "$manifest_abs")"
  manifest_display="${manifest_abs#"$workspace_real"/}"

  if [ -n "$allow_list_path" ]; then
    resolve_project_file allow_list_path "$allow_list_path"
    parse_allow_list "$resolved_file"
  fi

  if [ -n "$artefact_path" ]; then
    resolve_artefact_dir
    require_uploadable_dir artefact_path
    require_empty_artefact_dir
  fi
}

# Resolve artefact_path, relative to path_prefix, to 'artefact_dir'. It
# need not exist yet: the deepest part that exists is canonicalised, so
# a symlinked directory on the way counts by its target, and the rest
# may hold only plain names, which mkdir creates as real directories.
resolve_artefact_dir() {
  local candidate rest="" part existing
  candidate="$(resolve_against "$project_dir" "$artefact_path")"
  while [[ "$candidate" == */ ]]; do
    candidate="${candidate%/}"
  done
  if [ -L "$candidate" ]; then
    fail "artefact_path must not be a symlink"
  fi
  while [ ! -e "$candidate" ] && [ ! -L "$candidate" ]; do
    part="${candidate##*/}"
    case "$part" in
      "" | . | ..)
        fail "artefact_path may not use '.', '..' or '//' below a directory that does not exist yet"
        ;;
    esac
    rest="$part${rest:+/$rest}"
    candidate="${candidate%/*}"
  done
  if ! existing="$(cd -- "$candidate" 2> /dev/null && pwd -P)"; then
    fail "artefact_path must name a directory"
  fi
  artefact_dir="$existing${rest:+/$rest}"
  case "$artefact_dir" in
    "$workspace_real"/*) ;;
    *) fail "artefact_path must resolve to a directory below the workspace" ;;
  esac
}

# Succeeds when directory $1 holds any entry, hidden ones included.
# Bash builtins alone: a listing captured with $(...) loses trailing
# newlines, so a file named only a newline would read as no entry, and
# a command found on PATH may not be the system's.
dir_has_entries() (
  shopt -s nullglob dotglob
  entries=("$1"/*)
  [ "${#entries[@]}" -gt 0 ]
)

require_empty_artefact_dir() {
  if [ ! -e "$artefact_dir" ]; then
    return 0
  fi
  # A glob in a directory it cannot read matches nothing.
  if [ ! -r "$artefact_dir" ] || [ ! -x "$artefact_dir" ]; then
    fail "artefact_path must be a directory this action can read"
  fi
  if dir_has_entries "$artefact_dir"; then
    fail "artefact_path must be an empty or absent directory, so that the artefact holds only this run's reports"
  fi
}

# upload-artifact reads its path as a glob pattern, one per line, with
# outer whitespace trimmed: the directory must read literally. SOURCE
# names what chose the directory.
require_uploadable_dir() {
  case "$artefact_dir" in
    *[][*?\\]* | *[[:cntrl:]]* | *[[:space:]])
      fail "$1 must give a directory path without * ? [ ] backslashes, control characters or trailing spaces"
      ;;
  esac
}

### Running tools ###

# Run a command from DIR, pinned to the resolved toolchain, without the
# scrubbed variables. Every cargo, rustup and audit tool call goes
# through here.
run_in() {
  local dir="$1" name
  shift
  local -a pin=() unset_args=()
  if [ -n "$toolchain_pin" ]; then
    pin=("RUSTUP_TOOLCHAIN=$toolchain_pin")
  fi
  for name in "${scrubbed_variables[@]}"; do
    unset_args+=(-u "$name")
  done
  while IFS= read -r name; do
    if [[ "$name" =~ ^CARGO_REGISTRIES_.+_TOKEN$ ]]; then
      unset_args+=(-u "$name")
    fi
  done < <(compgen -e)
  (
    cd -- "$dir"
    exec env "${unset_args[@]}" ${pin[@]+"${pin[@]}"} "$@"
  )
}

# Print tool output from stdin with LABEL on every line. The runner
# trims leading whitespace before it looks for a '::' workflow command,
# so the label, not indentation, keeps that form inert. The runner also
# ends a line at a bare carriage return, which would start a line
# without the label, and parses the legacy '##[command]' form anywhere
# in a line, so both are neutralised first.
label_lines() {
  sed -e $'s/\r$//' | tr '\r' '\n' | sed -e 's/##\[/# #[/g' -e "s/^/  $1: /"
}

# Print a tool's captured stderr, labelled.
show_log() {
  if [ -s "$2" ]; then
    label_lines "$1" < "$2"
  fi
}

# Print the version from a tool's 'NAME X.Y.Z' version line, if valid.
tool_version() {
  local line
  if ! line="$(run_in "$work_dir" "$1" --version 2> /dev/null)"; then
    return 0
  fi
  line="${line%%$'\n'*}"
  line="${line##* }"
  if [[ "$line" =~ $version_re ]]; then
    printf '%s' "$line"
  fi
}

require_tool_version() {
  local tool="$1" expected="$2" found
  if ! command -v "$tool" > /dev/null 2>&1; then
    fail "$tool not found on PATH; check the install step"
  fi
  found="$(tool_version "$tool")"
  if [ "$found" != "$expected" ]; then
    fail "$tool reports version '${found:-unknown}', expected $expected"
  fi
}

check_tools() {
  stage="Check tools"
  if ! command -v jq > /dev/null 2>&1; then
    fail "required tool not found on PATH: jq"
  fi
  require_tool_version cargo-audit "$cargo_audit_version"
  if [ "$deny_enabled" = "true" ]; then
    require_tool_version cargo-deny "$cargo_deny_version"
  fi
}

# Set variable VAR to the second word of TOOL's 'TOOL X.Y.Z (...)'
# version line when it is a Rust release, and fail otherwise.
read_rust_version() {
  local tool="$1" line word
  if ! line="$(run_in "$manifest_dir" "$tool" --version 2> /dev/null)"; then
    fail "$tool --version failed for the selected toolchain"
  fi
  line="${line%%$'\n'*}"
  word="${line#"$tool" }"
  word="${word%% *}"
  if [[ ! "$word" =~ $rust_version_re ]]; then
    fail "$tool --version reported an unexpected version"
  fi
  printf -v "$2" '%s' "$word"
}

# Resolve the toolchain once and pin every later call to it, wherever
# that call runs from. The toolchain input names a rustup channel;
# without it, rustup names the toolchain the project selects, without
# running it. A path toolchain, from a rust-toolchain file naming a
# directory, runs unpinned from the project directory.
resolve_toolchain() {
  stage="Resolve toolchain"
  local active
  if ! command -v cargo > /dev/null 2>&1; then
    fail "required tool not found on PATH: cargo"
  fi
  if ! command -v rustup > /dev/null 2>&1; then
    if [ -n "$toolchain_input" ]; then
      fail "toolchain needs rustup, which is not on PATH"
    fi
    toolchain_kind="none"
  elif [ -n "$toolchain_input" ]; then
    toolchain="$toolchain_input"
    toolchain_kind="channel"
    toolchain_pin="$toolchain"
  else
    if ! active="$(run_in "$manifest_dir" rustup show active-toolchain 2> /dev/null)"; then
      fail "rustup could not name the project's active toolchain; set the toolchain input or install the one the project selects"
    fi
    # Kept whole: a newline in a path must fail below, not cut it short.
    if [[ "$active" =~ $toolchain_reason_re ]]; then
      active="${BASH_REMATCH[1]}"
    else
      active="${active% (*}"
    fi
    case "$active" in
      /*)
        if [[ "$active" =~ [[:cntrl:]] ]]; then
          fail "rustup named a toolchain path this action cannot report"
        fi
        toolchain="$active"
        toolchain_kind="path"
        warn "The project selects a toolchain by path; cargo runs unpinned from the project directory"
        ;;
      *)
        if [[ ! "$active" =~ $channel_re ]]; then
          fail "rustup named a toolchain this action cannot pin"
        fi
        toolchain="$active"
        toolchain_kind="channel"
        toolchain_pin="$active"
        ;;
    esac
  fi
  read_rust_version cargo cargo_version
  read_rust_version rustc rustc_version
  # A path toolchain is the project's choice, so label it like tool output.
  printf '%s (cargo %s, rustc %s)\n' "${toolchain:-cargo on PATH}" \
    "$cargo_version" "$rustc_version" | label_lines Toolchain
}

### Lockfile ###

# From here on, tools have run, and a path toolchain is the project's
# own code: either could plant programs on PATH. The checks that keep
# files inside the workspace therefore use bash builtins alone.

locate_lockfile() {
  stage="Locate lockfile"
  local root display log="$work_dir/cargo.log"
  if ! root="$(run_in "$manifest_dir" cargo locate-project --workspace \
    --locked --manifest-path "$manifest_abs" --message-format plain \
    2> "$log")"; then
    show_log cargo "$log"
    fail "cargo could not locate the workspace for manifest_path"
  fi
  case "$root" in
    *$'\n'* | *$'\r'*) fail "cargo named an unexpected workspace manifest" ;;
    /*/Cargo.toml) ;;
    *) fail "cargo named an unexpected workspace manifest" ;;
  esac
  if ! workspace_root="$(cd -- "${root%/Cargo.toml}" 2> /dev/null && pwd -P)"; then
    fail "the Cargo workspace root is not a directory"
  fi
  require_within_workspace "The Cargo workspace root" "$workspace_root"
  lockfile="$workspace_root/Cargo.lock"
  display="${lockfile#"$workspace_real"/}"
  if [ -L "$lockfile" ]; then
    fail "Cargo.lock must not be a symlink"
  fi
  if [ -e "$lockfile" ]; then
    if [ ! -f "$lockfile" ]; then
      fail "Cargo.lock is not a regular file"
    fi
    lockfile_cell="$(md_code "$display")"
    return 0
  fi
  if [ "$lockfile_required" = "true" ]; then
    lockfile_cell="❌ Missing"
    fail "Cargo.lock is missing and lockfile_required is 'true'"
  fi
  warn "Cargo.lock is missing, so the audit covers a freshly generated one: the newest compatible versions, not what the project last locked"
  if ! run_in "$manifest_dir" cargo generate-lockfile \
    --manifest-path "$workspace_root/Cargo.toml" > "$log" 2>&1; then
    show_log cargo "$log"
    fail "cargo generate-lockfile failed"
  fi
  show_log cargo "$log"
  if [ -L "$lockfile" ] || [ ! -f "$lockfile" ]; then
    fail "cargo generate-lockfile did not create Cargo.lock"
  fi
  lockfile_cell="⚠️ $(md_code "$display"), generated by the action"
}

### cargo-audit ###

# jq definitions turning findings into lines of unit-separated fields,
# with control characters flattened to spaces.
readonly jq_row_defs='
  def clean: tostring | gsub("[[:cntrl:]]"; " ");
  def row: map(clean) | join("\u001f");
'

# The report shape the parsing below relies on. Anything else is not a
# report this action can trust, and fails the stage.
readonly jq_report_shape='
  def package: type == "object" and (.package | type == "object");
  type == "object"
  and (.vulnerabilities.list | type == "array")
  and all(.vulnerabilities.list[];
    package and (.advisory | type == "object")
    and (.advisory.id | type == "string"))
  and (.warnings | type == "object")
  and all(.warnings[]; type == "array" and all(.[]; package))
'

advisory_link() {
  if [[ "$1" =~ $advisory_id_re ]]; then
    printf '[%s](https://rustsec.org/advisories/%s.html)' "$1" "$1"
  else
    printf '➖'
  fi
}

run_cargo_audit() {
  stage="Audit with cargo-audit"
  local status=0 id kind name version title patched level row_count=0
  local log="$work_dir/cargo-audit.log" report="$work_dir/cargo-audit.json"
  local -a args=(audit --json --file "$lockfile")
  for id in ${ignore_ids[@]+"${ignore_ids[@]}"}; do
    args+=(--ignore "$id")
  done
  for kind in ${denied_kinds[@]+"${denied_kinds[@]}"}; do
    args+=(--deny "$kind")
  done
  echo "Running cargo-audit $cargo_audit_version"
  # cargo-audit reads .cargo/audit.toml from its working directory, so
  # run it from the workspace root, as a developer would.
  run_in "$workspace_root" cargo-audit "${args[@]}" \
    > "$report" 2> "$log" || status=$?
  show_log cargo-audit "$log"
  # cargo-audit reports a failed per-crate yanked lookup on stderr alone
  # and still exits 0 with a report that lacks that crate.
  local yank_failures
  yank_failures="$(grep -cF "couldn't check if the package is yanked" "$log" || true)"

  if ! jq -e "$jq_report_shape" "$report" > /dev/null 2>&1; then
    audit_cell="❌ No report"
    fail "cargo-audit produced no report (exit status $status); see the step log"
  fi
  # The parsing below reads the work copy, which nothing else can reach.
  store_report "$report" cargo-audit.json
  report_path="$stored_report"
  if [ "$status" -ne 0 ] && [ "$status" -ne 1 ]; then
    audit_cell="❌ Exit status $status"
    fail "cargo-audit exited with status $status"
  fi

  local db_count db_date deps
  db_count="$(jq -r '.database."advisory-count"? // empty' "$report")"
  db_date="$(jq -r '.database."last-updated"? // empty | tostring' "$report")"
  deps="$(jq -r '.lockfile."dependency-count"? // empty' "$report")"
  audit_cell="$(md_code "$cargo_audit_version")"
  if [[ "$db_count" =~ ^[0-9]+$ ]]; then
    audit_cell="$audit_cell; $(count_of "$db_count" advisory advisories)"
    if [ -n "$db_date" ]; then
      audit_cell="$audit_cell, updated $(md_text "${db_date%%T*}")"
    fi
  fi
  if [[ "$deps" =~ ^[0-9]+$ ]]; then
    lockfile_cell="$lockfile_cell; $(count_of "$deps" package packages)"
  fi

  # Advisory IDs reach outputs and links, so every one must be valid.
  local -a ids=()
  while IFS= read -r id; do
    if [[ ! "$id" =~ $advisory_id_re ]]; then
      vulnerability_cell="❌ Unrecognised advisory ID"
      fail "cargo-audit reported an advisory ID outside the form RUSTSEC-YYYY-NNNN"
    fi
    ids+=("$id")
  done < <(jq -r '.vulnerabilities.list[].advisory.id
    | gsub("[[:cntrl:]]"; " ")' "$report")
  vulnerability_count="${#ids[@]}"
  if [ "$vulnerability_count" -ne "$(jq '.vulnerabilities.list | length' "$report")" ]; then
    fail "cargo-audit's report could not be read consistently"
  fi
  vulnerability_ids="$(printf '%s\n' ${ids[@]+"${ids[@]}"} \
    | awk 'NF && !seen[$0]++' | paste -s -d ' ' -)"

  level="$(failure_level)"
  while IFS=$'\x1f' read -r id name version title patched; do
    row_count=$((row_count + 1))
    if [ "$row_count" -le "$table_row_limit" ]; then
      vulnerability_rows+=("| $(advisory_link "$id") | $(md_code "$name") | $(md_text "$version") | $(md_text "$title") | $(md_text "${patched:-None}") |")
      annotate "$level" "$id" "$name $version: $title. Patched versions: ${patched:-none}"
    fi
  done < <(jq -r "$jq_row_defs"'
    .vulnerabilities.list[]
    | [.advisory.id, .package.name, .package.version, (.advisory.title // ""),
       ((.versions.patched? // []) | map(tostring) | join(", "))] | row' \
    "$report")
  if [ "$row_count" -gt "$table_row_limit" ]; then
    vulnerability_rows+=("| ➖ | $((row_count - table_row_limit)) more | ➖ | See the report | ➖ |")
  fi

  # Warnings: unmaintained, unsound, yanked, and any other kind the
  # database adds. Yanked crates carry no advisory.
  local total denied=0 count denied_list="" kinds_text=""
  total="$(jq '[.warnings[][]] | length' "$report")"
  warning_count="$total"
  row_count=0
  while IFS=$'\x1f' read -r kind id name version title; do
    row_count=$((row_count + 1))
    if [ "$row_count" -le "$table_row_limit" ]; then
      warning_rows+=("| $(md_text "$kind") | $(advisory_link "$id") | $(md_code "$name") | $(md_text "$version") | $(md_text "$title") |")
      annotate warning "$kind: $name $version" "${title:-$kind}"
    fi
  done < <(jq -r "$jq_row_defs"'
    .warnings | to_entries[] | .key as $kind | .value[]
    | [$kind, (.advisory.id? // ""), .package.name, .package.version,
       (.advisory.title? // (if $kind == "yanked"
         then "Yanked from its registry" else "" end))] | row' \
    "$report")
  if [ "$row_count" -gt "$table_row_limit" ]; then
    warning_rows+=("| ➖ | ➖ | $((row_count - table_row_limit)) more | ➖ | See the report |")
  fi
  kinds_text="$(jq -r '.warnings | to_entries
    | map(select(.value | length > 0) | "\(.value | length) \(.key)")
    | join(", ")' "$report")"
  for kind in ${denied_kinds[@]+"${denied_kinds[@]}"}; do
    count="$(jq --arg k "$kind" '(.warnings[$k] // []) | length' "$report")"
    if [ "$count" -gt 0 ]; then
      denied=$((denied + count))
      denied_list="${denied_list:+$denied_list, }$kind"
    fi
  done

  # Ignores beyond the action's own come from the project's config.
  local extra
  extra="$(jq -r --args '(.settings.ignore? // [])
    | map(select(type == "string")) - $ARGS.positional | join(" ")' \
    ${ignore_ids[@]+"${ignore_ids[@]}"} < "$report")"
  if [ "${#ignore_ids[@]}" -gt 0 ]; then
    ignored_cell="${#ignore_ids[@]}: $(md_text "${ignore_ids[*]}")"
  fi
  if [ -n "$extra" ]; then
    warn "The project's cargo-audit configuration ignores further advisories: $extra"
  fi

  if [ "$vulnerability_count" -gt 0 ]; then
    vulnerability_cell="❌ $vulnerability_count found"
  else
    vulnerability_cell="✅ None found"
  fi
  if [ "$total" -eq 0 ]; then
    warning_cell="✅ None"
  elif [ "$denied" -gt 0 ]; then
    warning_cell="❌ $(md_text "$kinds_text"); denied: $(md_text "$denied_list")"
  else
    warning_cell="⚠️ $(md_text "$kinds_text"); none denied"
  fi

  if [ "$vulnerability_count" -gt 0 ]; then
    audit_reason="cargo-audit found $(count_of "$vulnerability_count" vulnerability vulnerabilities): $vulnerability_ids."
  fi
  if [ "$denied" -gt 0 ]; then
    audit_reason="${audit_reason:+$audit_reason }deny_warnings fails the run on $(count_of "$denied" warning warnings) ($denied_list)."
  fi
  if [ "$yank_failures" -gt 0 ]; then
    local yank_note
    yank_note="cargo-audit could not check $(count_of "$yank_failures" crate crates) for yanked releases; see the step log."
    warning_cell="$warning_cell; ⚠️ yanked check incomplete"
    case " ${denied_kinds[*]-} " in
      *" yanked "*)
        audit_reason="${audit_reason:+$audit_reason }$yank_note deny_warnings names yanked, so the audit is incomplete."
        ;;
      *) warn "$yank_note" ;;
    esac
  fi
  if [ -z "$audit_reason" ] && [ "$status" -ne 0 ]; then
    audit_reason="cargo-audit exited with status $status without a finding this action gates on; the project's .cargo/audit.toml may deny further warnings."
  fi
  if [ -n "$audit_reason" ]; then
    audit_outcome="failed"
  else
    audit_outcome="passed"
  fi
}

### cargo-deny ###

# Use the first deny.toml, .deny.toml or .cargo/deny.toml found from
# the manifest's directory up to the project directory, stopping at the
# workspace root. Without one, hand cargo-deny an empty file: its
# defaults then apply, as when it finds no configuration, but no file
# outside the project can stand in.
find_deny_config() {
  local dir="$manifest_dir" name candidate
  while :; do
    for name in deny.toml .deny.toml .cargo/deny.toml; do
      candidate="$dir/$name"
      if [ -e "$candidate" ] || [ -L "$candidate" ]; then
        require_contained_config "$candidate"
        deny_config="$resolved_file"
        deny_config_cell="$(md_code "${resolved_file#"$workspace_real"/}")"
        return 0
      fi
    done
    if [ "$dir" = "$project_dir" ] || [ "$dir" = "$workspace_real" ]; then
      break
    fi
    dir="${dir%/*}"
    dir="${dir:-/}"
  done
  deny_config="$work_dir/default-deny.toml"
  : > "$deny_config"
  deny_config_cell="cargo-deny defaults"
  warn "No deny.toml found, so cargo-deny runs with its defaults, whose licence allow-list is empty: the licenses check then rejects every crate"
}

# CANDIDATE, a configuration file found by search, must be a regular
# file, not a symlink, whose canonical path ('resolved_file') lies
# inside the workspace: a symlinked '.cargo' directory could otherwise
# point outside it.
require_contained_config() {
  local candidate="$1" shown="${1#"$workspace_real"/}" dir
  if [ -L "$candidate" ] || [ ! -f "$candidate" ]; then
    fail "$shown must be a regular file, not a symlink"
  fi
  dir="$(cd -- "${candidate%/*}" && pwd -P)"
  resolved_file="$dir/${candidate##*/}"
  require_within_workspace "$shown" "$resolved_file"
}

# cargo-deny loads licence exceptions from the first exceptions file it
# finds beside the manifest or in ANY ancestor directory, whatever
# --config names. Find that file the same way and accept it only from
# inside the workspace, so nothing above the checkout can exempt crates.
check_deny_exceptions() {
  local dir="$manifest_dir" name candidate
  deny_exceptions_cell=""
  while :; do
    for name in deny.exceptions.toml .deny.exceptions.toml \
      .cargo/deny.exceptions.toml; do
      candidate="$dir/$name"
      if [ -e "$candidate" ] || [ -L "$candidate" ]; then
        case "$candidate" in
          "$workspace_real"/*) ;;
          *) fail "cargo-deny would load licence exceptions from $candidate, outside the workspace" ;;
        esac
        require_contained_config "$candidate"
        deny_exceptions_cell="; exceptions: $(md_code "${resolved_file#"$workspace_real"/}")"
        return 0
      fi
    done
    if [ "$dir" = "/" ]; then
      return 0
    fi
    dir="${dir%/*}"
    dir="${dir:-/}"
  done
}

run_cargo_deny() {
  stage="Check with cargo-deny"
  local status=0 log="$work_dir/cargo-deny.jsonl" results check errors
  local text="$work_dir/cargo-deny.txt" failed_checks="" passed_checks=""
  deny_outcome="failed"
  find_deny_config
  check_deny_exceptions
  echo "Running cargo-deny $cargo_deny_version: ${deny_check_list[*]}"
  run_in "$manifest_dir" cargo-deny --format json --color never \
    --manifest-path "$manifest_abs" --config "$deny_config" --locked \
    check "${deny_check_list[@]}" 2> "$log" > /dev/null || status=$?

  # cargo-deny writes JSON lines to stderr; print them readably, and
  # keep both forms as reports, whatever the outcome. A clean run with
  # a config emits only the summary, so it gets a line per check.
  jq -R -r 'def clean: tostring | gsub("[[:cntrl:]]"; " ");
    . as $line
    | ((fromjson? | objects | select(.fields | type == "object"))
       // {type: "raw", fields: {message: $line}})
    | if .type == "diagnostic" then
        "\(.fields.severity // "note" | clean)[\(.fields.code // "" | clean)]: \(.fields.message // "" | clean)"
        + ((try .fields.graphs[0].Krate catch null)
           | if type == "object"
             then " (\(.name // "" | clean) \(.version // "" | clean))"
             else "" end)
      elif .type == "summary" then
        .fields | to_entries[]
        | "summary: \(.key | clean): "
          + (.value | if type == "object"
              then [to_entries[] | "\(.key | clean) \(.value | clean)"]
                | join(", ")
              else clean end)
      else "\(.fields.level // "output" | clean): \(.fields.message // "" | clean)"
      end' "$log" > "$text"
  label_lines cargo-deny < "$text"
  if [ -s "$log" ]; then
    store_report "$log" cargo-deny.jsonl
    deny_report_path="$stored_report"
    store_report "$text" cargo-deny.txt
  fi

  results="$(jq -R -c 'fromjson? | objects | select(.type == "summary")
    | .fields | objects' "$log" | tail -n 1)"
  if [ -z "$results" ]; then
    deny_cell="❌ No result (exit status $status)"
    fail "cargo-deny produced no summary (exit status $status); see the step log"
  fi
  for check in "${deny_check_list[@]}"; do
    errors="$(jq -r --arg c "$check" 'if has($c) then
        (.[$c] | if type == "object" and (.errors | type) == "number"
          then .errors else "unknown" end)
      else "missing" end' <<< "$results")"
    if [[ "$errors" =~ ^[0-9]+$ ]] && [ "$errors" -eq 0 ]; then
      passed_checks="${passed_checks:+$passed_checks, }$check"
    elif [[ "$errors" =~ ^[0-9]+$ ]]; then
      failed_checks="${failed_checks:+$failed_checks, }$check ($(count_of "$errors" error errors))"
    else
      failed_checks="${failed_checks:+$failed_checks, }$check (no result)"
    fi
  done
  if [ -z "$failed_checks" ] && [ "$status" -ne 0 ]; then
    failed_checks="exit status $status"
  fi
  if [ -n "$failed_checks" ]; then
    deny_reason="cargo-deny failed: $failed_checks."
    deny_cell="❌ Failed: $failed_checks"
    if [ -n "$passed_checks" ]; then
      deny_cell="$deny_cell; passed: $passed_checks"
    fi
    annotate "$(failure_level)" "cargo-deny" "Failed: $failed_checks"
  else
    deny_outcome="passed"
    deny_cell="✅ Passed: $passed_checks"
  fi
  deny_cell="$deny_cell; config: $deny_config_cell$deny_exceptions_cell"
}

### Main ###

# Create the report directory: artefact_path, checked again now that it
# exists, or a fresh directory under RUNNER_TEMP.
prepare_artefact_dir() {
  if [ -z "$artefact_path" ]; then
    if ! artefact_dir="$(mktemp -d "$temp_root/rust-audit-results.XXXXXX")"; then
      artefact_dir=""
      fail "could not create a report directory under RUNNER_TEMP"
    fi
    require_uploadable_dir RUNNER_TEMP
  else
    # A symlink swapped in, here or above, changes the canonical path.
    if ! mkdir -p -- "$artefact_dir" \
      || [ "$(cd -- "$artefact_dir" && pwd -P)" != "$artefact_dir" ]; then
      fail "artefact_path could not be created as a directory inside the workspace"
    fi
    require_empty_artefact_dir
  fi
  artefact_display="${artefact_dir#"$workspace_real"/}"
}

# Copy report SOURCE into the report directory as NAME, setting
# 'stored_report'. That directory was empty when the run began, so a
# NAME already there came from elsewhere and is not overwritten.
# Under noclobber, bash opens a missing target with O_CREAT|O_EXCL,
# which refuses any entry that appears first, a dangling symlink
# included, and never follows it; an existing regular file, or a
# symlink to one, is refused before opening. A check-then-cp would
# leave a window in which cp writes through a planted symlink. Only a
# symlink to an existing non-regular file (a FIFO or device) is opened
# without O_EXCL; the type check after the write fails the run then.
store_report() {
  local target="$artefact_dir/$2" bytes
  if ! (set -o noclobber && cat -- "$1" > "$target") 2> /dev/null; then
    if [ -e "$target" ] || [ -L "$target" ]; then
      fail "$2 appeared in the report directory before the action wrote it"
    fi
    fail "could not write $2 to the report directory"
  fi
  if [ -L "$target" ] || [ ! -f "$target" ]; then
    fail "$2 in the report directory is not a regular file"
  fi
  stored_report="$target"
  bytes="$(wc -c < "$target" | tr -d ' ')"
  reports_cell="${reports_cell:+$reports_cell, }$(md_code "$2") ($(human_size "$bytes"))"
}

validate_inputs

if [ "$phase" = "check" ]; then
  tools="cargo-audit@$cargo_audit_version"
  if [ "$deny_enabled" = "true" ]; then
    tools="$tools,cargo-deny@$cargo_deny_version"
  fi
  set_output tools "$tools"
  echo "Inputs valid; tools to install: $tools"
  exit 0
fi

# Inputs are well formed, so from here on permit_fail applies.
failures_permitted="$permit_fail"

# A failed install still reaches this step (action.yaml continues on
# error). Tools of the requested versions may already be on PATH, but
# they are not the ones this run installed and verified, so the install
# failure stands, as an error or, under permit_fail, a warning.
if [ "${INSTALL_OUTCOME:-}" = "failure" ]; then
  stage="Install audit tools"
  fail "$install_failure_reason"
fi

stage="Prepare"
temp_root="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
if ! work_dir="$(mktemp -d "$temp_root/rust-audit.XXXXXX")"; then
  work_dir=""
  fail "could not create a temporary directory"
fi
prepare_artefact_dir

resolve_toolchain
check_tools
locate_lockfile
run_cargo_audit
if [ "$deny_enabled" = "true" ]; then
  run_cargo_deny
fi

if [ "$audit_outcome" = "failed" ] && [ "$deny_outcome" = "failed" ]; then
  stage="Audit with cargo-audit and cargo-deny"
elif [ "$audit_outcome" = "failed" ]; then
  stage="Audit with cargo-audit"
fi
if [ -n "$audit_reason$deny_reason" ]; then
  fail "$audit_reason${audit_reason:+${deny_reason:+ }}$deny_reason"
fi
echo "Audit passed"
