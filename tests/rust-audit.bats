#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

# Unit tests for scripts/rust-audit.sh, run against stand-ins for
# cargo, rustup, cargo-audit and cargo-deny (tests/stubs/) that replay
# output captured from the real tools (tests/fixtures/). No network
# access or compilation.

# Each @test runs in its own subshell and setup() resets the state, so
# variables exported inside one test stay local to it.
# shellcheck disable=SC2030,SC2031

bats_require_minimum_version 1.7.0

setup() {
  repo_dir="$(cd "$BATS_TEST_DIRNAME/.." && pwd -P)"
  script="$repo_dir/scripts/rust-audit.sh"
  action_file="$repo_dir/action.yaml"
  fixtures="$BATS_TEST_DIRNAME/fixtures"
  mkdir -p "$BATS_TEST_TMPDIR/work space"
  workdir="$(cd "$BATS_TEST_TMPDIR/work space" && pwd -P)"
  project="$workdir/my project"
  bin="$workdir/bin"
  mkdir -p "$bin" "$project" "$workdir/runner temp"
  local tool
  for tool in cargo rustc rustup cargo-audit cargo-deny; do
    cp "$BATS_TEST_DIRNAME/stubs/$tool.sh" "$bin/$tool"
    chmod +x "$bin/$tool"
  done
  cp "$BATS_TEST_DIRNAME/stubs/record.sh" "$bin/record.sh"
  printf '%s\n' '[package]' 'name = "example"' 'version = "0.1.0"' \
    'edition = "2021"' > "$project/Cargo.toml"
  printf '%s\n' 'version = 4' > "$project/Cargo.lock"

  # Keep any real Rust tool out of reach, so only stand-ins can run.
  local dir kept="$bin"
  local -a dirs=()
  IFS=: read -r -a dirs <<< "$PATH"
  for dir in "${dirs[@]}"; do
    for tool in cargo rustc rustup cargo-audit cargo-deny; do
      if [ -e "$dir/$tool" ]; then
        continue 2
      fi
    done
    kept="$kept:$dir"
  done
  export PATH="$kept"

  export GITHUB_WORKSPACE="$workdir"
  export GITHUB_OUTPUT="$workdir/github output"
  export GITHUB_STEP_SUMMARY="$workdir/job summary"
  export GITHUB_ENV="$workdir/github env"
  export GITHUB_PATH="$workdir/github path"
  export GITHUB_STATE="$workdir/github state"
  export RUNNER_TEMP="$workdir/runner temp"
  export INPUT_PATH_PREFIX="my project"
  export MOCK_EXPECT_MANIFEST="$project/Cargo.toml"
  export MOCK_TOOL_LOG="$workdir/tool calls"
  export MOCK_VERSION_LOG="$workdir/version calls"
  export MOCK_AUDIT_ARGS="$workdir/audit args"
  export MOCK_DENY_ARGS="$workdir/deny args"
  export MOCK_AUDIT_REPORT="$fixtures/audit-clean.json"
  export MOCK_DENY_LOG="$fixtures/deny-passed.jsonl"
  unset INPUT_MANIFEST_PATH INPUT_LOCKFILE_REQUIRED INPUT_IGNORE_VULNS
  unset INPUT_ALLOW_LIST_PATH INPUT_DENY_WARNINGS INPUT_DENY_ENABLED
  unset INPUT_DENY_CHECKS INPUT_CARGO_AUDIT_VERSION INPUT_CARGO_DENY_VERSION
  unset INPUT_PERMIT_FAIL INPUT_SUMMARY INPUT_TOOLCHAIN
  unset INPUT_ARTEFACT_UPLOAD INPUT_ARTEFACT_NAME INPUT_ARTEFACT_PATH
  unset MOCK_WORKSPACE_MANIFEST MOCK_LOCATE_OUTPUT MOCK_LOCATE_FAIL
  unset MOCK_GENERATE_FAIL MOCK_GENERATE_STDOUT MOCK_TOOLCHAIN MOCK_RUSTUP_FAIL MOCK_CARGO_VERSION
  unset MOCK_RUSTC_VERSION MOCK_RUSTC_FAIL
  unset MOCK_AUDIT_VERSION MOCK_AUDIT_EXIT MOCK_AUDIT_STDOUT MOCK_AUDIT_STDERR
  unset MOCK_AUDIT_PLANT MOCK_AUDIT_PLANT_TO MOCK_PROJECT_IGNORES
  unset MOCK_DENY_VERSION MOCK_DENY_ERRORS
  unset MOCK_DENY_EXIT MOCK_DENY_STDERR RUSTUP_TOOLCHAIN INSTALL_OUTCOME
  export CARGO_REGISTRY_TOKEN="registry-secret"
  export CARGO_REGISTRIES_CRATES_IO_TOKEN="crates-io-secret"
  export ACTIONS_ID_TOKEN_REQUEST_TOKEN="oidc-secret"
  export ACTIONS_ID_TOKEN_REQUEST_URL="https://oidc.example"
  export ACTIONS_RUNTIME_TOKEN="runtime-secret"
  export CARGO_REGISTRIES_PRIVATE_TOKEN="private-registry-secret"
  export CARGO_REGISTRIES_PRIVATE_INDEX="sparse+https://registry.example/"
  : > "$GITHUB_OUTPUT"
  : > "$GITHUB_STEP_SUMMARY"
  : > "$MOCK_TOOL_LOG"
  : > "$MOCK_VERSION_LOG"
}

run_check() {
  run "$BASH" "$script" check
}

run_audit() {
  run "$BASH" "$script" audit
}

# The last value written for output NAME.
output_value() {
  sed -n "s/^$1=//p" "$GITHUB_OUTPUT" | tail -n 1
}

# Tool calls in order, by first field of the call log.
tool_calls() {
  cut -d'|' -f1 "$MOCK_TOOL_LOG" | paste -s -d ' ' -
}

# Field N (1-based) of the recorded call STAGE: 2 working directory,
# 7 RUSTUP_TOOLCHAIN; tests/stubs/record.sh lists the rest.
call_field() {
  awk -F'|' -v stage="$1" -v field="$2" \
    '$1 == stage { print $field }' "$MOCK_TOOL_LOG" | tail -n 1
}

audit_args() {
  paste -s -d ' ' - < "$MOCK_AUDIT_ARGS"
}

deny_args() {
  paste -s -d ' ' - < "$MOCK_DENY_ARGS"
}

# The default declared for INPUT in action.yaml.
action_default() {
  awk -v name="  $1:" '
    $0 == name { found = 1; next }
    found && /^  [a-z]/ { exit }
    found && /default:/ { sub(/.*default: */, ""); gsub(/"/, ""); print; exit }
  ' "$action_file"
}

# Write allow-list CONTENT to FILE below the project directory.
allow_list() {
  printf '%b' "$2" > "$project/$1"
  export INPUT_ALLOW_LIST_PATH="$1"
}

# A findings report whose first vulnerability has the given title.
report_with_title() {
  jq --arg t "$1" '.vulnerabilities.list[0].advisory.title = $t' \
    "$fixtures/audit-findings.json" > "$workdir/report.json"
  export MOCK_AUDIT_REPORT="$workdir/report.json"
}

# The runner reads a line as a workflow command when it starts with
# '::' after leading whitespace, and otherwise parses a legacy
# '##[command]' anywhere in it.
assert_no_injected_command() {
  if printf '%s\n' "$output" | grep -q '^[[:space:]]*::error::injected'; then
    echo "a workflow command escaped into the log" >&2
    return 1
  fi
  if printf '%s\n' "$output" | grep -v '^[[:space:]]*::' | grep -qF '##['; then
    echo "a legacy workflow command escaped into the log" >&2
    return 1
  fi
}

### Check phase ###

@test "check validates defaults and names cargo-audit alone" {
  run_check
  [ "$status" -eq 0 ]
  [ "$(output_value tools)" = "cargo-audit@0.22.2" ]
  [ ! -s "$MOCK_TOOL_LOG" ]
  [ ! -s "$GITHUB_STEP_SUMMARY" ]
}

@test "a valid check publishes outcomes for an install that then fails" {
  export INPUT_DENY_ENABLED=true
  run_check
  [ "$status" -eq 0 ]
  [ "$(output_value audit_outcome)" = "failed" ]
  [ "$(output_value deny_outcome)" = "skipped" ]
}

@test "check names cargo-deny too when enabled, at the requested versions" {
  export INPUT_DENY_ENABLED=true INPUT_CARGO_AUDIT_VERSION=0.21.2
  export INPUT_CARGO_DENY_VERSION=0.19.9
  run_check
  [ "$status" -eq 0 ]
  [ "$(output_value tools)" = "cargo-audit@0.21.2,cargo-deny@0.19.9" ]
}

@test "an unknown phase is a usage error" {
  run "$BASH" "$script" publish
  [ "$status" -eq 2 ]
  [[ "$output" == *"usage: rust-audit.sh check|audit"* ]]
}

@test "action.yaml defaults match the script's" {
  [ "$(action_default cargo_audit_version)" = \
    "$(sed -n 's/^readonly default_cargo_audit_version="\(.*\)"$/\1/p' "$script")" ]
  [ "$(action_default cargo_deny_version)" = \
    "$(sed -n 's/^readonly default_cargo_deny_version="\(.*\)"$/\1/p' "$script")" ]
  [ "$(action_default deny_checks)" = \
    "$(sed -n 's/^readonly default_deny_checks="\(.*\)"$/\1/p' "$script")" ]
  [ "$(action_default permit_fail)" = "false" ]
  [ "$(action_default summary)" = "true" ]
  [ "$(action_default deny_enabled)" = "false" ]
  [ "$(action_default lockfile_required)" = "false" ]
  [ "$(action_default artefact_upload)" = "true" ]
  [ "$(action_default artefact_name)" = \
    "$(sed -n 's/^readonly default_artefact_name="\(.*\)"$/\1/p' "$script")" ]
  [ "$(action_default artefact_path)" = "" ]
  [ "$(action_default toolchain)" = "" ]
}

@test "action.yaml hands every input to both script steps through env" {
  local input count
  local -a inputs=()
  mapfile -t inputs < <(awk '/^inputs:/ { on = 1; next }
    /^outputs:/ { on = 0 } on && /^  [a-z_]+:$/ { sub(/:$/, ""); print $1 }' \
    "$action_file")
  [ "${#inputs[@]}" -eq 16 ]
  for input in "${inputs[@]}"; do
    count="$(grep -c "INPUT_$(printf '%s' "$input" | tr '[:lower:]' '[:upper:]'): \${{ inputs.$input }}" "$action_file")"
    [ "$count" -eq 2 ]
  done
  # Expressions reach shell only through env: no run line holds one.
  run ! grep -E '^\s+run: .*\$\{\{' "$action_file"
}

### Input validation ###

@test "booleans accept exactly 'true' or 'false'" {
  local input value
  for input in LOCKFILE_REQUIRED PERMIT_FAIL SUMMARY DENY_ENABLED ARTEFACT_UPLOAD; do
    for value in yes TRUE "" " true" $'true\n'; do
      export "INPUT_$input=$value"
      run_check
      [ "$status" -eq 1 ]
      [[ "$output" == *"$(printf '%s' "$input" | tr '[:upper:]' '[:lower:]') must be 'true' or 'false'"* ]]
      unset "INPUT_$input"
    done
  done
}

@test "invalid input writes failed outcomes and a summary, with no tool run" {
  export INPUT_DENY_ENABLED=maybe
  run_check
  [ "$status" -eq 1 ]
  [ "$(output_value audit_outcome)" = "failed" ]
  [ "$(output_value deny_outcome)" = "skipped" ]
  [ -z "$(output_value tools)" ]
  [ ! -s "$MOCK_TOOL_LOG" ]
  grep -q '^### ❌ Failed at Check inputs$' "$GITHUB_STEP_SUMMARY"
  grep -q "deny&#95;enabled must be 'true' or 'false'" "$GITHUB_STEP_SUMMARY"
}

@test "invalid input fails even with permit_fail, in either phase" {
  export INPUT_PERMIT_FAIL=true INPUT_IGNORE_VULNS="not-an-id"
  run_check
  [ "$status" -eq 1 ]
  run_audit
  [ "$status" -eq 1 ]
  [ ! -s "$MOCK_TOOL_LOG" ]
  [ "$(output_value audit_outcome)" = "failed" ]
}

@test "summary 'false' suppresses the job summary on failure too" {
  export INPUT_SUMMARY=false INPUT_IGNORE_VULNS="bad"
  run_check
  [ "$status" -eq 1 ]
  [ ! -s "$GITHUB_STEP_SUMMARY" ]
}

@test "tool versions must be plain release versions" {
  local value
  for value in latest 0.22 v0.22.2 "0.22.2 " "0.22.2;id" 0.22.2-rc1 ""; do
    export INPUT_CARGO_AUDIT_VERSION="$value"
    run_check
    [ "$status" -eq 1 ]
    [[ "$output" == *"cargo_audit_version must be a release version"* ]]
  done
  unset INPUT_CARGO_AUDIT_VERSION
  export INPUT_CARGO_DENY_VERSION="0.20"
  run_check
  [ "$status" -eq 1 ]
  [[ "$output" == *"cargo_deny_version must be a release version"* ]]
}

@test "deny_warnings accepts the three kinds, once each" {
  export INPUT_DENY_WARNINGS=$'yanked unmaintained\n\tyanked unsound'
  run_audit
  [ "$status" -eq 0 ]
  [ "$(audit_args)" = "audit --json --file $project/Cargo.lock --deny yanked --deny unmaintained --deny unsound" ]
}

@test "deny_warnings rejects other kinds without echoing them" {
  local value
  for value in warnings notice Yanked "unsound::error::x"; do
    export INPUT_DENY_WARNINGS="$value"
    run_check
    [ "$status" -eq 1 ]
    [[ "$output" == *"deny_warnings may contain only: unmaintained unsound yanked"* ]]
    [[ "$output" != *"::error::x"* ]]
  done
}

@test "deny_checks accepts the four checks and rejects others" {
  export INPUT_DENY_CHECKS="all"
  run_check
  [ "$status" -eq 1 ]
  [[ "$output" == *"deny_checks may contain only: advisories bans licenses sources"* ]]
  export INPUT_DENY_CHECKS="bans bans sources"
  run_check
  [ "$status" -eq 0 ]
}

@test "deny_checks must name a check when cargo-deny is enabled" {
  export INPUT_DENY_CHECKS=" "
  run_check
  [ "$status" -eq 0 ]
  export INPUT_DENY_ENABLED=true
  run_check
  [ "$status" -eq 1 ]
  [[ "$output" == *"deny_checks must name at least one check"* ]]
}

@test "ignore_vulns passes each RUSTSEC ID to cargo-audit once, in order" {
  export INPUT_IGNORE_VULNS=$'RUSTSEC-2023-0071\n\tRUSTSEC-2020-0071  RUSTSEC-2023-0071'
  run_audit
  [ "$status" -eq 0 ]
  [ "$(audit_args)" = "audit --json --file $project/Cargo.lock --ignore RUSTSEC-2023-0071 --ignore RUSTSEC-2020-0071" ]
}

@test "ignore_vulns rejects malformed IDs without echoing them" {
  local value
  # shellcheck disable=SC2016 # a literal command substitution
  for value in rustsec-2020-0071 RUSTSEC-2020-00711 RUSTSEC-20-0071 \
    "RUSTSEC-2020-0071,RUSTSEC-2023-0071" "RUSTSEC-2020-0071%0A::error::x" \
    'RUSTSEC-$(id)' "ghsa-wcg3-cvx6-7396"; do
    export INPUT_IGNORE_VULNS="RUSTSEC-2020-0071 $value"
    run_check
    [ "$status" -eq 1 ]
    [[ "$output" == *"ignore_vulns: an entry is not a RUSTSEC advisory ID"* ]]
    [[ "$output" != *"$value"* ]]
  done
}

@test "ignore_vulns rejects GHSA and CVE aliases, naming the alias" {
  local value
  for value in GHSA-wcg3-cvx6-7396 CVE-2020-26235; do
    export INPUT_IGNORE_VULNS="$value"
    run_check
    [ "$status" -eq 1 ]
    [[ "$output" == *"ignore_vulns: $value is an alias. cargo-audit matches ignores against RUSTSEC IDs alone"* ]]
  done
}

@test "allow-list reads IDs, comments, blank lines, CRLF and a BOM" {
  allow_list "allow list.txt" '\xef\xbb\xbfRUSTSEC-2023-0071\r\n# Comment line\r\n\r\n   RUSTSEC-2020-0071 # time: no fix yet\n\tRUSTSEC-2021-0139\tRUSTSEC-2021-0145\n# RUSTSEC-2099-0001\nRUSTSEC-2024-0375'
  run_audit
  [ "$status" -eq 0 ]
  [[ "$output" == *"Allow-list: 5 entries, 5 not already in ignore_vulns"* ]]
  [ "$(audit_args)" = "audit --json --file $project/Cargo.lock --ignore RUSTSEC-2023-0071 --ignore RUSTSEC-2020-0071 --ignore RUSTSEC-2021-0139 --ignore RUSTSEC-2021-0145 --ignore RUSTSEC-2024-0375" ]
}

@test "allow-list merges after ignore_vulns without duplicates" {
  export INPUT_IGNORE_VULNS="RUSTSEC-2020-0071 RUSTSEC-2021-0139"
  allow_list allow.txt 'RUSTSEC-2021-0139\nRUSTSEC-2023-0071\nRUSTSEC-2020-0071\n'
  run_audit
  [ "$status" -eq 0 ]
  [[ "$output" == *"Allow-list: 3 entries, 1 not already in ignore_vulns"* ]]
  [ "$(audit_args)" = "audit --json --file $project/Cargo.lock --ignore RUSTSEC-2020-0071 --ignore RUSTSEC-2021-0139 --ignore RUSTSEC-2023-0071" ]
  grep -q '^| Ignored | 3: RUSTSEC-2020-0071 RUSTSEC-2021-0139 RUSTSEC-2023-0071 |$' \
    "$GITHUB_STEP_SUMMARY"
}

@test "allow-list reads a last line without a newline" {
  allow_list allow.txt 'RUSTSEC-2020-0071'
  run_check
  [ "$status" -eq 0 ]
  [[ "$output" == *"Allow-list: 1 entry"* ]]
}

@test "allow-list names the line of an invalid entry, not its content" {
  allow_list allow.txt 'RUSTSEC-2020-0071\n\nRUSTSEC-2023-0071#trailing\n'
  run_check
  [ "$status" -eq 1 ]
  [[ "$output" == *"allow_list_path line 3: an entry is not a RUSTSEC advisory ID"* ]]
  [[ "$output" != *"#trailing"* ]]
  allow_list allow.txt 'RUSTSEC-2020-0071 time crate\n'
  run_check
  [ "$status" -eq 1 ]
  [[ "$output" == *"allow_list_path line 1: an entry is not"* ]]
}

@test "allow-list rejects an alias, naming line and alias" {
  allow_list allow.txt '# list\nGHSA-wcg3-cvx6-7396\n'
  run_check
  [ "$status" -eq 1 ]
  [[ "$output" == *"allow_list_path line 2: GHSA-wcg3-cvx6-7396 is an alias"* ]]
}

@test "allow-list holding only comments is an error" {
  allow_list allow.txt '# Nothing ignored yet\n\n   # still nothing\n'
  run_check
  [ "$status" -eq 1 ]
  [[ "$output" == *"allow_list_path holds no advisory IDs"* ]]
}

@test "allow-list larger than 1 MiB is refused" {
  head -c 1048577 /dev/zero | tr '\0' '\n' > "$project/big.txt"
  export INPUT_ALLOW_LIST_PATH=big.txt
  run_check
  [ "$status" -eq 1 ]
  [[ "$output" == *"allow_list_path is larger than 1048576 bytes"* ]]
}

@test "allow-list at the size limit validates in one pass and audits" {
  local -i round
  for ((round = 0; round < 12; round++)); do
    seq -f "RUSTSEC-2000-%04g" 0 4999
  done | head -n 58000 > "$project/big.txt"
  [ "$(wc -c < "$project/big.txt")" -le 1048576 ]
  export INPUT_ALLOW_LIST_PATH=big.txt
  run timeout 60 "$BASH" "$script" check
  [ "$status" -eq 0 ]
  [[ "$output" == *"Allow-list: 58000 entries, 5000 not already in ignore_vulns"* ]]
  run timeout 120 "$BASH" "$script" audit
  [ "$status" -eq 0 ]
  [ "$(grep -cx -- --ignore "$MOCK_AUDIT_ARGS")" -eq 5000 ]
  [ "$(sed -n 6p "$MOCK_AUDIT_ARGS")" = "RUSTSEC-2000-0000" ]
}

@test "more than 5000 distinct ignores are refused before installing" {
  seq -f "RUSTSEC-2000-%04g" 0 4999 > "$project/list.txt"
  export INPUT_ALLOW_LIST_PATH=list.txt INPUT_IGNORE_VULNS="RUSTSEC-2000-0001"
  run_check
  [ "$status" -eq 0 ]
  export INPUT_IGNORE_VULNS="RUSTSEC-2001-0001"
  : > "$GITHUB_OUTPUT"
  run_check
  [ "$status" -eq 1 ]
  [[ "$output" == *"ignore_vulns and allow_list_path together name more than 5000 distinct advisory IDs"* ]]
  [ -z "$(output_value tools)" ]
}

@test "allow-list must be a regular file inside the workspace" {
  printf 'RUSTSEC-2020-0071\n' > "$BATS_TEST_TMPDIR/outside.txt"
  local value
  for value in missing.txt "../../outside.txt" "$BATS_TEST_TMPDIR/outside.txt"; do
    export INPUT_ALLOW_LIST_PATH="$value"
    run_check
    [ "$status" -eq 1 ]
  done
  ln -s "$BATS_TEST_TMPDIR/outside.txt" "$project/link.txt"
  export INPUT_ALLOW_LIST_PATH=link.txt
  run_check
  [ "$status" -eq 1 ]
  [[ "$output" == *"allow_list_path must not be a symlink"* ]]
  mkdir "$project/dir.txt"
  export INPUT_ALLOW_LIST_PATH=dir.txt
  run_check
  [ "$status" -eq 1 ]
}

@test "allow-list may sit elsewhere in the workspace, relative to path_prefix" {
  mkdir -p "$workdir/.github"
  printf 'RUSTSEC-2020-0071\n' > "$workdir/.github/allow.txt"
  export INPUT_ALLOW_LIST_PATH="../.github/allow.txt"
  run_check
  [ "$status" -eq 0 ]
}

@test "path_prefix must be a directory inside the workspace" {
  local value
  for value in missing /etc "../.." "my project/Cargo.toml"; do
    export INPUT_PATH_PREFIX="$value"
    run_check
    [ "$status" -eq 1 ]
    [[ "$output" == *"path_prefix"* ]]
  done
  ln -s "$BATS_TEST_TMPDIR" "$workdir/escape"
  export INPUT_PATH_PREFIX=escape
  run_check
  [ "$status" -eq 1 ]
  [[ "$output" == *"path_prefix must resolve within the workspace"* ]]
}

@test "path inputs may not hold control characters" {
  printf 'RUSTSEC-2020-0071\n' > "$project/allow.txt"
  local pair name good value
  # $(...) drops a trailing newline, which would turn a value into the
  # valid path before it rather than fail.
  for pair in "path_prefix=my project" manifest_path=Cargo.toml \
    allow_list_path=allow.txt artefact_path=reports; do
    name="${pair%%=*}" good="${pair#*=}"
    for value in "$good"$'\n' "$good"$'\r' $'\t'"$good"; do
      export "INPUT_${name^^}=$value"
      run_check
      [ "$status" -eq 1 ]
      [[ "$output" == *"::error::$name must not contain control characters"* ]]
    done
    export "INPUT_${name^^}=$good"
    run_check
    [ "$status" -eq 0 ]
  done
  [ ! -e "$project/reports" ]
}

@test "an empty path_prefix means the workspace root" {
  cp "$project/Cargo.toml" "$workdir/Cargo.toml"
  export INPUT_PATH_PREFIX=""
  run_check
  [ "$status" -eq 0 ]
}

@test "manifest_path must name a regular Cargo.toml below path_prefix" {
  local value
  for value in Cargo.lock "sub/Cargo.toml" "$project/Cargo.toml" "../Cargo.toml"; do
    export INPUT_MANIFEST_PATH="$value"
    run_check
    [ "$status" -eq 1 ]
    [[ "$output" == *"manifest_path"* ]]
  done
  mkdir -p "$project/linked"
  ln -s "$project/Cargo.toml" "$project/linked/Cargo.toml"
  export INPUT_MANIFEST_PATH=linked/Cargo.toml
  run_check
  [ "$status" -eq 1 ]
  [[ "$output" == *"manifest_path must not be a symlink"* ]]
}

@test "a symlinked directory cannot carry manifest_path outside" {
  mkdir -p "$BATS_TEST_TMPDIR/elsewhere"
  cp "$project/Cargo.toml" "$BATS_TEST_TMPDIR/elsewhere/Cargo.toml"
  ln -s "$BATS_TEST_TMPDIR/elsewhere" "$project/away"
  export INPUT_MANIFEST_PATH=away/Cargo.toml
  run_check
  [ "$status" -eq 1 ]
  [[ "$output" == *"manifest_path must resolve within the workspace"* ]]
}

### Audit phase: a clean run ###

@test "a clean audit passes and sets every output" {
  run_audit
  [ "$status" -eq 0 ]
  [ "$(output_value audit_outcome)" = "passed" ]
  [ "$(output_value deny_outcome)" = "skipped" ]
  [ "$(output_value vulnerability_count)" = "0" ]
  [ "$(output_value warning_count)" = "0" ]
  [ "$(output_value vulnerability_ids)" = "" ]
  local report dir
  dir="$(output_value artefact_path)"
  report="$(output_value report_path)"
  [[ "$dir" == "$RUNNER_TEMP"/rust-audit-results.* ]]
  [ "$report" = "$dir/cargo-audit.json" ]
  jq -e '.vulnerabilities.count == 0' "$report"
  # The report alone: the tools' logs stay in the work directory.
  [ "$(ls -A "$dir")" = "cargo-audit.json" ]
  [ "$(output_value deny_report_path)" = "" ]
  [ "$(output_value artefact_name)" = "rust-audit-results" ]
  [ "$(output_value upload_reports)" = "true" ]
  [ "$(cut -d= -f1 "$GITHUB_OUTPUT" | sort | paste -s -d ' ' -)" = \
    "artefact_name artefact_path audit_outcome cargo_version deny_outcome deny_report_path report_path rustc_version toolchain toolchain_kind upload_reports vulnerability_count vulnerability_ids warning_count" ]
  [ "$(tool_calls)" = "rustup cargo-version rustc-version locate-project audit" ]
  [ "$(audit_args)" = "audit --json --file $project/Cargo.lock" ]
  [[ "$output" == *"Audit passed"* ]]
}

@test "a clean audit writes the summary table" {
  run_audit
  [ "$status" -eq 0 ]
  local s="$GITHUB_STEP_SUMMARY"
  grep -qx '## 🦀 Rust Dependency Audit' "$s"
  grep -qx '### ✅ Passed' "$s"
  grep -qxF '| Manifest | <code>my project/Cargo.toml</code> |' "$s"
  grep -qxF '| Toolchain | <code>stable-x86&#95;64-unknown-linux-gnu</code> (cargo 1.99.0, rustc 1.99.0) |' "$s"
  grep -qxF '| Lockfile | <code>my project/Cargo.lock</code>; 1 package |' "$s"
  grep -qxF '| cargo-audit | <code>0.22.2</code>; 1293 advisories |' "$s"
  grep -qxF '| Vulnerabilities | ✅ None found |' "$s"
  grep -qxF '| Warnings | ✅ None |' "$s"
  grep -qxF '| Ignored | ➖ None |' "$s"
  grep -qxF '| cargo-deny | ➖ Not enabled |' "$s"
  grep -qE '^\| Reports \| <code>cargo-audit.json</code> \([0-9.]+ (B|KiB)\) in <code>runner temp/rust-audit-results\.[A-Za-z0-9]+</code> \|$' "$s"
  grep -qxF '| Artefact | 📦 <code>rust-audit-results</code>, uploaded after this step |' "$s"
  run ! grep -q '^### Vulnerabilities' "$s"
}

@test "every tool runs pinned to the project's toolchain, from its directory" {
  export INPUT_DENY_ENABLED=true
  run_audit
  [ "$status" -eq 0 ]
  local call
  for call in cargo-version locate-project audit deny; do
    [ "$(call_field "$call" 7)" = "stable-x86_64-unknown-linux-gnu" ]
  done
  [ "$(call_field rustup 2)" = "$project" ]
  [ "$(call_field locate-project 2)" = "$project" ]
  [ "$(call_field audit 2)" = "$project" ]
  [ "$(call_field deny 2)" = "$project" ]
}

# The canonical scrub, identical in every Rust action: registry tokens,
# GitHub OIDC and runtime variables, and the runner's command files.
@test "no cargo, rustup or audit tool call sees a scrubbed variable" {
  export INPUT_DENY_ENABLED=true
  rm "$project/Cargo.lock"
  run_audit
  [ "$status" -eq 0 ]
  # Every child process the action starts, version queries included.
  [ "$(tool_calls)" = "rustup cargo-version rustc-version locate-project generate-lockfile audit deny" ]
  [ "$(cut -d'|' -f1 "$MOCK_VERSION_LOG" | paste -s -d ' ' -)" = \
    "audit-version deny-version" ]
  local field
  # 3-6 and 8-9: registry, OIDC and runtime tokens; 11-15: GITHUB_OUTPUT,
  # GITHUB_ENV, GITHUB_PATH, GITHUB_STATE and GITHUB_STEP_SUMMARY.
  for field in 3 4 5 6 8 9 11 12 13 14 15; do
    [ "$(cut -d'|' -f"$field" "$MOCK_TOOL_LOG" "$MOCK_VERSION_LOG" | sort -u)" = "unset" ]
  done
  # Only tokens go: Cargo still needs a registry's other settings.
  [ "$(cut -d'|' -f10 "$MOCK_TOOL_LOG" "$MOCK_VERSION_LOG" | sort -u)" = \
    "sparse+https://registry.example/" ]
  run ! grep -qE 'secret|github (output|env|path|state)|job summary' \
    "$MOCK_TOOL_LOG" "$MOCK_VERSION_LOG"
  # The action's own writes still land.
  [ "$(output_value audit_outcome)" = "passed" ]
  [ "$(output_value deny_outcome)" = "passed" ]
  grep -qx '### ✅ Passed' "$GITHUB_STEP_SUMMARY"
}

@test "summary 'false' writes no job summary but still sets outputs" {
  export INPUT_SUMMARY=false MOCK_AUDIT_REPORT="$fixtures/audit-findings.json"
  run_audit
  [ "$status" -eq 1 ]
  [ ! -s "$GITHUB_STEP_SUMMARY" ]
  [ "$(output_value vulnerability_count)" = "3" ]
}

@test "an unwritable job summary warns without changing the result" {
  export GITHUB_STEP_SUMMARY="$workdir"
  run_audit
  [ "$status" -eq 0 ]
  [[ "$output" == *"::warning::Could not write the job summary"* ]]
}

@test "a RUNNER_TEMP that upload-artifact would misread fails at Prepare" {
  export RUNNER_TEMP="$workdir/runner"$'\n'"temp"
  mkdir -p "$RUNNER_TEMP"
  run_audit
  [ "$status" -eq 1 ]
  [[ "$output" == *"::error::RUNNER_TEMP must give a directory path without"* ]]
  [[ "$output" == *"::warning::Skipped output artefact_path: its value spans lines"* ]]
  [ "$(tool_calls)" = "" ]
  run ! grep -q '^artefact_path=' "$GITHUB_OUTPUT"
  [ "$(output_value upload_reports)" = "false" ]
  grep -qx '### ❌ Failed at Prepare' "$GITHUB_STEP_SUMMARY"
}

### Report artefacts ###

@test "action.yaml uploads the reports after failures too, when told to" {
  local step
  step="$(awk '/- name: "Upload audit reports"/ { on = 1 } on' "$action_file")"
  grep -qxF "      if: \${{ !cancelled() && steps.audit.outputs.upload_reports == 'true' }}" <<< "$step"
  grep -qxF '      uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2' <<< "$step"
  grep -qxF "      continue-on-error: \${{ inputs.permit_fail == 'true' }}" <<< "$step"
  grep -qxF "        name: \${{ steps.audit.outputs.artefact_name }}" <<< "$step"
  grep -qxF "        path: \${{ steps.audit.outputs.artefact_path }}" <<< "$step"
  grep -qxF '        if-no-files-found: warn' <<< "$step"
}

@test "cargo-deny's output is kept as JSON lines and as readable text" {
  export INPUT_DENY_ENABLED=true MOCK_DENY_LOG="$fixtures/deny-failed.jsonl"
  export MOCK_DENY_ERRORS="licenses=9"
  run_audit
  [ "$status" -eq 1 ]
  local dir
  dir="$(output_value artefact_path)"
  [ "$(cd "$dir" && echo ./*)" = \
    "./cargo-audit.json ./cargo-deny.jsonl ./cargo-deny.txt" ]
  [ "$(output_value deny_report_path)" = "$dir/cargo-deny.jsonl" ]
  [ "$(output_value upload_reports)" = "true" ]
  # Every line is JSON, ending with the summary record.
  jq -e -s '.[-1] | .type == "summary" and .fields.licenses.errors == 9' \
    "$dir/cargo-deny.jsonl"
  [ "$(grep -c '^error\[rejected\]: ' "$dir/cargo-deny.txt")" -eq 8 ]
  grep -qF 'error[rejected]: ' "$dir/cargo-deny.txt"
  run ! grep -q '{' "$dir/cargo-deny.txt"
  grep -qE '^\| Reports \| <code>cargo-audit.json</code> \([^)]*\), <code>cargo-deny.jsonl</code> \([^)]*\), <code>cargo-deny.txt</code> \([^)]*\) in ' \
    "$GITHUB_STEP_SUMMARY"
}

@test "a run with findings keeps its reports for upload, permitted or not" {
  export MOCK_AUDIT_REPORT="$fixtures/audit-findings.json"
  local permit
  for permit in false true; do
    export INPUT_PERMIT_FAIL="$permit"
    : > "$GITHUB_OUTPUT"
    run_audit
    if [ "$permit" = "true" ]; then
      [ "$status" -eq 0 ]
    else
      [ "$status" -eq 1 ]
    fi
    [ "$(output_value audit_outcome)" = "failed" ]
    [ "$(output_value upload_reports)" = "true" ]
    [ "$(output_value artefact_name)" = "rust-audit-results" ]
    jq -e '.vulnerabilities.count == 3' "$(output_value report_path)"
  done
}

@test "artefact_upload 'false' keeps the reports but uploads nothing" {
  export INPUT_ARTEFACT_UPLOAD=false
  run_audit
  [ "$status" -eq 0 ]
  [ "$(output_value upload_reports)" = "false" ]
  run ! grep -q '^artefact_name=' "$GITHUB_OUTPUT"
  [ -f "$(output_value report_path)" ]
  grep -qxF '| Artefact | ➖ Upload disabled |' "$GITHUB_STEP_SUMMARY"
}

@test "artefact_name takes the characters artefact names allow" {
  local value
  for value in "" "a b" "bad/name" 'bad"name' "bad:name" $'bad\nname'; do
    export INPUT_ARTEFACT_NAME="$value"
    run_check
    [ "$status" -eq 1 ]
    [[ "$output" == *"::error::artefact_name must be non-empty and contain only A-Z a-z 0-9 . _ -"* ]]
  done
  export INPUT_ARTEFACT_NAME="audit_results-1.0"
  run_audit
  [ "$status" -eq 0 ]
  [ "$(output_value artefact_name)" = "audit_results-1.0" ]
}

@test "artefact_path places the reports below path_prefix" {
  export INPUT_ARTEFACT_PATH="reports/audit/"
  run_audit
  [ "$status" -eq 0 ]
  [ "$(output_value artefact_path)" = "$project/reports/audit" ]
  [ "$(output_value report_path)" = "$project/reports/audit/cargo-audit.json" ]
  grep -qE '^\| Reports \| .* in <code>my project/reports/audit</code> \|$' "$GITHUB_STEP_SUMMARY"
  # An existing empty directory serves too, as does one reached
  # through a symlinked directory inside the workspace.
  mkdir -p "$workdir/elsewhere/empty"
  ln -s "$workdir/elsewhere" "$project/linked"
  export INPUT_ARTEFACT_PATH="linked/empty"
  run_audit
  [ "$status" -eq 0 ]
  [ "$(output_value artefact_path)" = "$workdir/elsewhere/empty" ]
  [ -f "$workdir/elsewhere/empty/cargo-audit.json" ]
}

@test "artefact_path must be an empty or absent directory in the workspace" {
  mkdir -p "$project/full" "$workdir/elsewhere" "$BATS_TEST_TMPDIR/outside"
  : > "$project/full/old.json"
  : > "$project/a-file"
  ln -s "$workdir/elsewhere" "$project/link"
  ln -s "$BATS_TEST_TMPDIR/outside" "$project/escape"
  local pair
  for pair in "full:must be an empty or absent directory" \
    ".:must be an empty or absent directory" \
    "a-file:must name a directory" \
    "link:must not be a symlink" \
    "link/:must not be a symlink" \
    "escape/reports:must resolve to a directory below the workspace" \
    "../..:must resolve to a directory below the workspace" \
    "missing/../x:may not use '.', '..' or '//'" \
    "rep*rts:must give a directory path without" \
    "reports :must give a directory path without"; do
    export INPUT_ARTEFACT_PATH="${pair%%:*}"
    run_check
    [ "$status" -eq 1 ]
    [[ "$output" == *"::error::artefact_path ${pair#*:}"* ]]
  done
  [ ! -e "$project/missing" ]
  [ -z "$(ls -A "$BATS_TEST_TMPDIR/outside")" ]
}

# A stand-in mkdir that, after creating TARGET, plants a file in it or
# swaps it for a symlink, as a rival writer could between the check and
# the creation.
rival_mkdir() {
  local real
  real="$(PATH="${PATH#"$bin":}" command -v mkdir)"
  printf '%s\n' '#!/usr/bin/env bash' \
    "\"$real\" \"\$@\" || exit" \
    "[ \"\${!#}\" = \"$1\" ] || exit 0" \
    "$2" > "$bin/mkdir"
  chmod +x "$bin/mkdir"
}

@test "artefact_path is checked again once created" {
  export INPUT_ARTEFACT_PATH="reports"
  mkdir -p "$workdir/elsewhere"
  rival_mkdir "$project/reports" ": > \"$project/reports/planted\""
  run_audit
  [ "$status" -eq 1 ]
  [[ "$output" == *"::error::artefact_path must be an empty or absent directory"* ]]
  [ "$(tool_calls)" = "" ]
  rm -r "$project/reports"
  rival_mkdir "$project/reports" \
    "rmdir \"$project/reports\" && ln -s \"$workdir/elsewhere\" \"$project/reports\""
  run_audit
  [ "$status" -eq 1 ]
  [[ "$output" == *"::error::artefact_path could not be created as a directory inside the workspace"* ]]
  [ "$(tool_calls)" = "" ]
  grep -qx '### ❌ Failed at Prepare' "$GITHUB_STEP_SUMMARY"
}

# A listing read through $(...) loses trailing newlines, so a check
# built on 'ls -A' saw no entry in a directory holding only a file
# named by a newline. A planted ls must not matter either.
@test "a hidden file or one named by a newline makes artefact_path non-empty" {
  printf '%s\n' '#!/bin/sh' 'exit 0' > "$bin/ls"
  chmod +x "$bin/ls"
  export INPUT_ARTEFACT_PATH="reports"
  local name
  for name in .hidden $'\n'; do
    mkdir "$project/reports"
    : > "$project/reports/$name"
    run_check
    [ "$status" -eq 1 ]
    [[ "$output" == *"::error::artefact_path must be an empty or absent directory"* ]]
    rm -r "$project/reports"
  done
  rival_mkdir "$project/reports" ": > \"$project/reports/\"\$'\\n'"
  run_audit
  [ "$status" -eq 1 ]
  [[ "$output" == *"::error::artefact_path must be an empty or absent directory"* ]]
  [ "$(tool_calls)" = "" ]
  grep -qx '### ❌ Failed at Prepare' "$GITHUB_STEP_SUMMARY"
}

@test "an artefact_path the action cannot list is refused" {
  mkdir "$project/reports"
  : > "$project/reports/old.json"
  chmod 300 "$project/reports"
  export INPUT_ARTEFACT_PATH="reports"
  run_check
  chmod 700 "$project/reports"
  [ "$status" -eq 1 ]
  [[ "$output" == *"::error::artefact_path must be a directory this action can read"* ]]
}

# Once tools have run, a program planted on PATH could lie about paths.
# This dirname maps the two escapes below onto the project directory.
@test "containment checks after tools run do not rely on dirname or basename" {
  local real
  real="$(PATH="${PATH#"$bin":}" command -v dirname)"
  # shellcheck disable=SC2016 # the stand-in's own expansions
  printf '%s\n' '#!/usr/bin/env bash' \
    'case "${!#}" in' \
    "  */outside/Cargo.toml | */.cargo/deny.toml) printf '%s\\n' \"$project\" ;;" \
    "  *) exec \"$real\" \"\$@\" ;;" \
    'esac' > "$bin/dirname"
  chmod +x "$bin/dirname"
  [ "$("$bin/dirname" -- "$BATS_TEST_TMPDIR/outside/Cargo.toml")" = "$project" ]
  mkdir -p "$BATS_TEST_TMPDIR/outside"
  export MOCK_LOCATE_OUTPUT="$BATS_TEST_TMPDIR/outside/Cargo.toml"
  run_audit
  [ "$status" -eq 1 ]
  [[ "$output" == *"The Cargo workspace root must resolve within the workspace"* ]]
  unset MOCK_LOCATE_OUTPUT
  export INPUT_DENY_ENABLED=true
  printf '' > "$BATS_TEST_TMPDIR/outside/deny.toml"
  ln -s "$BATS_TEST_TMPDIR/outside" "$project/.cargo"
  run_audit
  [ "$status" -eq 1 ]
  [[ "$output" == *"my project/.cargo/deny.toml must resolve within the workspace"* ]]
  [[ "$(tool_calls)" != *deny* ]]
}

@test "a report file that appears during the run is not overwritten" {
  export INPUT_ARTEFACT_PATH="reports"
  export MOCK_AUDIT_PLANT="$project/reports/cargo-audit.json"
  run_audit
  [ "$status" -eq 1 ]
  [[ "$output" == *"::error::cargo-audit.json appeared in the report directory before the action wrote it"* ]]
  [ "$(cat "$project/reports/cargo-audit.json")" = "planted" ]
  [ "$(output_value report_path)" = "" ]
}

@test "a symlink planted at a report name is never written through" {
  export INPUT_ARTEFACT_PATH="reports"
  export MOCK_AUDIT_PLANT="$project/reports/cargo-audit.json"
  echo victim > "$workdir/victim"
  local to
  for to in "$workdir/victim" "$workdir/absent"; do
    rm -f -- "$MOCK_AUDIT_PLANT"
    export MOCK_AUDIT_PLANT_TO="$to"
    run_audit
    [ "$status" -eq 1 ]
    [[ "$output" == *"::error::cargo-audit.json appeared in the report directory before the action wrote it"* ]]
    [ "$(cat "$workdir/victim")" = "victim" ]
    [ ! -e "$workdir/absent" ]
    [ "$(output_value report_path)" = "" ]
  done
}

@test "a symlink to a non-regular file at a report name fails the run" {
  export INPUT_ARTEFACT_PATH="reports"
  export MOCK_AUDIT_PLANT="$project/reports/cargo-audit.json"
  export MOCK_AUDIT_PLANT_TO=/dev/null
  run_audit
  [ "$status" -eq 1 ]
  [[ "$output" == *"::error::cargo-audit.json in the report directory is not a regular file"* ]]
  [ "$(output_value report_path)" = "" ]
}

@test "a symlink planted between any check and the write is not followed" {
  # A rival writer acting inside the action's own copy command, the
  # latest moment a check-then-copy could be raced.
  export INPUT_ARTEFACT_PATH="reports" VICTIM="$workdir/victim"
  echo victim > "$VICTIM"
  local real_cp
  real_cp="$(type -P cp)"
  cat > "$bin/cp" << EOF
#!/usr/bin/env bash
for dest; do :; done
case "\$dest" in */reports/*) ln -s -- "\$VICTIM" "\$dest" ;; esac
exec '$real_cp' "\$@"
EOF
  chmod +x "$bin/cp"
  run_audit
  [ "$(cat "$VICTIM")" = "victim" ]
  [ "$status" -eq 0 ]
  [ "$(output_value report_path)" = "$project/reports/cargo-audit.json" ]
  jq -e 'type == "object"' "$project/reports/cargo-audit.json"
  [ ! -L "$project/reports/cargo-audit.json" ]
}

### Tools and toolchain ###

@test "a missing or mismatched cargo-audit fails at Check tools" {
  export MOCK_AUDIT_VERSION=0.21.0
  run_audit
  [ "$status" -eq 1 ]
  [[ "$output" == *"cargo-audit reports version '0.21.0', expected 0.22.2"* ]]
  grep -qx '### ❌ Failed at Check tools' "$GITHUB_STEP_SUMMARY"
  [ "$(output_value audit_outcome)" = "failed" ]
  export MOCK_AUDIT_VERSION='0.22.2::error::x'
  run_audit
  [ "$status" -eq 1 ]
  [[ "$output" == *"reports version 'unknown'"* ]]
  rm "$bin/cargo-audit"
  : > "$MOCK_TOOL_LOG"
  run_audit
  [ "$status" -eq 1 ]
  [[ "$output" == *"cargo-audit not found on PATH"* ]]
  # Only the toolchain stage ran before it.
  [ "$(tool_calls)" = "rustup cargo-version rustc-version" ]
}

@test "cargo-deny's version is checked only when it is enabled" {
  export MOCK_DENY_VERSION=0.19.0
  run_audit
  [ "$status" -eq 0 ]
  export INPUT_DENY_ENABLED=true
  run_audit
  [ "$status" -eq 1 ]
  [[ "$output" == *"cargo-deny reports version '0.19.0', expected 0.20.2"* ]]
}

@test "permit_fail turns a tool failure into a warning and a failed outcome" {
  rm "$bin/cargo-audit"
  export INPUT_PERMIT_FAIL=true
  run_audit
  [ "$status" -eq 0 ]
  [[ "$output" == *"::warning::Failed at Check tools; permit_fail is 'true', so the step reports success"* ]]
  [[ "$output" == *"::warning::cargo-audit not found on PATH"* ]]
  [ "$(output_value audit_outcome)" = "failed" ]
  grep -qx '### ⚠️ Failed at Check tools (permitted)' "$GITHUB_STEP_SUMMARY"
}

@test "a failed install fails the audit even with matching tools on PATH" {
  export INSTALL_OUTCOME=failure INPUT_DENY_ENABLED=true
  run_audit
  [ "$status" -eq 1 ]
  [ ! -s "$MOCK_TOOL_LOG" ]
  [ "$(output_value audit_outcome)" = "failed" ]
  [ "$(output_value deny_outcome)" = "skipped" ]
  [[ "$output" == *"::error::The audit tools did not install; see the Install audit tools step log."* ]]
  grep -qx '### ❌ Failed at Install audit tools' "$GITHUB_STEP_SUMMARY"
  : > "$GITHUB_OUTPUT"
  : > "$GITHUB_STEP_SUMMARY"
  export INPUT_PERMIT_FAIL=true
  run_audit
  [ "$status" -eq 0 ]
  [ ! -s "$MOCK_TOOL_LOG" ]
  [ "$(output_value audit_outcome)" = "failed" ]
  [ "$(output_value deny_outcome)" = "skipped" ]
  [[ "$output" == *"::warning::The audit tools did not install; see the Install audit tools step log."* ]]
  [[ "$output" == *"::warning::Failed at Install audit tools; permit_fail is 'true', so the step reports success"* ]]
  grep -qx '### ⚠️ Failed at Install audit tools (permitted)' "$GITHUB_STEP_SUMMARY"
  export INSTALL_OUTCOME=success
  run_audit
  [ "$status" -eq 0 ]
  [ "$(output_value audit_outcome)" = "passed" ]
  [ "$(output_value deny_outcome)" = "passed" ]
}

@test "the audit step receives the install step's outcome" {
  # shellcheck disable=SC2016 # matches the literal expression
  grep -qxF '        INSTALL_OUTCOME: ${{ steps.install.outcome }}' "$action_file"
  # An expression here would read the nested action's inputs (see
  # action.yaml), so the install must continue on error unconditionally.
  [ "$(sed -n '/^      id: install$/,/^      with:$/p' "$action_file" |
    grep -c '^      continue-on-error: true$')" -eq 1 ]
}

@test "a path toolchain runs unpinned, with a warning" {
  export MOCK_TOOLCHAIN=/opt/rust/custom
  run_audit
  [ "$status" -eq 0 ]
  [ "$(call_field audit 7)" = "unset" ]
  [ "$(call_field locate-project 7)" = "unset" ]
  [[ "$output" == *"::warning::The project selects a toolchain by path"* ]]
  grep -qF '| Toolchain | ⚠️ Path toolchain <code>/opt/rust/custom</code> (cargo 1.99.0, rustc 1.99.0) |' "$GITHUB_STEP_SUMMARY"
}

@test "a path toolchain cannot forge workflow commands in the log" {
  export MOCK_TOOLCHAIN='/opt/##[error]injected'
  run_audit
  [ "$status" -eq 0 ]
  assert_no_injected_command
  [[ "$output" == *"  Toolchain: /opt/# #[error]injected (cargo 1.99.0, rustc 1.99.0)"* ]]
  [ "$(output_value toolchain)" = '/opt/##[error]injected' ]
  export MOCK_TOOLCHAIN='/opt/::error::injected'
  run_audit
  [ "$status" -eq 0 ]
  assert_no_injected_command
  [[ "$output" == *"  Toolchain: /opt/::error::injected (cargo 1.99.0, rustc 1.99.0)"* ]]
}

@test "without rustup, cargo runs unpinned from PATH" {
  rm "$bin/rustup"
  export RUSTUP_TOOLCHAIN=from-caller
  run_audit
  [ "$status" -eq 0 ]
  [ "$(tool_calls)" = "cargo-version rustc-version locate-project audit" ]
  [ "$(call_field audit 7)" = "from-caller" ]
  grep -qF '| Toolchain | No rustup: <code>cargo</code> from PATH (cargo 1.99.0, rustc 1.99.0) |' "$GITHUB_STEP_SUMMARY"
}

@test "an unresolvable or unpinnable toolchain fails at Resolve toolchain" {
  export MOCK_RUSTUP_FAIL=true
  run_audit
  [ "$status" -eq 1 ]
  [[ "$output" == *"rustup could not name the project's active toolchain"* ]]
  grep -qx '### ❌ Failed at Resolve toolchain' "$GITHUB_STEP_SUMMARY"
  unset MOCK_RUSTUP_FAIL
  export MOCK_TOOLCHAIN='stable;id'
  run_audit
  [ "$status" -eq 1 ]
  [[ "$output" == *"rustup named a toolchain this action cannot pin"* ]]
  [[ "$output" != *"stable;id"* ]]
}

@test "the toolchain input pins every call to that channel, without asking rustup" {
  export INPUT_TOOLCHAIN=nightly-2026-01-01 INPUT_DENY_ENABLED=true
  export MOCK_CARGO_VERSION=1.100.0-nightly MOCK_RUSTC_VERSION=1.100.0-nightly
  export RUSTUP_TOOLCHAIN=from-caller
  run_audit
  [ "$status" -eq 0 ]
  [ "$(tool_calls)" = "cargo-version rustc-version locate-project audit deny" ]
  [ "$(cut -d'|' -f7 "$MOCK_TOOL_LOG" "$MOCK_VERSION_LOG" | sort -u)" = \
    "nightly-2026-01-01" ]
  [ "$(output_value toolchain)" = "nightly-2026-01-01" ]
  [ "$(output_value toolchain_kind)" = "channel" ]
  [ "$(output_value cargo_version)" = "1.100.0-nightly" ]
  [ "$(output_value rustc_version)" = "1.100.0-nightly" ]
  grep -qxF '| Toolchain | <code>nightly-2026-01-01</code> (cargo 1.100.0-nightly, rustc 1.100.0-nightly) |' "$GITHUB_STEP_SUMMARY"
}

@test "the toolchain input takes a channel name and needs rustup" {
  local value
  for value in stable 1.99.0 nightly-2026-01-01 stable-x86_64-unknown-linux-gnu \
    1.99+x; do
    export INPUT_TOOLCHAIN="$value"
    run_check
    [ "$status" -eq 0 ]
  done
  # shellcheck disable=SC2016 # a literal command substitution
  for value in 'stable;id' ../x /opt/rust 'a b' $'stable\n::error::injected' \
    'stable$(id)'; do
    export INPUT_TOOLCHAIN="$value"
    run_check
    [ "$status" -eq 1 ]
    [[ "$output" == *"::error::toolchain must be a rustup channel name (A-Z a-z 0-9 . _ + -)"* ]]
    [[ "$output" != *"$value"* ]]
    assert_no_injected_command
  done
  export INPUT_TOOLCHAIN=stable
  rm "$bin/rustup"
  run_audit
  [ "$status" -eq 1 ]
  [[ "$output" == *"::error::toolchain needs rustup, which is not on PATH"* ]]
  grep -qx '### ❌ Failed at Resolve toolchain' "$GITHUB_STEP_SUMMARY"
  [ "$(tool_calls)" = "" ]
}

@test "the project's toolchain is reported in the outputs, by kind" {
  export INPUT_DENY_ENABLED=true
  run_audit
  [ "$status" -eq 0 ]
  [ "$(output_value toolchain)" = "stable-x86_64-unknown-linux-gnu" ]
  [ "$(output_value toolchain_kind)" = "channel" ]
  [ "$(output_value cargo_version)" = "1.99.0" ]
  [ "$(output_value rustc_version)" = "1.99.0" ]
  # The version queries run after the toolchain resolves, pinned too.
  [ "$(cut -d'|' -f7 "$MOCK_VERSION_LOG" | sort -u)" = \
    "stable-x86_64-unknown-linux-gnu" ]
  [ "$(call_field rustc-version 7)" = "stable-x86_64-unknown-linux-gnu" ]
  # A path may hold ' (', so only the reason rustup appends goes.
  : > "$GITHUB_OUTPUT"
  export MOCK_TOOLCHAIN="/opt/rust (old)/custom"
  run_audit
  [ "$status" -eq 0 ]
  [ "$(output_value toolchain)" = "/opt/rust (old)/custom" ]
  [ "$(output_value toolchain_kind)" = "path" ]
  [ "$(output_value rustc_version)" = "1.99.0" ]
  [ "$(call_field rustc-version 7)" = "unset" ]
  local value
  for value in $'/opt/rust\r/custom' $'/opt/rust\n/custom'; do
    export MOCK_TOOLCHAIN="$value"
    run_audit
    [ "$status" -eq 1 ]
    [[ "$output" == *"rustup named a toolchain path this action cannot report"* ]]
    [[ "$output" != *"Toolchain: /opt/rust"* ]]
  done
  unset MOCK_TOOLCHAIN
  : > "$GITHUB_OUTPUT"
  rm "$bin/rustup"
  run_audit
  [ "$status" -eq 0 ]
  [ "$(output_value toolchain)" = "" ]
  [ "$(output_value toolchain_kind)" = "none" ]
  [ "$(output_value cargo_version)" = "1.99.0" ]
}

@test "a toolchain whose cargo or rustc cannot report a version fails" {
  export MOCK_RUSTC_FAIL=true
  run_audit
  [ "$status" -eq 1 ]
  [[ "$output" == *"::error::rustc --version failed for the selected toolchain"* ]]
  grep -qx '### ❌ Failed at Resolve toolchain' "$GITHUB_STEP_SUMMARY"
  [ "$(output_value rustc_version)" = "" ]
  unset MOCK_RUSTC_FAIL
  export MOCK_CARGO_VERSION='1.99.0::error::injected'
  run_audit
  [ "$status" -eq 1 ]
  [[ "$output" == *"::error::cargo --version reported an unexpected version"* ]]
  assert_no_injected_command
  rm "$bin/cargo"
  run_audit
  [ "$status" -eq 1 ]
  [[ "$output" == *"::error::required tool not found on PATH: cargo"* ]]
}

### Lockfile ###

@test "a missing Cargo.lock is generated with a warning" {
  rm "$project/Cargo.lock"
  run_audit
  [ "$status" -eq 0 ]
  [ "$(tool_calls)" = "rustup cargo-version rustc-version locate-project generate-lockfile audit" ]
  [ "$(call_field generate-lockfile 3)" = "unset" ]
  [ "$(call_field generate-lockfile 7)" = "stable-x86_64-unknown-linux-gnu" ]
  [[ "$output" == *"::warning::Cargo.lock is missing, so the audit covers a freshly generated one"* ]]
  [[ "$output" == *"  cargo:     Locking 1 package"* ]]
  : > "$MOCK_TOOL_LOG"
  rm "$project/Cargo.lock"
  export MOCK_GENERATE_STDOUT=$'::error::injected\n##[error]legacy'
  run_audit
  [ "$status" -eq 0 ]
  assert_no_injected_command
  [[ "$output" == *$'  cargo: ::error::injected\n  cargo: # #[error]legacy'* ]]
  grep -qF '| Lockfile | ⚠️ <code>my project/Cargo.lock</code>, generated by the action; 1 package |' "$GITHUB_STEP_SUMMARY"
  grep -q '^- Cargo.lock is missing' "$GITHUB_STEP_SUMMARY"
}

@test "lockfile_required fails on a missing Cargo.lock without generating one" {
  rm "$project/Cargo.lock"
  export INPUT_LOCKFILE_REQUIRED=true
  run_audit
  [ "$status" -eq 1 ]
  [[ "$output" == *"Cargo.lock is missing and lockfile_required is 'true'"* ]]
  [ "$(tool_calls)" = "rustup cargo-version rustc-version locate-project" ]
  grep -qx '### ❌ Failed at Locate lockfile' "$GITHUB_STEP_SUMMARY"
  grep -qF '| Lockfile | ❌ Missing |' "$GITHUB_STEP_SUMMARY"
}

@test "a failed lockfile generation stops the run" {
  rm "$project/Cargo.lock"
  export MOCK_GENERATE_FAIL=true
  run_audit
  [ "$status" -eq 1 ]
  [[ "$output" == *"cargo generate-lockfile failed"* ]]
  [[ "$output" == *"  cargo: error: failed to select a version"* ]]
  export MOCK_GENERATE_STDOUT=::error::injected
  run_audit
  [ "$status" -eq 1 ]
  assert_no_injected_command
  [[ "$output" == *"  cargo: ::error::injected"* ]]
  [[ "$(tool_calls)" != *audit* ]]
}

@test "a workspace member is audited through the workspace's Cargo.lock" {
  mkdir -p "$project/member"
  cp "$project/Cargo.toml" "$project/member/Cargo.toml"
  export INPUT_MANIFEST_PATH=member/Cargo.toml
  export MOCK_EXPECT_MANIFEST="$project/member/Cargo.toml"
  export MOCK_WORKSPACE_MANIFEST="$project/Cargo.toml"
  run_audit
  [ "$status" -eq 0 ]
  [ "$(call_field locate-project 2)" = "$project/member" ]
  [ "$(call_field audit 2)" = "$project" ]
  [ "$(audit_args)" = "audit --json --file $project/Cargo.lock" ]
  rm "$project/Cargo.lock"
  run_audit
  [ "$status" -eq 0 ]
  [ -f "$project/Cargo.lock" ]
  [ ! -e "$project/member/Cargo.lock" ]
}

@test "the workspace root cargo names must be inside the workspace" {
  mkdir -p "$BATS_TEST_TMPDIR/outside"
  export MOCK_LOCATE_OUTPUT="$BATS_TEST_TMPDIR/outside/Cargo.toml"
  run_audit
  [ "$status" -eq 1 ]
  [[ "$output" == *"The Cargo workspace root must resolve within the workspace"* ]]
  local value
  for value in Cargo.toml "$project/Cargo.lock" "$project/Cargo.toml"$'\n'"/x/Cargo.toml"; do
    export MOCK_LOCATE_OUTPUT="$value"
    run_audit
    [ "$status" -eq 1 ]
    [[ "$output" == *"cargo named an unexpected workspace manifest"* ]]
  done
  unset MOCK_LOCATE_OUTPUT
  export MOCK_LOCATE_FAIL=true
  run_audit
  [ "$status" -eq 1 ]
  [[ "$output" == *"cargo could not locate the workspace for manifest_path"* ]]
  [[ "$output" == *"  cargo: error: could not find Cargo.toml"* ]]
}

@test "Cargo.lock must be a regular file, not a symlink" {
  mv "$project/Cargo.lock" "$BATS_TEST_TMPDIR/real.lock"
  ln -s "$BATS_TEST_TMPDIR/real.lock" "$project/Cargo.lock"
  run_audit
  [ "$status" -eq 1 ]
  [[ "$output" == *"Cargo.lock must not be a symlink"* ]]
  [[ "$(tool_calls)" != *audit* ]]
  rm "$project/Cargo.lock"
  mkdir "$project/Cargo.lock"
  run_audit
  [ "$status" -eq 1 ]
  [[ "$output" == *"Cargo.lock is not a regular file"* ]]
}

### cargo-audit findings ###

@test "vulnerabilities fail the run with outputs, annotations and rows" {
  export MOCK_AUDIT_REPORT="$fixtures/audit-findings.json"
  run_audit
  [ "$status" -eq 1 ]
  [ "$(output_value audit_outcome)" = "failed" ]
  [ "$(output_value vulnerability_count)" = "3" ]
  [ "$(output_value vulnerability_ids)" = "RUSTSEC-2020-0071 RUSTSEC-2023-0071" ]
  [ "$(output_value warning_count)" = "4" ]
  [[ "$output" == *"::error title=RUSTSEC-2020-0071::time 0.1.43: Potential segfault in the time crate. Patched versions: >=0.2.23"* ]]
  [[ "$output" == *"::error title=RUSTSEC-2023-0071::rsa 0.9.6: Marvin Attack"*"Patched versions: none"* ]]
  [[ "$output" == *"::warning title=unmaintained%3A ansi_term 0.12.1::ansi_term is Unmaintained"* ]]
  [[ "$output" == *"::warning title=yanked%3A cfg-if 1.0.2::Yanked from its registry"* ]]
  [[ "$output" == *"::error::cargo-audit found 3 vulnerabilities: RUSTSEC-2020-0071 RUSTSEC-2023-0071."* ]]
  local s="$GITHUB_STEP_SUMMARY"
  grep -qx '### ❌ Failed at Audit with cargo-audit' "$s"
  grep -qxF '| Vulnerabilities | ❌ 3 found |' "$s"
  grep -qxF '| Warnings | ⚠️ 2 unmaintained, 1 unsound, 1 yanked; none denied |' "$s"
  grep -qxF '| [RUSTSEC-2020-0071](https://rustsec.org/advisories/RUSTSEC-2020-0071.html) | <code>time</code> | 0.1.43 | Potential segfault in the time crate | &gt;=0.2.23 |' "$s"
  grep -qF '| <code>rsa</code> | 0.9.6 | Marvin Attack: potential key recovery through timing sidechannels | None |' "$s"
  grep -qxF '| yanked | ➖ | <code>cfg-if</code> | 1.0.2 | Yanked from its registry |' "$s"
  grep -qxF '| unsound | [RUSTSEC-2021-0145](https://rustsec.org/advisories/RUSTSEC-2021-0145.html) | <code>atty</code> | 0.2.14 | Potential unaligned read |' "$s"
  [ "$(grep -c "^| \[RUSTSEC" "$s")" -eq 3 ]
}

@test "permit_fail reports findings as warnings and passes the step" {
  export MOCK_AUDIT_REPORT="$fixtures/audit-findings.json" INPUT_PERMIT_FAIL=true
  run_audit
  [ "$status" -eq 0 ]
  [ "$(output_value audit_outcome)" = "failed" ]
  [ "$(output_value vulnerability_count)" = "3" ]
  [[ "$output" == *"::warning title=RUSTSEC-2020-0071::time 0.1.43"* ]]
  [[ "$output" != *"::error title="* ]]
  [[ "$output" != *"::error::"* ]]
  [[ "$output" == *"::warning::cargo-audit found 3 vulnerabilities"* ]]
  [[ "$output" == *"::warning::Failed at Audit with cargo-audit; permit_fail is 'true'"* ]]
  grep -qx '### ⚠️ Failed at Audit with cargo-audit (permitted)' "$GITHUB_STEP_SUMMARY"
}

@test "ignoring every vulnerability passes, warnings still listed" {
  export MOCK_AUDIT_REPORT="$fixtures/audit-findings.json"
  export INPUT_IGNORE_VULNS="RUSTSEC-2023-0071"
  allow_list allow.txt 'RUSTSEC-2020-0071 # time 0.1: no fix\n'
  run_audit
  [ "$status" -eq 0 ]
  [ "$(output_value audit_outcome)" = "passed" ]
  [ "$(output_value vulnerability_count)" = "0" ]
  [ "$(output_value vulnerability_ids)" = "" ]
  [ "$(output_value warning_count)" = "4" ]
  grep -qxF '| Ignored | 2: RUSTSEC-2023-0071 RUSTSEC-2020-0071 |' "$GITHUB_STEP_SUMMARY"
  grep -qxF '| Warnings | ⚠️ 2 unmaintained, 1 unsound, 1 yanked; none denied |' "$GITHUB_STEP_SUMMARY"
}

@test "deny_warnings fails the run on each denied kind present" {
  export MOCK_AUDIT_REPORT="$fixtures/audit-findings.json"
  export INPUT_IGNORE_VULNS="RUSTSEC-2020-0071 RUSTSEC-2023-0071"
  local kind expected
  for kind in unmaintained:2 unsound:1 yanked:1; do
    expected="${kind#*:}"
    kind="${kind%:*}"
    export INPUT_DENY_WARNINGS="$kind"
    run_audit
    [ "$status" -eq 1 ]
    [ "$(output_value audit_outcome)" = "failed" ]
    [[ "$output" == *"deny_warnings fails the run on $expected warning"*" ($kind)."* ]]
    grep -qF "denied: $kind |" "$GITHUB_STEP_SUMMARY"
  done
  export INPUT_DENY_WARNINGS="unsound yanked"
  run_audit
  [ "$status" -eq 1 ]
  [[ "$output" == *"deny_warnings fails the run on 2 warnings (unsound, yanked)."* ]]
}

@test "a failed yanked lookup fails the audit when deny_warnings names yanked" {
  export INPUT_DENY_WARNINGS=yanked
  export MOCK_AUDIT_STDERR="error: couldn't check if the package is yanked: index lookup failed"
  run_audit
  [ "$status" -eq 1 ]
  [ "$(output_value audit_outcome)" = "failed" ]
  [[ "$output" == *"::error::cargo-audit could not check 1 crate for yanked releases; see the step log. deny_warnings names yanked, so the audit is incomplete."* ]]
  grep -qF '| Warnings | ✅ None; ⚠️ yanked check incomplete |' "$GITHUB_STEP_SUMMARY"
  export INPUT_PERMIT_FAIL=true
  run_audit
  [ "$status" -eq 0 ]
  [ "$(output_value audit_outcome)" = "failed" ]
  [[ "$output" == *"::warning::cargo-audit could not check 1 crate for yanked releases"* ]]
  [[ "$output" != *"::error::"* ]]
}

@test "a failed yanked lookup only warns when yanked crates are not denied" {
  local line="error: couldn't check if the package is yanked"
  export INPUT_DENY_WARNINGS=unsound
  export MOCK_AUDIT_STDERR="$line: a"$'\n'"$line: b"
  run_audit
  [ "$status" -eq 0 ]
  [ "$(output_value audit_outcome)" = "passed" ]
  [[ "$output" == *"::warning::cargo-audit could not check 2 crates for yanked releases; see the step log."* ]]
  grep -q '^- cargo-audit could not check 2 crates for yanked releases' "$GITHUB_STEP_SUMMARY"
}

@test "an ignored advisory also clears its warning from deny_warnings" {
  export MOCK_AUDIT_REPORT="$fixtures/audit-findings.json"
  export INPUT_IGNORE_VULNS="RUSTSEC-2020-0071 RUSTSEC-2023-0071 RUSTSEC-2021-0145"
  export INPUT_DENY_WARNINGS=unsound
  run_audit
  [ "$status" -eq 0 ]
  [ "$(output_value warning_count)" = "3" ]
}

@test "vulnerabilities and denied warnings are reported together" {
  export MOCK_AUDIT_REPORT="$fixtures/audit-findings.json" INPUT_DENY_WARNINGS=yanked
  run_audit
  [ "$status" -eq 1 ]
  [[ "$output" == *"cargo-audit found 3 vulnerabilities: RUSTSEC-2020-0071 RUSTSEC-2023-0071. deny_warnings fails the run on 1 warning (yanked)."* ]]
}

@test "ignores from the project's own configuration are reported" {
  export MOCK_AUDIT_REPORT="$fixtures/audit-findings.json"
  export MOCK_PROJECT_IGNORES="RUSTSEC-2023-0071 RUSTSEC-2021-0139"
  export INPUT_IGNORE_VULNS="RUSTSEC-2020-0071"
  run_audit
  [ "$status" -eq 0 ]
  [[ "$output" == *"::warning::The project's cargo-audit configuration ignores further advisories: RUSTSEC-2023-0071 RUSTSEC-2021-0139"* ]]
  grep -qF -- "- The project's cargo-audit configuration ignores further advisories" "$GITHUB_STEP_SUMMARY"
}

@test "cargo-audit failing without a gated finding still fails" {
  export MOCK_AUDIT_EXIT=1
  run_audit
  [ "$status" -eq 1 ]
  [[ "$output" == *"cargo-audit exited with status 1 without a finding this action gates on"* ]]
  [ "$(output_value audit_outcome)" = "failed" ]
}

@test "cargo-audit's other exit statuses fail even with a report" {
  export MOCK_AUDIT_EXIT=2
  run_audit
  [ "$status" -eq 1 ]
  [[ "$output" == *"cargo-audit exited with status 2"* ]]
  grep -qxF '| cargo-audit | ❌ Exit status 2 |' "$GITHUB_STEP_SUMMARY"
}

@test "a missing, garbled or misshapen report fails without a report path" {
  local value
  for value in "" "not json" '{"vulnerabilities":{"list":[{"advisory":{}}]},"warnings":{}}' \
    '{"vulnerabilities":{"list":[]},"warnings":{"yanked":{}}}' '[]'; do
    export MOCK_AUDIT_STDOUT="$value"
    run_audit
    [ "$status" -eq 1 ]
    [[ "$output" == *"cargo-audit produced no report (exit status 1)"* ]]
    [ "$(output_value report_path)" = "" ]
    [ "$(output_value audit_outcome)" = "failed" ]
    [ "$(output_value upload_reports)" = "false" ]
    [ -z "$(ls -A "$(output_value artefact_path)")" ]
    grep -qxF '| cargo-audit | ❌ No report |' "$GITHUB_STEP_SUMMARY"
  done
}

@test "an advisory ID outside the RUSTSEC form stops the run" {
  local value
  for value in "RUSTSEC-2020-0071 ::error::injected" "GHSA-wcg3-cvx6-7396" \
    "RUSTSEC-2020-0071"$'\n'"::error::injected"; do
    jq --arg id "$value" '.vulnerabilities.list[1].advisory.id = $id' \
      "$fixtures/audit-findings.json" > "$workdir/report.json"
    export MOCK_AUDIT_REPORT="$workdir/report.json"
    run_audit
    [ "$status" -eq 1 ]
    [[ "$output" == *"cargo-audit reported an advisory ID outside the form RUSTSEC-YYYY-NNNN"* ]]
    [ "$(output_value vulnerability_ids)" = "" ]
    assert_no_injected_command
  done
}

@test "large reports cap each summary table at 200 rows" {
  jq '.vulnerabilities.list = [range(205) as $i | .vulnerabilities.list[0]]
    | .warnings.yanked = [range(203) as $i | .warnings.yanked[0]]' \
    "$fixtures/audit-findings.json" > "$workdir/report.json"
  export MOCK_AUDIT_REPORT="$workdir/report.json"
  run_audit
  [ "$status" -eq 1 ]
  [ "$(output_value vulnerability_count)" = "205" ]
  [ "$(output_value vulnerability_ids)" = "RUSTSEC-2020-0071" ]
  [ "$(output_value warning_count)" = "206" ]
  [ "$(grep -c '^::error title=RUSTSEC' <<< "$output")" -eq 200 ]
  [ "$(grep -c '^| \[RUSTSEC-2020-0071\]' "$GITHUB_STEP_SUMMARY")" -eq 200 ]
  grep -qxF '| ➖ | 5 more | ➖ | See the report | ➖ |' "$GITHUB_STEP_SUMMARY"
  grep -qxF '| ➖ | ➖ | 6 more | ➖ | See the report |' "$GITHUB_STEP_SUMMARY"
}

### Untrusted text ###

@test "report text is escaped in the summary and inert in the log" {
  report_with_title $'<img src=x> | **bold** [a](http://x) `c` _u_ ~s~ \\ &amp;\n::error::injected'
  jq '.vulnerabilities.list[0].package.name = "evil|<b>"
    | .warnings.unmaintained[0].advisory.title = "w\r\n::error::injected"' \
    "$workdir/report.json" > "$workdir/report2.json"
  export MOCK_AUDIT_REPORT="$workdir/report2.json"
  export MOCK_AUDIT_STDERR="::error::injected"
  run_audit
  [ "$status" -eq 1 ]
  assert_no_injected_command
  [[ "$output" == *"  cargo-audit: ::error::injected"* ]]
  local s="$GITHUB_STEP_SUMMARY"
  grep -qF '| <code>evil&#124;&lt;b&gt;</code> | 0.1.43 | &lt;img src=x&gt; &#124; &#42;&#42;bold&#42;&#42; &#91;a&#93;(http://x) &#96;c&#96; &#95;u&#95; &#126;s&#126; &#92; &amp;amp; ::error::injected |' "$s"
  run ! grep -q '<img\|<b>' "$s"
  run ! grep -q '^::error' "$s"
  [ "$(grep -c '^| ' "$s")" -eq "$(grep -c '^|' "$s")" ]
}

@test "workflow command properties and data are escaped" {
  jq '.warnings.unmaintained[0].package.name = "a,b::c"
    | .warnings.unmaintained[0].advisory.title = "100% done"' \
    "$fixtures/audit-findings.json" > "$workdir/report.json"
  export MOCK_AUDIT_REPORT="$workdir/report.json"
  run_audit
  [[ "$output" == *"::warning title=unmaintained%3A a%2Cb%3A%3Ac 0.12.1::100%25 done"* ]]
}

### cargo-deny ###

@test "cargo-deny passes with its defaults and a warning when no config exists" {
  export INPUT_DENY_ENABLED=true INPUT_DENY_CHECKS="advisories bans sources"
  run_audit
  [ "$status" -eq 0 ]
  [ "$(output_value deny_outcome)" = "passed" ]
  [ "$(output_value audit_outcome)" = "passed" ]
  [ "$(tool_calls)" = "rustup cargo-version rustc-version locate-project audit deny" ]
  local config
  config="$(sed -n '8p' "$MOCK_DENY_ARGS")"
  [[ "$config" == "$RUNNER_TEMP"/rust-audit.*/default-deny.toml ]]
  [ ! -s "$config" ]
  [ "$(deny_args)" = "--format json --color never --manifest-path $project/Cargo.toml --config $config --locked check advisories bans sources" ]
  [[ "$output" == *"::warning::No deny.toml found, so cargo-deny runs with its defaults"* ]]
  grep -qxF '| cargo-deny | ✅ Passed: advisories, bans, sources; config: cargo-deny defaults |' "$GITHUB_STEP_SUMMARY"
}

@test "a clean cargo-deny run still writes a readable report" {
  # With --config, a clean run emits nothing but the summary record.
  export INPUT_DENY_ENABLED=true INPUT_DENY_CHECKS="advisories bans"
  run_audit
  [ "$status" -eq 0 ]
  local dir
  dir="$(output_value artefact_path)"
  [ "$(jq -r .type "$dir/cargo-deny.jsonl")" = "summary" ]
  [ "$(cat "$dir/cargo-deny.txt")" = "summary: advisories: errors 0, warnings 0, notes 0, helps 0
summary: bans: errors 0, warnings 0, notes 0, helps 0" ]
  [[ "$output" == *"  cargo-deny: summary: bans: errors 0, warnings 0, notes 0, helps 0"* ]]
}

@test "cargo-deny failures fail the run, naming each failed check" {
  export INPUT_DENY_ENABLED=true MOCK_DENY_LOG="$fixtures/deny-failed.jsonl"
  export MOCK_DENY_ERRORS="advisories=4 licenses=9"
  run_audit
  [ "$status" -eq 1 ]
  [ "$(output_value deny_outcome)" = "failed" ]
  [ "$(output_value audit_outcome)" = "passed" ]
  [[ "$output" == *"::error title=cargo-deny::Failed: advisories (4 errors), licenses (9 errors)"* ]]
  [[ "$output" == *"  cargo-deny: error[rejected]: "*"(ansi_term 0.12.1)"* ]]
  grep -qx '### ❌ Failed at Check with cargo-deny' "$GITHUB_STEP_SUMMARY"
  grep -qF '| cargo-deny | ❌ Failed: advisories (4 errors), licenses (9 errors); passed: bans, sources; config: cargo-deny defaults |' "$GITHUB_STEP_SUMMARY"
}

@test "findings from both tools are reported in one run" {
  export INPUT_DENY_ENABLED=true MOCK_DENY_ERRORS="bans=1"
  export MOCK_AUDIT_REPORT="$fixtures/audit-findings.json"
  run_audit
  [ "$status" -eq 1 ]
  [ "$(output_value audit_outcome)" = "failed" ]
  [ "$(output_value deny_outcome)" = "failed" ]
  [[ "$output" == *"::error::cargo-audit found 3 vulnerabilities: RUSTSEC-2020-0071 RUSTSEC-2023-0071. cargo-deny failed: bans (1 error)."* ]]
  grep -qx '### ❌ Failed at Audit with cargo-audit and cargo-deny' "$GITHUB_STEP_SUMMARY"
}

@test "permit_fail covers cargo-deny failures too" {
  export INPUT_DENY_ENABLED=true MOCK_DENY_ERRORS="licenses=2" INPUT_PERMIT_FAIL=true
  run_audit
  [ "$status" -eq 0 ]
  [ "$(output_value deny_outcome)" = "failed" ]
  [[ "$output" == *"::warning title=cargo-deny::Failed: licenses (2 errors)"* ]]
  [[ "$output" != *"::error"* ]]
  [[ "$output" == *"::warning::Failed at Check with cargo-deny; permit_fail is 'true'"* ]]
}

@test "cargo-deny finds the project's config, nearest first" {
  export INPUT_DENY_ENABLED=true
  local name
  for name in .cargo/deny.toml .deny.toml deny.toml; do
    mkdir -p "$project/.cargo"
    printf '[licenses]\nallow = ["MIT"]\n' > "$project/$name"
    run_audit
    [ "$status" -eq 0 ]
    [ "$(sed -n '8p' "$MOCK_DENY_ARGS")" = "$project/$name" ]
    [[ "$output" != *"No deny.toml found"* ]]
    grep -qF "config: <code>my project/$name</code> |" "$GITHUB_STEP_SUMMARY"
  done
  mkdir -p "$project/member"
  cp "$project/Cargo.toml" "$project/member/Cargo.toml"
  export INPUT_MANIFEST_PATH=member/Cargo.toml
  export MOCK_EXPECT_MANIFEST="$project/member/Cargo.toml"
  export MOCK_WORKSPACE_MANIFEST="$project/Cargo.toml"
  run_audit
  [ "$status" -eq 0 ]
  [ "$(sed -n '8p' "$MOCK_DENY_ARGS")" = "$project/deny.toml" ]
  [ "$(call_field deny 2)" = "$project/member" ]
  printf '' > "$project/member/.deny.toml"
  run_audit
  [ "$(sed -n '8p' "$MOCK_DENY_ARGS")" = "$project/member/.deny.toml" ]
}

@test "cargo-deny looks no higher than path_prefix" {
  export INPUT_DENY_ENABLED=true
  printf '' > "$workdir/deny.toml"
  run_audit
  [ "$status" -eq 0 ]
  [[ "$output" == *"No deny.toml found"* ]]
}

@test "a symlinked deny config is refused" {
  export INPUT_DENY_ENABLED=true
  printf '' > "$BATS_TEST_TMPDIR/deny.toml"
  ln -s "$BATS_TEST_TMPDIR/deny.toml" "$project/deny.toml"
  run_audit
  [ "$status" -eq 1 ]
  [[ "$output" == *"my project/deny.toml must be a regular file, not a symlink"* ]]
  [[ "$(tool_calls)" != *deny* ]]
  [ "$(output_value deny_outcome)" = "failed" ]
  [ "$(output_value audit_outcome)" = "passed" ]
}

@test "a deny config reached through a symlinked directory is refused" {
  export INPUT_DENY_ENABLED=true
  mkdir "$BATS_TEST_TMPDIR/outside"
  printf '' > "$BATS_TEST_TMPDIR/outside/deny.toml"
  ln -s "$BATS_TEST_TMPDIR/outside" "$project/.cargo"
  run_audit
  [ "$status" -eq 1 ]
  [[ "$output" == *"my project/.cargo/deny.toml must resolve within the workspace"* ]]
  [[ "$(tool_calls)" != *deny* ]]
  [ "$(output_value deny_outcome)" = "failed" ]
}

@test "cargo-deny licence exceptions from above the workspace are refused" {
  export INPUT_DENY_ENABLED=true
  local above
  above="$(cd "$BATS_TEST_TMPDIR" && pwd -P)"
  printf '' > "$above/.deny.exceptions.toml"
  run_audit
  [ "$status" -eq 1 ]
  [[ "$output" == *"cargo-deny would load licence exceptions from $above/.deny.exceptions.toml, outside the workspace"* ]]
  [[ "$(tool_calls)" != *deny* ]]
  [ "$(output_value deny_outcome)" = "failed" ]
}

@test "cargo-deny licence exceptions in the workspace are reported, not symlinks" {
  export INPUT_DENY_ENABLED=true
  mkdir "$workdir/.cargo"
  printf '' > "$workdir/.cargo/deny.exceptions.toml"
  run_audit
  [ "$status" -eq 0 ]
  grep -qF '; exceptions: <code>.cargo/deny.exceptions.toml</code> |' "$GITHUB_STEP_SUMMARY"
  printf '' > "$BATS_TEST_TMPDIR/exceptions.toml"
  ln -s "$BATS_TEST_TMPDIR/exceptions.toml" "$project/deny.exceptions.toml"
  : > "$MOCK_TOOL_LOG"
  run_audit
  [ "$status" -eq 1 ]
  [[ "$output" == *"my project/deny.exceptions.toml must be a regular file, not a symlink"* ]]
  [[ "$(tool_calls)" != *deny* ]]
}

@test "cargo-deny without a summary record fails at its stage" {
  export INPUT_DENY_ENABLED=true MOCK_DENY_EXIT=2
  export MOCK_DENY_STDERR=$'error: unexpected argument\n::error::injected\n'
  run_audit
  [ "$status" -eq 1 ]
  [[ "$output" == *"cargo-deny produced no summary (exit status 2)"* ]]
  [[ "$output" == *"  cargo-deny: output: ::error::injected"* ]]
  assert_no_injected_command
  grep -qF '| cargo-deny | ❌ No result (exit status 2) |' "$GITHUB_STEP_SUMMARY"
}

@test "cargo-deny failing with zero errors, or missing a check, still fails" {
  export INPUT_DENY_ENABLED=true MOCK_DENY_EXIT=1
  run_audit
  [ "$status" -eq 1 ]
  [[ "$output" == *"cargo-deny failed: exit status 1."* ]]
  export MOCK_DENY_EXIT=0
  export MOCK_DENY_STDERR='{"type":"summary","fields":{"advisories":{"errors":0},"bans":{"errors":"x"}}}'
  run_audit
  [ "$status" -eq 1 ]
  [[ "$output" == *"cargo-deny failed: bans (no result), licenses (no result), sources (no result)."* ]]
  export MOCK_DENY_STDERR='{"type":"summary","fields":{"advisories":{},"bans":{"errors":null},"licenses":{"errors":false},"sources":{"errors":0}}}'
  run_audit
  [ "$status" -eq 1 ]
  [[ "$output" == *"cargo-deny failed: advisories (no result), bans (no result), licenses (no result)."* ]]
}

@test "legacy ##[ commands and bare carriage returns in tool output stay inert" {
  export INPUT_DENY_ENABLED=true INPUT_DENY_CHECKS=bans MOCK_DENY_EXIT=0
  export MOCK_AUDIT_STDERR=$'note\r::error::injected ##[error]legacy\r\n'
  export MOCK_DENY_STDERR=$'{"type":"diagnostic","fields":{"severity":"error","code":"x","message":"##[warning]legacy"}}\n{"type":"log","fields":{"level":"WARN","message":"##[error]log"}}\n{"type":"summary","fields":{"bans":{"errors":0}}}\n'
  run_audit
  [ "$status" -eq 0 ]
  assert_no_injected_command
  [[ "$output" != *"##["* ]]
  [[ "$output" != *$'\r'* ]]
  [[ "$output" == *$'  cargo-audit: note\n  cargo-audit: ::error::injected # #[error]legacy\n'* ]]
  [[ "$output" == *"  cargo-deny: error[x]: # #[warning]legacy"* ]]
  [[ "$output" == *"  cargo-deny: WARN: # #[error]log"* ]]
  [[ "$output" == *"  cargo-deny: summary: bans: errors 0"* ]]
}

### Markdown and workflow-command helpers ###

@test "md_text flattens line breaks and control characters" {
  # shellcheck source=../scripts/markdown.sh
  source "$repo_dir/scripts/markdown.sh"
  [ "$(md_text $'a\nb\rc\td\x01e|f')" = "a b c d e&#124;f" ]
  [ "$(md_code $'x\n<y>')" = "<code>x &lt;y&gt;</code>" ]
}

@test "command_data and command_property escape their metacharacters" {
  # shellcheck source=../scripts/markdown.sh
  source "$repo_dir/scripts/markdown.sh"
  [ "$(command_data $'50%\r\n::error::x')" = "50%25%0D%0A::error::x" ]
  [ "$(command_property $'a:b,c\nd')" = "a%3Ab%2Cc%0Ad" ]
  [ "$(annotate notice "" $'one\ntwo')" = "::notice::one%0Atwo" ]
  [ "$(human_size 512)" = "512 B" ]
  [ "$(human_size 2048)" = "2.0 KiB" ]
  [ "$(human_size 3145728)" = "3.0 MiB" ]
}
