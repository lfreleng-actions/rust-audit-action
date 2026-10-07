#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

# Sourced by the stand-ins. record_call LOG CALL appends one line of
# '|'-separated fields to LOG: 1 CALL, 2 the working directory, then
# the value the caller sees of each variable in the loop below, in
# order from field 3 (CARGO_REGISTRY_TOKEN) to field 15
# (GITHUB_STEP_SUMMARY), or 'unset'.

record_call() {
  local log="$1" name
  local -a fields=("$2" "$(pwd -P)")
  for name in CARGO_REGISTRY_TOKEN CARGO_REGISTRIES_CRATES_IO_TOKEN \
    ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL \
    RUSTUP_TOOLCHAIN ACTIONS_RUNTIME_TOKEN CARGO_REGISTRIES_PRIVATE_TOKEN \
    CARGO_REGISTRIES_PRIVATE_INDEX GITHUB_OUTPUT GITHUB_ENV GITHUB_PATH \
    GITHUB_STATE GITHUB_STEP_SUMMARY; do
    fields+=("${!name-unset}")
  done
  (
    IFS='|'
    printf '%s\n' "${fields[*]}"
  ) >> "$log"
}
