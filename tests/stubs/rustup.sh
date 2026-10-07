#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

# Stand-in for 'rustup show active-toolchain'. Records where it ran and
# the environment it sees (record.sh), and names MOCK_TOOLCHAIN, a
# channel or a path, the way rustup does.

set -euo pipefail
# shellcheck source=record.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/record.sh"

record_call "$MOCK_TOOL_LOG" rustup
if [ "$*" != "show active-toolchain" ]; then
  echo "rustup stand-in: unexpected arguments: $*" >&2
  exit 90
fi
if [ "${MOCK_RUSTUP_FAIL:-false}" = "true" ]; then
  echo "error: toolchain 'nightly-2026-01-01' is not installed" >&2
  exit 1
fi
printf '%s (overridden by rust-toolchain.toml)\n' \
  "${MOCK_TOOLCHAIN:-stable-x86_64-unknown-linux-gnu}"
