#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

# Stand-in for 'rustc --version', the only rustc command rust-audit.sh
# runs. Records where it ran and the environment it sees (record.sh),
# and prints MOCK_RUSTC_VERSION the way rustc does.

set -euo pipefail
# shellcheck source=record.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/record.sh"

record_call "$MOCK_TOOL_LOG" rustc-version
if [ "$*" != "--version" ]; then
  echo "rustc stand-in: unexpected arguments: $*" >&2
  exit 90
fi
if [ "${MOCK_RUSTC_FAIL:-false}" = "true" ]; then
  echo "error: toolchain 'nightly-2026-01-01' is not installed" >&2
  exit 1
fi
echo "rustc ${MOCK_RUSTC_VERSION:-1.99.0} (b940084d7 2026-09-28)"
