#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

# Markdown and workflow-command helpers, sourced by rust-audit.sh.
#
# Every value that did not originate in this action passes through
# md_text or md_code before it reaches the job summary, and through
# command_data or command_property before it reaches a workflow
# command such as ::error::.

# Render untrusted text inert inside a Markdown table cell. HTML and
# Markdown metacharacters become numeric character references, and
# control characters (line breaks included) become spaces, so a value
# can neither leave its cell nor format, link or embed anything. Each
# replacement is quoted, keeping '&' literal under patsub_replacement.
md_text() {
  local text="$1"
  text=${text//&/"&amp;"}
  text=${text//</"&lt;"}
  text=${text//>/"&gt;"}
  text=${text//|/"&#124;"}
  text=${text//\`/"&#96;"}
  text=${text//\\/"&#92;"}
  text=${text//\[/"&#91;"}
  text=${text//\]/"&#93;"}
  text=${text//\*/"&#42;"}
  text=${text//_/"&#95;"}
  text=${text//\~/"&#126;"}
  text=${text//[[:cntrl:]]/" "}
  printf '%s' "$text"
}

# Render untrusted text as inline code. An HTML code element keeps
# working on escaped text, where a backtick span would show the
# character references literally.
md_code() {
  printf '<code>%s</code>' "$(md_text "$1")"
}

# Escape the message part of a workflow command.
command_data() {
  local text="$1"
  text=${text//%/%25}
  text=${text//$'\r'/%0D}
  text=${text//$'\n'/%0A}
  printf '%s' "$text"
}

# Escape a workflow command property value, such as title=.
command_property() {
  local text
  text="$(command_data "$1")"
  text=${text//:/%3A}
  text=${text//,/%2C}
  printf '%s' "$text"
}

# Print one workflow command: LEVEL (error, warning, notice), TITLE
# (may be empty) and MESSAGE.
annotate() {
  if [ -n "$2" ]; then
    printf '::%s title=%s::%s\n' "$1" "$(command_property "$2")" \
      "$(command_data "$3")"
  else
    printf '::%s::%s\n' "$1" "$(command_data "$3")"
  fi
}

# Print a byte count in binary units: '512 B', '12.3 KiB'.
human_size() {
  awk -v n="$1" 'BEGIN {
    u = "B"
    if (n >= 1048576) { n /= 1048576; u = "MiB" }
    else if (n >= 1024) { n /= 1024; u = "KiB" }
    if (u == "B") printf "%d %s", n, u
    else printf "%.1f %s", n, u
  }'
}
