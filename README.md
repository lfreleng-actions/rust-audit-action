<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# 🦀 Rust Dependency Audit

<!-- prettier-ignore-start -->
<!-- markdownlint-disable-next-line MD013 -->
[![Linux Foundation](https://img.shields.io/badge/Linux-Foundation-blue)](https://linuxfoundation.org/) [![Source Code](https://img.shields.io/badge/GitHub-100000?logo=github&logoColor=white&color=blue)](https://github.com/lfreleng-actions/rust-audit-action) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![pre-commit.ci status badge]][pre-commit.ci results page] [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/lfreleng-actions/rust-audit-action/badge)](https://scorecard.dev/viewer/?uri=github.com/lfreleng-actions/rust-audit-action)
<!-- prettier-ignore-end -->

Audits the dependencies of a Rust project against the
[RustSec advisory database](https://rustsec.org/) with
[cargo-audit](https://github.com/rustsec/rustsec/tree/main/cargo-audit),
and, on request, checks them with
[cargo-deny](https://github.com/EmbarkStudios/cargo-deny).

The action reads `Cargo.lock`; it never compiles the project.

## rust-audit-action

## Usage Example

<!-- markdownlint-disable MD046 -->

```yaml
steps:
  - name: "Checkout repository"
    uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
    with:
      persist-credentials: false

  - name: "Audit Rust dependencies"
    id: audit
    uses: lfreleng-actions/rust-audit-action@main
    with:
      lockfile_required: "true"
      allow_list_path: ".github/audit-allow.txt"
      deny_warnings: "unsound"
      deny_enabled: "true"
```

<!-- markdownlint-enable MD046 -->

Pin the action to a commit SHA in real workflows.

## Inputs

<!-- markdownlint-disable MD013 -->

| Name                | Required | Default                            | Description                                                                              |
| ------------------- | -------- | ---------------------------------- | ---------------------------------------------------------------------------------------- |
| path_prefix         | False    | `.`                                | Directory holding the Rust project, inside the workspace                                 |
| manifest_path       | False    | `Cargo.toml`                       | Path to the project's `Cargo.toml`, relative to `path_prefix`                            |
| toolchain           | False    | `''`                               | rustup channel to use; empty uses the toolchain the project selects                      |
| lockfile_required   | False    | `false`                            | Fail when `Cargo.lock` is missing, rather than generating one with a warning             |
| ignore_vulns        | False    | `''`                               | RUSTSEC advisory IDs for cargo-audit to ignore, whitespace-separated                     |
| allow_list_path     | False    | `''`                               | File of RUSTSEC IDs to ignore, one per line with `#` comments, relative to `path_prefix` |
| deny_warnings       | False    | `''`                               | cargo-audit warning kinds that fail the run: any of `unmaintained unsound yanked`        |
| deny_enabled        | False    | `false`                            | Also run cargo-deny                                                                      |
| deny_checks         | False    | `advisories bans licenses sources` | cargo-deny checks to run                                                                 |
| cargo_audit_version | False    | `0.22.2`                           | cargo-audit version to install                                                           |
| cargo_deny_version  | False    | `0.20.2`                           | cargo-deny version to install, when `deny_enabled` is `true`                             |
| permit_fail         | False    | `false`                            | Report success, with a warning, even when the audit fails                                |
| summary             | False    | `true`                             | Write the audit results to the job summary                                               |
| artefact_upload     | False    | `true`                             | Upload the reports as a workflow artefact, after a failed audit too                      |
| artefact_name       | False    | `rust-audit-results`               | Name of the report artefact; give each call in a workflow run its own                    |
| artefact_path       | False    | `''`                               | Empty or absent directory for the reports, relative to `path_prefix`                     |

<!-- markdownlint-enable MD013 -->

Boolean inputs accept `true` or `false` and nothing else.

## Outputs

<!-- markdownlint-disable MD013 -->

| Name                | Description                                                                          |
| ------------------- | ------------------------------------------------------------------------------------ |
| toolchain           | Toolchain used: a rustup channel, a path, or empty without rustup                    |
| toolchain_kind      | How the action chose the toolchain: `channel`, `path` or `none`                      |
| cargo_version       | Version of the cargo that ran the audit                                              |
| rustc_version       | Version of the selected toolchain's rustc                                            |
| audit_outcome       | cargo-audit result: `passed` or `failed`, even when `permit_fail` lets the step pass |
| vulnerability_count | Vulnerabilities cargo-audit found, after ignores                                     |
| warning_count       | cargo-audit warnings (unmaintained, unsound, yanked), after ignores                  |
| vulnerability_ids   | Space-separated RUSTSEC IDs of the vulnerabilities found                             |
| report_path         | Absolute path to cargo-audit's JSON report, in `artefact_path`                       |
| deny_report_path    | Absolute path to cargo-deny's JSON lines output; empty when cargo-deny did not run   |
| artefact_path       | Absolute path to the directory holding the reports                                   |
| artefact_name       | Name of the uploaded report artefact; empty when the action uploads nothing          |
| deny_outcome        | cargo-deny result: `passed`, `failed` or `skipped`                                   |

<!-- markdownlint-enable MD013 -->

## Implementation Details

The action runs these stages, and the job summary names the stage
where a run failed:

1. **Check inputs**: validates every input, the allow-list file
   included, before installing anything.
2. **Install audit tools**: installs prebuilt, checksum-verified
   binaries of cargo-audit (and cargo-deny) with
   [taiki-e/install-action](https://github.com/taiki-e/install-action),
   with no fallback to building from source.
3. **Resolve toolchain**: uses the `toolchain` input when set, which
   needs rustup. Otherwise asks `rustup show active-toolchain` which
   toolchain the project selects, without running it. Every later
   rustup, `cargo`, `rustc`, cargo-audit and cargo-deny call runs
   pinned to that channel through `RUSTUP_TOOLCHAIN`. Without rustup,
   the action uses `cargo` from `PATH` and reports `toolchain_kind` as
   `none`. Records the Cargo and rustc versions.
4. **Check tools**: confirms the installed versions match the inputs.
5. **Locate lockfile**: finds the workspace root with
   `cargo locate-project --workspace`, so a workspace member uses the
   workspace's `Cargo.lock`.
6. **Audit with cargo-audit**: runs from the workspace root, so the
   project's own `.cargo/audit.toml` applies.
7. **Check with cargo-deny**, when `deny_enabled` is `true`.
8. **Upload audit reports**, when `artefact_upload` is `true` and a
   report exists, also after a failed audit.

The action gathers findings from both tools before failing, so one run
reports everything. Each vulnerability becomes an error annotation (a
warning annotation under `permit_fail`), and each crate warning a
warning annotation, up to 200 of each; the job summary tables stop at
the same limit. The `vulnerability_count` and `warning_count` outputs
always give the full totals, and the JSON report at `report_path` holds
every finding.

### Report artefacts

The action writes its reports to one directory:

- `cargo-audit.json`: cargo-audit's JSON report, once it has the shape
  the action expects.
- `cargo-deny.jsonl` and `cargo-deny.txt`: cargo-deny's JSON lines
  output and a readable rendering of it, when cargo-deny ran and
  printed anything, whatever its result.

With `artefact_path` empty, that directory is a fresh one under
`RUNNER_TEMP`, so the action writes nothing into the checkout. Set
`artefact_path` to keep the reports in the workspace instead: it
resolves against `path_prefix`, must stay inside the workspace, must
not be a symlink, and must be empty or absent. The action checks it
again once it exists, and refuses to overwrite a report file that
something else created there. upload-artifact reads the directory path
as a glob pattern, so the path may not hold `*`, `?`, `[`, `]`, a
backslash, a control character or a trailing space.

With `artefact_upload: "true"`, the action uploads the directory as
the artefact `artefact_name` whenever it holds a report. The upload
also runs after the audit step fails, so a run with findings, failed or
permitted, keeps its evidence. An artefact name must be unique within
a workflow run: give each call (each matrix entry, or each audit in one
job) its own `artefact_name`. With `artefact_upload: "false"` the
reports stay on the runner, and `artefact_path` still names them.

### Ignoring advisories

cargo-audit matches `--ignore` against an advisory's RUSTSEC ID and
nothing else: it accepts a GHSA or CVE alias, or a lower-case ID, and
then ignores nothing. The action rejects those forms with a message
that names the alias, so name the RUSTSEC advisory that lists it.
Ignoring an advisory also hides any crate warning it raised.

An allow-list file holds one ID per line. A `#` at the start of a line,
or after whitespace, opens a comment:

```text
# time 0.1: no fixed release in the 0.1 series
RUSTSEC-2020-0071
RUSTSEC-2023-0071  # rsa: no fix available
```

`ignore_vulns` and `allow_list_path` apply to cargo-audit. cargo-deny
reads its ignores from `deny.toml`.

The allow-list may hold up to 1 MiB, and the two inputs together up to
5000 distinct IDs, about four times the RustSec database. The action
passes each ID to cargo-audit as a command-line argument, and far more
would exceed the operating system's argument limit.

When the project's `.cargo/audit.toml` ignores further advisories, the
action lists them as a warning.

### Crate warnings

cargo-audit reports unmaintained, unsound and yanked crates as
warnings, which do not fail the run. Name the kinds that should fail
it in `deny_warnings`.

cargo-audit asks the crates.io index whether each crate's release is
still available. When a lookup for one crate fails, it logs the error
and carries on with exit status 0. The action spots that log line:
with `yanked` in `deny_warnings` the audit fails as incomplete,
otherwise it warns. When cargo-audit cannot fetch or open the index at
all, it skips the yanked check and, in the JSON mode the action uses,
prints nothing, so the action cannot detect that case.

### Missing `Cargo.lock`

Without a `Cargo.lock`, the action runs `cargo generate-lockfile` and
warns: the audit then covers the newest compatible versions, not the
versions the project last locked. Set `lockfile_required: "true"` to
fail instead. Applications should commit their `Cargo.lock`.

### cargo-deny configuration

The action uses the first `deny.toml`, `.deny.toml` or
`.cargo/deny.toml` it finds, starting in the manifest's directory and
walking up no further than `path_prefix`. When `manifest_path` points
outside `path_prefix` (for example `../other/Cargo.toml`), the walk
stops at the workspace root instead. Without one, cargo-deny runs
with its defaults and the action warns: the default licence allow-list
is empty, so the `licenses` check rejects every crate. Either commit a
`deny.toml` or drop `licenses` from `deny_checks`.

cargo-deny also loads licence exceptions from the first
`deny.exceptions.toml`, `.deny.exceptions.toml` or
`.cargo/deny.exceptions.toml` in the manifest's directory or any
directory above it, whatever configuration file it receives. The
action looks for that file the same way, refuses it from outside the
workspace, and names it in the job summary.

### permit_fail

`permit_fail: "true"` covers every failure after input validation,
including a failed tool install, and turns the action's error
annotations into warnings. Invalid inputs always fail the step.
`audit_outcome` and `deny_outcome` still report the real result. A
failed tool install stops the action with `audit_outcome: failed` and
`deny_outcome: skipped`, with or without `permit_fail`: the action
never falls back to cargo-audit or cargo-deny binaries already on
`PATH`. It also covers a failed report upload, such as a duplicate
`artefact_name`: the step still passes, and upload-artifact's own
error annotation remains.

### Security

- Every `${{ }}` expression reaches the scripts through `env:`.
- rustup, cargo, rustc and the audit tools, version queries included, run
  without these variables in their environment:
  - `CARGO_REGISTRY_TOKEN` and every `CARGO_REGISTRIES_<NAME>_TOKEN`;
    a registry's other settings, such as `CARGO_REGISTRIES_<NAME>_INDEX`,
    stay;
  - `ACTIONS_ID_TOKEN_REQUEST_TOKEN`, `ACTIONS_ID_TOKEN_REQUEST_URL` and
    `ACTIONS_RUNTIME_TOKEN`;
  - the runner's command files: `GITHUB_OUTPUT`, `GITHUB_ENV`,
    `GITHUB_PATH`, `GITHUB_STATE` and `GITHUB_STEP_SUMMARY`, so that
    code they run cannot forge this step's outputs, inject environment
    variables or `PATH` entries into later steps, or spoof the job
    summary.

  This is defence in depth, not a security boundary: the command
  files' paths are predictable, so code running as the same user can
  still find them. The action's own outputs and summary still reach
  the runner.
- The action trusts the job it runs in. Its checks on the report
  directory (empty when created, no report written through a symlink)
  stop mistakes and stale files, not a hostile process running as the
  same user during the step: such a process could also rewrite the
  runner's command files, swap the report directory, or add files for
  the upload to collect. Run untrusted code in a separate job, as the
  `rust-workflows` lanes do; that separation is the boundary.
- Once a tool has run, the checks that keep files inside the workspace
  use bash builtins alone, so a program planted on `PATH` cannot
  answer for them.
- `path_prefix`, `manifest_path`, `allow_list_path`, `artefact_path`,
  `Cargo.lock`, any `deny.toml` and any licence exceptions file must
  resolve inside the workspace; symlinks to the files themselves, and
  an `artefact_path` that is a symlink, fail. The four path inputs
  may not hold control characters such as a newline.
- Text from the reports reaches the job summary escaped for Markdown,
  and the log through escaped workflow commands. The action prefixes
  each line of tool output with the tool's name, splits lines at bare
  carriage returns first and defuses legacy `##[command]` markers, so
  tool output cannot issue a workflow command. The same applies to
  the stdout of `cargo generate-lockfile` and to a toolchain path the
  project selects; a toolchain path holding a control character fails.
- Error messages name the input at fault and never echo a rejected
  value.

## Notes

- A project that selects its toolchain by path, rather than by channel
  name, runs unpinned from the project directory, with a warning.
- The workflow needs network access to `github.com` (the advisory
  database and the tool downloads), to GitHub's artefact storage when
  uploading reports, and, when the action generates a `Cargo.lock` or
  runs cargo-deny, to `index.crates.io`.

[pre-commit.ci results page]: https://results.pre-commit.ci/latest/github/lfreleng-actions/rust-audit-action/main
[pre-commit.ci status badge]: https://results.pre-commit.ci/badge/github/lfreleng-actions/rust-audit-action/main.svg
