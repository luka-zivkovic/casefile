#!/usr/bin/env bash
# Casefile composite GitHub Action runner.
#
# Runs `casefile scan` (and `casefile verify` when a lock is supplied) over an
# artifact directory, writes the JSON report and SARIF outside the artifact,
# publishes them as step outputs, and appends a short summary to
# $GITHUB_STEP_SUMMARY. The scanned artifact is never executed: the only
# commands run here are the Casefile CLI and a Node one-liner that formats the
# Casefile report.
#
# Inputs arrive as environment variables (see action.yml):
#   CASEFILE_PATH        artifact directory (default .)
#   CASEFILE_CONFIG      operator-owned policy passed as --config (optional)
#   CASEFILE_VERSION     published casefile version for `npx --yes casefile@<v>`
#   CASEFILE_FAIL_ON     critical | warning | none (default warning)
#   CASEFILE_STRICT      "true" adds --strict (default true)
#   CASEFILE_SARIF       "true" also writes SARIF (default true)
#   CASEFILE_LOCK        lock file; when set, `verify` also runs and drift fails
#   CASEFILE_OUTPUT_DIR  where reports are written (default $RUNNER_TEMP/casefile)
#   CASEFILE_COMMAND     override for the CLI invocation, used by tests
#
# Exit code (also written as the `exit-code` output):
#   0 gate passed and, when a lock was given, no drift
#   1 finding gate failed or the lock has evidence drift
#   2 invalid input, tampered lock, unsafe output path, or I/O failure
set -u -o pipefail

artifact="${CASEFILE_PATH:-.}"
config="${CASEFILE_CONFIG:-}"
version="${CASEFILE_VERSION:-}"
fail_on="${CASEFILE_FAIL_ON:-warning}"
strict="${CASEFILE_STRICT:-true}"
want_sarif="${CASEFILE_SARIF:-true}"
lock="${CASEFILE_LOCK:-}"
out_dir="${CASEFILE_OUTPUT_DIR:-${RUNNER_TEMP:-$(mktemp -d)}/casefile}"
github_output="${GITHUB_OUTPUT:-/dev/null}"
step_summary="${GITHUB_STEP_SUMMARY:-/dev/null}"

emit_output() {
  printf '%s=%s\n' "$1" "$2" >> "$github_output"
}

fail_input() {
  echo "casefile-action: $1" >&2
  emit_output exit-code 2
  emit_output report-json ''
  emit_output sarif ''
  exit 2
}

case "$fail_on" in
  critical | warning | none) ;;
  *) fail_input "fail-on must be critical, warning, or none (got '$fail_on')" ;;
esac

if [ -n "${CASEFILE_COMMAND:-}" ]; then
  read -r -a cli <<< "$CASEFILE_COMMAND"
else
  [ -n "$version" ] || fail_input "version input is required"
  cli=(npx --yes "casefile@${version}")
fi

mkdir -p "$out_dir" || fail_input "could not create output directory $out_dir"
report_json="$out_dir/casefile-report.json"
sarif_file="$out_dir/casefile-report.sarif"
verify_json="$out_dir/casefile-verify.json"
rm -f "$report_json" "$sarif_file" "$verify_json"

scan_flags=(--no-store)
verify_flags=()
if [ "$strict" = "true" ]; then
  scan_flags+=(--strict)
  verify_flags+=(--strict)
fi
if [ -n "$config" ]; then
  scan_flags+=(--config "$config")
  verify_flags+=(--config "$config")
fi

echo "casefile-action: scanning $artifact (fail-on=$fail_on strict=$strict)"
"${cli[@]}" scan "$artifact" --json --out "$report_json" --fail-on "$fail_on" "${scan_flags[@]}" > /dev/null
scan_exit=$?

sarif_exit=0
if [ "$want_sarif" = "true" ] && [ "$scan_exit" -ne 2 ]; then
  "${cli[@]}" scan "$artifact" --sarif --out "$sarif_file" --fail-on none "${scan_flags[@]}" > /dev/null
  sarif_exit=$?
fi

verify_exit=0
if [ -n "$lock" ]; then
  echo "casefile-action: verifying $artifact against $lock"
  "${cli[@]}" verify "$artifact" --lock "$lock" --json "${verify_flags[@]+"${verify_flags[@]}"}" > "$verify_json"
  verify_exit=$?
fi

final=0
if [ "$scan_exit" -eq 2 ] || [ "$sarif_exit" -eq 2 ] || [ "$verify_exit" -eq 2 ]; then
  final=2
elif [ "$scan_exit" -eq 1 ] || [ "$verify_exit" -eq 1 ]; then
  final=1
fi

[ -f "$report_json" ] || report_json=''
[ -f "$sarif_file" ] || sarif_file=''
[ -n "$lock" ] && [ -f "$verify_json" ] || verify_json=''

emit_output exit-code "$final"
emit_output report-json "$report_json"
emit_output sarif "$sarif_file"

# Format the summary from Casefile's own JSON. Report text is already
# sanitized by Casefile; the table escaping below only protects Markdown.
node - "$report_json" "$verify_json" "$fail_on" "$strict" "$scan_exit" "$verify_exit" "$final" "$lock" <<'JS' >> "$step_summary"
const fs = require('node:fs');
const [reportPath, verifyPath, failOn, strict, scanExit, verifyExit, final, lock] = process.argv.slice(2);
const cell = (v) => String(v ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\|/g, '\\|').replace(/`/g, "'");
const lines = ['## Casefile', ''];
let report;
if (reportPath) {
  try { report = JSON.parse(fs.readFileSync(reportPath, 'utf-8')); } catch { report = undefined; }
}
if (!report) {
  lines.push(`Casefile could not produce a report (scan exit ${scanExit}). See the step log.`, '');
} else {
  const { artifact, summary } = report;
  lines.push(
    `- Artifact: \`${cell(artifact.type)}\` · files scanned: ${summary.filesScanned} · content hash \`sha256:${cell(artifact.contentHash)}\``,
    `- Report identity: \`sha256:${cell(report.identity.digest)}\` · casefile ${cell(report.tool.version)}`,
    `- Gate: \`--fail-on ${failOn}\`${strict === 'true' ? ' with `--strict`' : ''} → ${scanExit === '0' ? '**passed**' : '**failed**'} (exit ${scanExit})`,
  );
  if (lock) {
    let verify;
    if (verifyPath) {
      try { verify = JSON.parse(fs.readFileSync(verifyPath, 'utf-8')); } catch { verify = undefined; }
    }
    if (verify && verify.exact) {
      lines.push(`- Lock: **exact match** (\`sha256:${cell(verify.lockDigest.digest)}\`)`);
    } else if (verify) {
      const d = verify.drift;
      lines.push(
        `- Lock: **drift detected** (exit ${verifyExit}) — artifact ${d.artifact.changed ? 'changed' : 'unchanged'}, policy ${d.policy.changed ? 'changed' : 'unchanged'}, report identity ${d.reportIdentity.changed ? 'changed' : 'unchanged'}, findings +${d.findings.added.length} −${d.findings.removed.length} ~${d.findings.changed.length}`,
      );
    } else {
      lines.push(`- Lock: **verification failed** (exit ${verifyExit}); the lock may be invalid or tampered. See the step log.`);
    }
  }
  lines.push('', '| Severity | Count |', '|---|---:|');
  for (const key of ['critical', 'warning', 'info', 'suppressed']) lines.push(`| ${key} | ${summary[key]} |`);
  const top = report.findings.slice(0, 10);
  if (top.length > 0) {
    lines.push('', `### Top findings (${top.length} of ${report.findings.length})`, '', '| Severity | Rule | Location | Message |', '|---|---|---|---|');
    for (const f of top) {
      const loc = f.line === undefined ? f.file : `${f.file}:${f.line}`;
      lines.push(`| ${cell(f.severity)} | \`${cell(f.ruleId)}\` | \`${cell(loc)}\` | ${cell(f.message)} |`);
    }
  } else {
    lines.push('', 'No active findings at this gate.');
  }
}
lines.push('', `Result: exit code **${final}**.`, '', '_Findings are static review signals, not verdicts. Casefile never executes the artifact, and a clean scan does not prove that it is behaviorally safe._', '');
process.stdout.write(lines.join('\n'));
JS

echo "casefile-action: exit code $final (scan=$scan_exit verify=$verify_exit)"
exit "$final"
