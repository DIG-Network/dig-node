#!/usr/bin/env bash
#
# Refuses a workflow whose `run:` step pipes a command into another without making the FIRST
# command's exit code load-bearing.
#
# The Actions default `run:` shell is `bash -e {0}` — `-e`, no `-o pipefail`. A pipeline's status is
# therefore its LAST command's, so `cargo test ... | tee out.txt` reports `tee`'s success and the
# step goes green on a suite that never ran. dig-node's REQUIRED "Test + coverage" check carried
# exactly that shape from 2026-07-04 to 2026-08-09; a run that died with `exit status: 102` reported
# the check green in 29 seconds (dig_ecosystem#2513).
#
# A step is pipefail-safe when either is true:
#   * it declares `shell: bash` — which Actions expands to `bash --noprofile --norc -eo pipefail {0}`
#     (or inherits that through workflow-/job-level `defaults.run.shell`), or
#   * its `run:` body sets pipefail itself (`set -o pipefail`, `set -euo pipefail`, ...).
#
# Steps on a non-bash shell (`pwsh`, `powershell`, `cmd`, `python`) are out of scope: they do not
# have bash pipeline semantics and are governed by their own status rules.
#
# Usage: check-workflow-pipefail.sh [workflow-dir]   (default: .github/workflows)
# Exit 0 = every piping step is safe; exit 1 = at least one swallows an exit code.
set -euo pipefail

DIR="${1:-.github/workflows}"

python3 - "$DIR" <<'PY'
import re, sys, pathlib

BASH_SHELLS = {"bash"}
# Shells whose pipeline semantics are not bash's; this gate makes no claim about them.
OUT_OF_SCOPE = {"pwsh", "powershell", "cmd", "python"}

def indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))

def strip_comment(line: str) -> str:
    """Drop a trailing shell comment. Naive on `#` inside quotes, which can only make the gate
    MORE permissive — never less — so it cannot manufacture a false finding."""
    out, quote = [], None
    for ch in line:
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "#":
            break
        out.append(ch)
    return "".join(out)

PIPE = re.compile(r"(?<!\|)\|(?!\|)")

def has_pipe(body: str) -> bool:
    for raw in body.splitlines():
        line = strip_comment(raw)
        # A pipe inside single/double quotes is data (a `grep -E 'a|b'` alternation), not a pipeline.
        unquoted = re.sub(r"'[^']*'|\"[^\"]*\"", "", line)
        if PIPE.search(unquoted):
            return True
    return False

def default_shell(text: str) -> str | None:
    """Workflow- or job-level `defaults: run: shell:` — an inherited shell is as good as a local one."""
    m = re.search(r"^\s*defaults:\s*$\n(?:\s+.*\n)*?\s+shell:\s*(\S+)", text, re.M)
    return m.group(1).strip("'\"") if m else None

def steps_of(lines):
    """Yield (step_lines) for each `- ` item under a `steps:` key."""
    i = 0
    while i < len(lines):
        if re.match(r"^\s*steps:\s*$", lines[i]):
            base = indent(lines[i])
            i += 1
            cur, item_indent = None, None
            while i < len(lines):
                line = lines[i]
                if line.strip() and indent(line) <= base:
                    break
                if re.match(r"^\s*- ", line) and (item_indent is None or indent(line) == item_indent):
                    if cur:
                        yield cur
                    item_indent = indent(line)
                    cur = [line]
                elif cur is not None:
                    cur.append(line)
                i += 1
            if cur:
                yield cur
            continue
        i += 1

def run_body(step_lines):
    """The shell text of the step's `run:`, block or inline; None when the step has no `run:`."""
    for idx, line in enumerate(step_lines):
        m = re.match(r"^(\s*)-?\s*run:\s*(.*)$", line)
        if not m:
            continue
        head = m.group(2).strip()
        if head not in ("|", "|-", ">", ">-", "|+"):
            return head
        key_indent = len(line) - len(line.lstrip(" ")) 
        body = []
        for nxt in step_lines[idx + 1:]:
            if nxt.strip() and indent(nxt) <= key_indent:
                break
            body.append(nxt)
        return "\n".join(body)
    return None

def shell_of(step_lines):
    for line in step_lines:
        m = re.match(r"^\s*-?\s*shell:\s*(\S+)", line)
        if m:
            return m.group(1).strip("'\"")
    return None

root = pathlib.Path(sys.argv[1])
findings = []
files = sorted(list(root.glob("*.yml")) + list(root.glob("*.yaml")))
for path in files:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    inherited = default_shell(text)
    for step in steps_of(lines):
        body = run_body(step)
        if body is None or not has_pipe(body):
            continue
        shell = shell_of(step) or inherited
        if shell in OUT_OF_SCOPE:
            continue
        if shell in BASH_SHELLS:
            continue
        if re.search(r"^\s*set\s+-[a-zA-Z]*o\s+pipefail", body, re.M) or \
           re.search(r"^\s*set\s+-o\s+pipefail", body, re.M):
            continue
        name = next((re.sub(r"^\s*-?\s*name:\s*", "", l).strip()
                     for l in step if re.match(r"^\s*-?\s*name:\s*\S", l)), "<unnamed step>")
        findings.append(f"{path.as_posix()}: step '{name}' pipes without pipefail "
                        f"(shell={shell or 'default bash -e'})")

if findings:
    print("::error::a piping run: step would report its LAST command's status, not the command that matters")
    for f in findings:
        print(f"  {f}")
    print("Fix: add `shell: bash`, or `set -o pipefail` as the first line of the run block.")
    sys.exit(1)

print(f"pipefail gate: {len(files)} workflow file(s) checked, every piping step is safe.")
PY
