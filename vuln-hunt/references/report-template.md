# Report Template

Emit one block per `CONFIRMED` finding. Keep it tight — the goal is a GitHub issue body,
not a thesis. Order by severity (Critical first).

## Overall structure

```
# Security findings: <class summary>

<finding block>
<finding block>
...

## Needs manual verification
<UNPROVEN findings, one line each, or "none">
```

## Finding block

```markdown
### [<SEVERITY>] <Title>

**Type:** <RCE | LFI | Path Traversal | LPE | Memory Safety>
**CWE:** <CWE-XX>
**Location:** `<file>:<line>`

**Summary**
<1–2 sentences: what the bug is and why it matters.>

**Exploitation path**
<source> → <sink>. <Concrete conditions/steps an attacker needs.>

**Impact**
<What the attacker gains, privilege level, remote vs local.>

**Fix**
<Specific remediation — the actual code change, not generic advice.>
```

## Severity guide

| Severity | Criteria |
|----------|----------|
| **Critical** | Remote RCE, or LPE to root, with no preconditions; remotely reachable memory corruption with a controlled write |
| **High** | Remote RCE/LFI with auth or config preconditions; local LPE to root; UAF/OOB in a network-facing or privileged service |
| **Medium** | Local-only RCE/LFI; LPE to a non-root user; path traversal with limited impact; memory bug needing a hard-to-meet layout/race |
| **Low** | Requires unusual config, race, or already-privileged attacker; crash-only memory bug with no demonstrated primitive |

## CWE quick reference

| Class | Common CWE |
|-------|-----------|
| RCE (command injection) | CWE-78 |
| RCE (eval/deserialization) | CWE-94 / CWE-502 |
| LFI | CWE-98 |
| Path Traversal | CWE-22 |
| LPE (unsafe file ops) | CWE-269 / CWE-59 / CWE-377 |
| Memory: buffer overflow | CWE-120 / CWE-121 / CWE-122 / CWE-787 |
| Memory: use-after-free | CWE-416 |
| Memory: double free | CWE-415 |
| Memory: out-of-bounds read | CWE-125 |
| Memory: integer overflow/wraparound | CWE-190 |
| Memory: format string | CWE-134 |
| Memory: uninitialized use | CWE-457 |

## Example

```markdown
### [High] Command injection via window title in backtick handler

**Type:** RCE
**CWE:** CWE-78
**Location:** `src/backtick.c:412`

**Summary**
The backtick command handler passes an attacker-controlled string to `system()` without
quoting, allowing command injection.

**Exploitation path**
A remote or local user sets a window title containing shell metacharacters → the title is
concatenated into a command string → `system(cmd)` executes it with the screen process's
privileges.

**Impact**
Arbitrary command execution as the user running screen; if screen is setuid, this is
privilege escalation to that user.

**Fix**
Avoid `system()`; build an argv array and call `execvp()`, or validate/quote the title
against a strict allowlist before use.
```
