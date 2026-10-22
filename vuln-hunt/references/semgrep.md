# Semgrep Pro Integration

Semgrep Pro is the **candidate generator** for Phase 2 (Hunt). It provides high-recall
taint analysis (including cross-file/interfile flows) that manual grep cannot. It is
**not** the arbiter — every finding it produces still goes through the Phase 3
adversarial subagent.

## Role in the workflow

| Step | Tool | Output |
|------|------|--------|
| Candidate discovery | Semgrep Pro | Raw findings (noisy, high recall) |
| Class filtering | jq / manual | Findings mapped to the 4 classes |
| Verification | Adversarial subagent | `CONFIRMED` / `REJECTED` / `UNPROVEN` |

## Invocation

Run from the repo root:

```bash
semgrep scan --pro \
  --config p/security-audit \
  --config p/owasp-top-ten \
  --json \
  --metrics off \
  --output semgrep-results.json .
```

Notes:

- `--pro` enables the proprietary engine with **interfile taint** — the key value over
  OSS. It traces data across function and file boundaries.
- `p/security-audit` is broad (high recall, more false positives — good, the subagent
  filters them).
- `p/owasp-top-ten` is high-signal (fewer, higher-confidence findings).
- `--json` is required for machine-readable parsing.
- `--metrics off` avoids telemetry noise in output.
- Add `--severity ERROR WARNING` to include warnings; default is ERROR only. For a
  thorough hunt, include WARNING.

## Filtering to the in-scope classes

Semgrep reports many classes (XSS, SQLi, CSRF, secrets, etc.). Keep only findings whose
CWE maps to LFI / Path Traversal / LPE / RCE / Memory Safety. Memory-safety findings are
kept only for C/C++ and Rust sources (and Rust only inside `unsafe`/FFI):

```bash
jq '[.results[] |
  select((.extra.metadata.cwe // []) |
    any(. ; test("CWE-(22|23|35|36|73|77|78|94|95|98|502|269|59|377|119|120|121|122|125|134|190|415|416|457|476|787)"))) |
  {check_id, path, line: .start.line, severity: .extra.severity,
   cwe: .extra.metadata.cwe, confidence: .extra.metadata.confidence,
   message: .extra.message}]' semgrep-results.json
```

### CWE → class mapping

| CWE | Class |
|-----|-------|
| CWE-22, 23, 35, 36 | Path Traversal |
| CWE-73 | LFI / external file path control |
| CWE-98 | LFI (PHP include) |
| CWE-77, 78 | RCE (command injection) |
| CWE-94, 95 | RCE (code/eval injection) |
| CWE-502 | RCE (deserialization) |
| CWE-269, 59, 377 | LPE (privilege mgmt / link following / temp file) |
| CWE-119, 120, 121, 122, 787 | Memory: buffer overflow |
| CWE-125, 476 | Memory: out-of-bounds / NULL pointer |
| CWE-134 | Memory: format string |
| CWE-190 | Memory: integer overflow/wraparound |
| CWE-415, 416 | Memory: double free / use-after-free |
| CWE-457 | Memory: uninitialized use |

## Reading a finding

The JSON `results[]` entries carry everything the adversarial subagent needs:

```json
{
  "check_id": "rules.security.audit...",
  "path": "src/backtick.c",
  "start": { "line": 412, "col": 5 },
  "end":   { "line": 412, "col": 20 },
  "extra": {
    "severity": "ERROR",
    "message": "Detected user input flowing into system()...",
    "metadata": {
      "cwe": ["CWE-78"],
      "confidence": "HIGH",
      "owasp": ["A03:2021 - Injection"]
    },
    "dataflow_trace": { ... }   // Pro interfile taint path (source → sink)
  }
}
```

- `extra.dataflow_trace` is the taint path — feed it to the subagent as the "claimed data
  flow". It is the single most useful field for the adversarial challenge.
- `extra.metadata.confidence` (`HIGH`/`MEDIUM`/`LOW`) is a hint, not a verdict. LOW
  confidence findings are still worth challenging — they are often the interesting ones.

## Feeding the adversarial phase

For each filtered finding, spawn the `general` subagent with
`references/adversarial-prompt.md`, filling in:

- **Class** — from the CWE mapping above
- **Location** — `path:line`
- **Sink** — from `extra.message` / the code at `start`–`end`
- **Claimed source / data flow** — from `extra.dataflow_trace`

Run challenges in parallel (batch by file or by rule). The subagent verdict is final for
reporting purposes.

## What Semgrep Pro does NOT cover

- **LPE** — Semgrep has almost no rules for privilege-boundary issues (setuid/setgid,
  root context, sudo, TOCTOU, symlink/junction attacks, DLL search-order hijacking).
  These are contextual and must be hunted manually using the `vuln-hunt-*` language
  skills. Treat any CWE-269/59/377 hits as *hints* to investigate manually, not as
  complete findings.
- **Custom/domain-specific sinks** — if the codebase has its own wrappers around
  `system()`/`open()`/etc., Semgrep may miss them. The language skills' manual pass
  catches these.
- **Config-dependent reachability** — Semgrep does not know runtime config (auth, chroot,
  seccomp, privilege drop). The subagent resolves this.

## Workflow order (Phase 2)

1. Run Semgrep Pro (above), filter to the 4 classes.
2. Feed filtered findings to the adversarial subagent.
3. **In parallel**, run the manual LPE pass using the relevant `vuln-hunt-*` language
   skills (Semgrep won't find these).
4. Merge `CONFIRMED` findings from both paths into the report.

## Troubleshooting

- **Pro engine missing**: `semgrep install-semgrep-pro` (installs
  `semgrep-core-proprietary` into the semgrep package's `bin/`).
- **Auth**: `semgrep login` — the Pro engine requires a valid `api_token` in
  `~/.semgrep/settings.yml`.
- **Slow on large repos**: scope with `--include`/`--exclude`, or scan per-language
  subdirectories. Interfile analysis is slower than OSS.
- **No `dataflow_trace`**: the finding may be from a non-taint rule (pattern match only).
  Still challenge it, but note the trace is absent.
