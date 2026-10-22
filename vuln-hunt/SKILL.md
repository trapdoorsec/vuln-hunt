---
name: vuln-hunt
description: >
  Hunt for practical LFI, Path Traversal, LPE, RCE, and memory-safety vulnerabilities in
  source code. Use when the user wants to audit code for exploitable local file
  inclusion, path traversal, local privilege escalation, remote code execution, buffer
  overflows, use-after-free, or other memory corruption (C/C++ and Rust unsafe only), or
  asks for a security review focused on these classes. Produces a concise
  GitHub-issue-ready report and adversarially challenges every finding before reporting
  it.
---

# Practical Vulnerability Hunt (LFI / Path Traversal / LPE / RCE / Memory Safety)

Find *exploitable* vulnerabilities, not theoretical ones. Every finding must survive an
adversarial challenge before it reaches the report. If you cannot describe a concrete
path to exploitation, it does not belong in the report.

## Scope

Five vulnerability classes:

| Class | What it means |
|-------|---------------|
| **LFI** | Attacker-controlled path reaches a file read/include, disclosing arbitrary local files |
| **Path Traversal** | `../` (or an absolute path) escapes an intended base directory |
| **LPE** | A privileged context (setuid/root/sudo) performs an unsafe operation an unprivileged user can influence |
| **RCE** | Attacker-controlled data reaches a command/exec/eval/deserialization sink |
| **Memory Safety** | Reachable buffer overflow, use-after-free, double free, OOB access, or integer error corrupts memory — **C/C++ and Rust `unsafe`/FFI only** |

Memory-safety hunting applies only where the language allows it: **C/C++**, and **Rust
inside `unsafe` blocks or FFI** (including safe wrappers that leak unsoundness). Do not
report memory corruption in memory-safe languages (Python, Go, Ruby, C#, Java, JS); a
crash there is a runtime/FFI bug, not this class.

Ignore everything else (XSS, SQLi, CSRF, business logic, etc.) unless it directly enables
one of the classes above.

## Workflow

### Phase 1 — Recon

1. Identify the languages and frameworks in the repo (file extensions, manifests, build files).
2. Identify trust boundaries — where untrusted input enters: network sockets, HTTP
   handlers, CLI args, env vars, config files, IPC, file uploads, message queues.
3. Identify privileged contexts: setuid/setgid binaries, root services, sudo wrappers,
   daemons running as root, install scripts.

### Phase 2 — Hunt

Two parallel passes, then merge:

**Pass A — Semgrep Pro (automated candidate discovery).** If the Semgrep CLI is
available, run it first per `references/semgrep.md`. It produces high-recall taint
findings (including cross-file flows) for Path Traversal, LFI, RCE, and some memory
patterns. Filter to the in-scope classes and feed each finding to Phase 3.

**Pass B — Manual (language skills).** Semgrep does not cover LPE or memory safety and
misses domain-specific sinks. For each language present, load the matching language skill
via the `skill` tool and use it as the authoritative sink/source reference:

| Language | Skill ID |
|----------|----------|
| C / C++ | `vuln-hunt-c` |
| Rust | `vuln-hunt-rust` |
| Java / JVM | `vuln-hunt-java` |
| C# / .NET | `vuln-hunt-csharp` |
| Python | `vuln-hunt-python` |
| Go | `vuln-hunt-go` |
| Ruby | `vuln-hunt-ruby` |

**Memory-safety pass.** Run this only for C/C++ and Rust:
- **C/C++** — follow allocations, frees, lengths, indices, and object lifetimes, not just
  data flow. Look for BOF, UAF, double free, OOB, integer/length errors, and format
  strings (see `vuln-hunt-c`).
- **Rust** — enumerate every `unsafe` block, `extern "C"` boundary, and manual
  `Send`/`Sync` impl. Do not report memory bugs in safe code; the target is UB reachable
  through a safe API or FFI (see `vuln-hunt-rust`).

For languages without a dedicated skill, fall back to `references/patterns.md`. Trace
taint from source → sink. For each candidate record:

- `file:line` of the sink
- the source of attacker control
- the data-flow path (even if partial)
- any sanitization/validation observed along the way

Do **not** stop at the first grep hit. For every sink, determine whether the argument is
attacker-influenced and whether any check breaks the chain: `realpath`, `basename`,
allowlists, `chroot`, seccomp, privilege drop, shell quoting, `--` argument separators,
path canonicalization, `openat2` with `RESOLVE_BENEATH`, etc.

### Phase 3 — Adversarial challenge (mandatory)

For **every** candidate, spawn a subagent to attack the finding. Use the `general` agent
with the prompt template in `references/adversarial-prompt.md`. The subagent is a
skeptic whose job is to break the claim — do not tell it the finding is real.

The subagent must answer:

1. **Reachability** — can an attacker actually control the data at the sink?
2. **Mitigations** — is there a check that breaks the chain (validation, chroot, seccomp,
   privilege drop, quoting, allowlist, canonicalization)?
3. **Impact** — if exploitable, what does the attacker concretely gain? What privilege?
   Remote or local-only?
4. **Exploitability (memory-safety candidates)** — is there a controlled read or write,
   or only a crash? Which mitigations ship (canaries, NX, PIE/ASLR, RELRO, sanitizers,
   allocator hardening)? Is an info leak required and available?
5. **Verdict** — `CONFIRMED` / `REJECTED` / `UNPROVEN`, with one-line reasoning.

Run challenges in parallel where possible. A finding is reported only if the subagent
returns `CONFIRMED`. `UNPROVEN` findings are listed separately as "needs manual
verification" and are **not** reported as vulnerabilities.

### Phase 4 — Report

Emit a concise report using `references/report-template.md`. Include only `CONFIRMED`
findings. Keep each entry tight enough to paste directly into a GitHub issue.

## Rules

- **No theoretical findings.** If you cannot describe a concrete exploitation path, drop it.
- **Precision over recall.** A short list of real bugs beats a long list of noise.
- **Challenge everything.** A finding that survives the adversarial subagent is worth
  reporting; one that does not is not.
- **Respect scope.** Do not report issues outside the in-scope classes, and do not report
  memory corruption in memory-safe languages.
- **Read the code.** Never report a sink without tracing where its argument comes from.
