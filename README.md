# vuln-hunt skills

A collection of [OpenCode](https://opencode.ai) skills for hunting **practical,
exploitable** vulnerabilities in source code — focused on five classes:

| Class | Meaning |
|-------|---------|
| **LFI** | Attacker-controlled path reaches a file read/include, disclosing arbitrary local files |
| **Path Traversal** | `../` (or an absolute path) escapes an intended base directory |
| **LPE** | A privileged context (setuid/root/sudo) performs an unsafe operation an unprivileged user can influence |
| **RCE** | Attacker-controlled data reaches a command/exec/eval/deserialization sink |
| **Memory Safety** | Buffer overflow, UAF, double free, OOB, or integer error — **C/C++ and Rust `unsafe`/FFI only** |

Memory-safety hunting is scoped to languages where it can occur: C/C++ and Rust `unsafe`
blocks/FFI. It is deliberately skipped for memory-safe languages (Python, Go, Ruby, C#,
Java, JS). Everything else (XSS, SQLi, CSRF, business logic, etc.) is intentionally out of
scope unless it directly enables one of the classes above.

## Skill layout

### Source-code hunting

One **master** skill and seven **language** helpers:

```
vuln-hunt/                 # master orchestrator (workflow + adversarial gate)
  SKILL.md
  references/
    patterns.md            # generic sink/source patterns for languages without a helper
    semgrep.md             # Semgrep Pro pass (automated candidate discovery)
    adversarial-prompt.md  # prompt template for the adversarial challenge
    report-template.md     # GitHub-issue-ready report format

vuln-hunt-c/               # C / C++
vuln-hunt-rust/            # Rust
vuln-hunt-java/            # Java / JVM (Spring, Jakarta EE, Struts)
vuln-hunt-csharp/          # C# / .NET
vuln-hunt-python/          # Python
vuln-hunt-go/              # Go
vuln-hunt-ruby/            # Ruby (incl. Rails)
```
## Installation

Copy (or symlink) the skill directories into your OpenCode skills directory:

```sh
# Default location (Linux/macOS)
mkdir -p ~/.config/opencode/skills
cp -R vuln-hunt vuln-hunt-* \
      ~/.config/opencode/skills/
```

Skills can also be installed under `~/.claude/skills/` if that is where your OpenCode
instance discovers them.

The skills are discovered automatically by their `name:` and `description:`
front-matter in each `SKILL.md`. After copying, they appear in OpenCode's
available-skills list and are auto-triggered when a task matches their description.

> Note: if you prefer a single top-level directory to keep the files together, the
> `SKILL.md` files must each live in their own directory (one skill per folder).

## Usage

### Trigger the master skill

The `vuln-hunt` skill is auto-selected by its description. Invoke it explicitly with:

```
@vuln-hunt
```

or just describe the task, e.g. *"audit this repo for path traversal and RCE"*.

### Language helpers load automatically

The master skill detects the language(s) in the target repo and loads the matching
helper (e.g. `vuln-hunt-go` for a Go codebase). You can also use a helper directly:

```
@vuln-hunt-python
```

## How the source-code workflow runs

1. **Recon** — identify languages/frameworks, trust boundaries, and privileged contexts.
2. **Hunt** — two parallel passes, then merge:
   - **Pass A (automated):** Semgrep Pro taint findings, filtered to the in-scope classes.
   - **Pass B (manual):** language-specific sink/source tracing using the helper skills.
3. **Adversarial challenge** — every candidate is attacked by a skeptical subagent that
   must return `CONFIRMED` / `REJECTED` / `UNPROVEN`. Only `CONFIRMED` findings are
   reported.
4. **Report** — a concise, GitHub-issue-ready list of confirmed findings.

## Philosophy

- **No theoretical findings.** A bug is reported only if a concrete exploitation path
  can be described.
- **Precision over recall.** A short list of real bugs beats a long list of noise.
- **Challenge everything.** A finding that survives the adversarial subagent is worth
  reporting; one that does not is not.
