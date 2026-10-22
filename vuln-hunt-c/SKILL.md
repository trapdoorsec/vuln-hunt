---
name: vuln-hunt-c
description: >
  Language-specific hunting guide for LFI, Path Traversal, LPE, RCE, and memory-safety
  bugs (buffer overflows, use-after-free, double free, OOB, integer errors) in C and C++
  source code. Load this when auditing C/C++ for these vulnerability classes, either
  directly or as a helper for the vuln-hunt master skill. Covers system()/popen()/exec*,
  file path handling, setuid/setgid, TOCTOU, symlink attacks, and unsafe memory
  management.
---

# C / C++ Vulnerability Hunting (LFI / Path Traversal / LPE / RCE / Memory Safety)

Deep reference for these classes in C and C++. Use alongside the master `vuln-hunt`
skill. Trace every sink back to its source before flagging.

## RCE

### Sinks

```c
system(cmd);                 // /bin/sh -c cmd  → shell metacharacters are live
popen(cmd, "r");             // same shell boundary
execl("/bin/sh", "sh", "-c", cmd, NULL);
execlp("sh", "sh", "-c", cmd, NULL);
execvp(cmd, argv);           // PATH lookup — hijackable if cmd is relative
posix_spawn(...);
dlopen(path, ...);           // loads attacker-chosen .so
```

### What to look for

- `system()` / `popen()` where the format string or argument is built from
  `argv[]`, `getenv()`, socket `read()`, or config input.
- `sprintf(buf, "cmd %s", user)` then `system(buf)` — the classic.
- `execvp()` / `execlp()` with a *relative* command name → `PATH` hijacking.
- `dlopen()` with a path derived from user input.

### Gotchas

- `execv()`/`execve()` with a **fixed** argv array is *not* command injection — no shell
  is involved. Only flag it if the *program path* or an *argument* is attacker-controlled
  in a way that changes what runs.
- `system()` always goes through `/bin/sh -c`, so even a single argument with `;`, `|`,
  `$()`, or backticks is exploitable.
- Check for `setuid` + `system()` — that combination is RCE *and* LPE.

## LFI / Path Traversal

### Sinks

```c
open(path, ...);  openat(dirfd, path, ...);
fopen(path, ...); freopen(path, ...);
stat(path, ...);  lstat(path, ...);  access(path, ...);
opendir(path);    readlink(path, ...);
unlink(path);     rename(path, ...);  chmod(path, ...);  chown(path, ...);
```

### What to look for

- Path built with `sprintf`/`snprintf`/`strcat`/`strcpy` from a variable, then passed to
  any of the above.
- `snprintf(buf, sizeof buf, "%s/%s", base, user)` where `user` contains `../` or starts
  with `/`.
- `getenv("HOME")` / `getenv("TMPDIR")` concatenated into a path — env is attacker
  controlled in many contexts (setuid, CGI, sudo).

### Mitigations that break the chain

- `realpath()` before use (but note: `realpath` on a *nonexistent* file fails — check the
  code handles that).
- `openat2(..., RESOLVE_BENEATH)` — strong, modern defense.
- `chroot()` before file access.
- Explicit `strcmp`/allowlist against a fixed set of names.
- Rejecting `..`, leading `/`, or `strchr(path, '/')`.

## LPE

### Signals

```c
setuid(0); setgid(0); seteuid(0); setegid(0); setreuid(...); setresuid(...);
chown(...); chmod(...); chroot(...); initgroups(...);
```

### What to look for

- A binary installed **setuid/setgid** (check `Makefile.in`, `install.sh`, packaging
  `chmod 4755` / `chmod u+s`). Any unsafe operation in a setuid binary is LPE.
- **TOCTOU**: `access(path, W_OK)` followed by `open(path, ...)` — attacker swaps a
  symlink between the two calls.
- `mktemp()` / `tmpnam()` — predictable names → symlink attack. `mkstemp()` is safe.
- `chown`/`chmod` on a path the attacker can influence (e.g. a file they own, or a
  directory they can write).
- `setuid()`/`setgid()` called but the return value ignored, or privilege dropped in the
  wrong order (drop gid before uid, or forget `setgroups`/`initgroups`).
- Environment variables (`PATH`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `IFS`) trusted while
  privileged — classic setuid env hijack.

### Gotchas

- Privilege drop order matters: `setgid()` then `setuid()`, and clear supplementary
  groups with `setgroups(0, NULL)` / `initgroups()`. Forgetting this leaves the process
  with elevated group rights.
- `system()`/`popen()`/`exec*` in a setuid binary is almost always LPE — the shell
  inherits the elevated euid unless dropped.

## Memory Safety (BOF / UAF / OOB)

C and C++ have no bounds or lifetime safety. Treat every attacker-influenced length,
index, pointer, and object lifetime as hostile. A memory bug is in scope when it is
reachable from untrusted input and does more than produce a clean, non-exploitable crash.

### Buffer overflows

**Stack**
- `strcpy()`, `strcat()`, `sprintf()`, `vsprintf()`, `gets()`, `scanf("%s")` into a
  fixed-size buffer.
- `memcpy(dst, src, user_len)` / `read(fd, buf, user_len)` where `user_len` can exceed
  `sizeof(buf)`.
- `alloca(user_len)` or attacker-sized VLAs (stack exhaustion → overflow).
- Unbounded expanding format output written into a fixed buffer.

**Heap**
- Size arithmetic overflow/truncation before `malloc()`: `n * sizeof(T)`, `a + b`, or a
  `size_t` → `int`/`short` narrowing.
- Off-by-one: `buf[len] = 0`, `<=` in a copy loop, `strncpy()` without a terminator.
- Writes outside the allocation via pointer arithmetic or a wrong stride.
- `realloc()` assigned to the original pointer without a `NULL` check, followed by use.
- Custom allocators/pools: check metadata, alignment, and freelist handling.

### Use-after-free / double free

- `free(p)` followed by any read or write through `p` — including error paths, signal
  handlers, and callbacks.
- Pointer left in a global, struct, or container after its allocation is freed.
- Two owners of one allocation: missing refcount increment, decrement on an error path.
- Double free through duplicated cleanup blocks, `goto` error handling, or a callback
  that frees and then the caller frees again.
- C++: `delete` then use; `unique_ptr::get()` escaping; `shared_ptr` cycle or `reset()`
  while a raw pointer still aliases it; virtual call during destruction.

### Out-of-bounds and type confusion

- Attacker-controlled index into an array or table with no bound check.
- Signed/unsigned mismatch: a negative index becomes a huge `size_t`.
- Pointer arithmetic beyond the object (`p + n`, `p[-1]`).
- C++: invalid `static_cast` downcast, `reinterpret_cast`, unions, object slicing, and
  iterator invalidation on `vector`/`string`/`map`.
- Uninitialized stack or heap memory returned to the attacker (info leak / ASLR bypass).

### Integer and format-string issues

- Integer overflow/underflow feeding an allocation, index, or length (`CWE-190`).
- Truncation before a copy or index (`size_t` → `int` → `short`).
- `printf(user_input)` / `syslog(user_input)` — format-string read/write (`%n`).
- `atoi()`/`strtol()` results used unchecked, or negative lengths passed to `mem*`.

### From memory bug to impact

- **RCE** — controlled overwrite of a return address, function pointer, vtable, GOT
  entry, or heap metadata that is later used. Usually needs an info leak for ASLR.
- **LPE** — the same primitive inside a setuid/root daemon or privileged parser.
- **Info leak** — OOB read or uninitialized memory returned to the attacker; often the
  enabler for the two above.
- **DoS only** — a NULL dereference or clean abort is real but low value. Report it only
  when the target is remote and availability matters; do not dress it up as RCE.

Before claiming exploitability, check the build's mitigations: stack canaries, NX,
PIE/ASLR, RELRO, `_FORTIFY_SOURCE`, bounded string functions, allocator hardening,
seccomp/sandbox. Read `Makefile`/`CMakeLists.txt`/packaging flags — source alone does not
tell you what ships.

### How to hunt

- Pair every allocation with every free and follow the pointer's lifetime across
  functions, threads, and callbacks.
- Grep the unbounded APIs above, then check the destination size and the real source
  length — not just that `strncpy`/`snprintf` appears.
- Scrutinize length arithmetic and casts near `memcpy`/`malloc`/`read`/`write`.
- Build with ASan/UBSan (`-fsanitize=address,undefined`) and fuzz the parser or request
  handler. A sanitizer report is strong evidence; a bare crash is not proof of control.
- In C++, also check container/iterator lifetimes and `std::function`/lambda captures.

## Sources (untrusted input)

- `argv[]`, `getopt()` results
- `getenv()` — especially `HOME`, `TMPDIR`, `PATH`, `LD_*`
- `read()`/`recv()`/`recvfrom()` from sockets
- `fgets()`/`scanf()`/`getline()` on stdin
- Config-file parsing, `getpwuid()`/`getpwnam()` results (user-controlled via NSS)

## Taint tracing notes

- C has no type system to help — follow the variable by hand. A `char buf[PATH_MAX]`
  filled from `argv[1]` and later passed to `open()` is the whole story.
- Watch for `strcpy`/`strcat`/`sprintf` (unbounded) vs `strncpy`/`snprintf` (bounded) —
  bounded copies don't stop path traversal, they only stop overflow.
- In C++, also check `std::filesystem::path` concatenation and `std::ifstream`/`ofstream`
  constructors, and `std::system`/`std::popen` equivalents.
- For memory bugs, the taint is the length, index, and lifetime as much as the data.
  Follow the size variable from its source; check where it is bounded (or not) and
  whether the allocation and the copy agree on units and signedness.
- A pointer freed on one path and used on another is a UAF even if the free and use are
  in different functions — build the call graph before concluding.
