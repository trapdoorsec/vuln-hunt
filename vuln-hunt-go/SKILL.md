---
name: vuln-hunt-go
description: >
  Language-specific hunting guide for LFI, Path Traversal, LPE, and RCE in Go source code.
  Load this when auditing Go for these vulnerability classes, directly or as a helper for
  the vuln-hunt master skill. Covers os/exec, os.Open/ReadFile, http.ServeFile, archive
  extraction, and setuid/chown.
---

# Go Vulnerability Hunting (LFI / Path Traversal / LPE / RCE)

Deep reference for the four classes in Go. Use alongside the master `vuln-hunt` skill.

## RCE

### Sinks

```go
exec.Command("sh", "-c", userInput)          // shell boundary
exec.Command("bash", "-c", userInput)
exec.Command(userInput, args...)              // attacker picks the binary
exec.CommandContext(ctx, "sh", "-c", userInput)
syscall.Exec(userInput, args, env)            // attacker picks the binary
plugin.Open(userInput)                        // loads attacker-chosen .so
```

### What to look for

- `exec.Command("sh"|"bash"|"cmd", "-c", ...)` with a user-controlled string.
- `exec.Command(userInput, ...)` where the program path is attacker-chosen.
- `syscall.Exec` with an attacker-controlled path.
- `plugin.Open` with a user-controlled path.

### Gotchas

- `exec.Command("ls", userInput)` is **not** command injection — Go passes args directly
  via `execve`, no shell. Only flag when `sh -c` is explicitly introduced or the *binary
  path* is attacker-controlled.
- `exec.Command("sh", "-c", userInput)` is the Go equivalent of `system()` — fully
  exploitable.
- `exec.Command` with a *relative* binary name relies on `PATH` — flag if `PATH` is
  attacker-influenced (e.g. in a setuid context).

## LFI / Path Traversal

### Sinks

```go
os.Open(path)  os.OpenFile(path, ...)  os.ReadFile(path)  os.WriteFile(path, ...)
os.Remove(path)  os.Rename(path, ...)  os.ReadDir(path)
ioutil.ReadFile(path)   // deprecated but still common
http.ServeFile(w, r, path)
http.FileServer(http.Dir(root))   // misconfig if root is user-controlled
archive/tar / archive/zip extraction
```

### What to look for

- `filepath.Join(base, userInput)` or `fmt.Sprintf("%s/%s", base, user)` passed to a file
  API. `filepath.Join` **does** clean the path, but `filepath.Join("/srv", "../../etc/passwd")`
  still yields `/etc/passwd` — it does not confine to `base`.
- `userInput` used directly as a path.
- `http.ServeFile` with a user-controlled path.
- `archive/tar`/`archive/zip` extraction without validating member paths (zip-slip).

### Mitigations that break the chain

- `filepath.Clean` + verifying the result is under the intended base via
  `strings.HasPrefix(cleaned, base)` (careful: prefix check must be on path boundaries).
- `filepath.Rel(base, path)` and rejecting results that start with `..`.
- Rejecting absolute paths and `..` components.
- For archives: validate each member with `filepath.Clean`/`filepath.Rel` before writing.

### Gotchas

- `filepath.Join` cleans `..` but does **not** prevent escaping the base — a common
  misconception. Always verify the joined result is still under the base.
- `http.FileServer(http.Dir(root))` is safe *if* `root` is a fixed constant; it's a
  finding only when `root` is user-controlled.

## LPE

### Signals

```go
os.Chown(path, uid, gid)  os.Chmod(path, mode)
os.Setuid(uid)  os.Setgid(gid)
syscall.Setuid(uid)  syscall.Setgid(gid)  syscall.Setgroups(...)
```

### What to look for

- A binary installed setuid/setgid, or a service running as root, that performs file
  operations on attacker-writable paths.
- `os.Chown`/`os.Chmod` on user-influenced paths while privileged.
- Privilege drop done incorrectly: `os.Setuid` before `os.Setgid`, or not calling
  `syscall.Setgroups` to clear supplementary groups.
- Trusting environment variables (`PATH`, `LD_PRELOAD`, `LD_LIBRARY_PATH`) while
  privileged.

### Gotchas

- Go's `os.Setuid`/`os.Setgid` are thin wrappers over the syscalls — same ordering and
  supplementary-group pitfalls as C.
- A root service that calls `exec.Command` with a relative binary name is vulnerable to
  `PATH` hijacking.

## Sources (untrusted input)

- `r.URL.Query().Get()`, `r.FormValue()`, `r.URL.Path`, `r.Header.Get()`
- `r.Body` via `io.ReadAll` / `json.NewDecoder`
- `os.Args`, `os.Getenv()`
- `net.Conn` reads, gRPC/HTTP handlers

## Taint tracing notes

- Go's static types make data flow easier to trace than dynamic languages. Follow the
  `string` from the request/input to the sink.
- `filepath.Join` and `fmt.Sprintf` are the two path builders — both traversal-prone.
- For `exec.Command`, the key question is always: is there a `sh -c`, or is the binary
  path attacker-controlled? If neither, it's not RCE.
