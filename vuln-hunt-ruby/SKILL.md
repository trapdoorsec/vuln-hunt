---
name: vuln-hunt-ruby
description: >
  Language-specific hunting guide for LFI, Path Traversal, LPE, and RCE in Ruby source
  code. Load this when auditing Ruby (including Rails) for these vulnerability classes,
  directly or as a helper for the vuln-hunt master skill. Covers system/backticks/exec,
  eval, Marshal/YAML deserialization, File path handling, and setuid.
---

# Ruby Vulnerability Hunting (LFI / Path Traversal / LPE / RCE)

Deep reference for the four classes in Ruby. Use alongside the master `vuln-hunt` skill.

## RCE

### Sinks

```ruby
system(cmd)                 # /bin/sh -c cmd
`#{cmd}`                    # backticks — shell
%x(#{cmd})                  # shell
exec(cmd)                   # replaces process via shell
spawn(cmd)                  # shell
IO.popen(cmd)               # shell
Open3.capture2(cmd)         # shell
eval(user_input)            # arbitrary code
Kernel.load(user_input)     # loads/executes a file
Marshal.load(data)          # unsafe deserialization
YAML.load(data)             # unsafe (Psych) — RCE via gadgets
```

### What to look for

- `system`, backticks, `%x`, `exec`, `spawn`, `IO.popen`, `Open3.*` with a string built
  from user input (interpolation or concatenation).
- `eval` on anything not a hardcoded literal.
- `Marshal.load` on untrusted data.
- `YAML.load` (not `YAML.safe_load`) on untrusted YAML.
- `Kernel.load` / `require` with a user-controlled path.

### Gotchas

- `system("ls", user_input)` (multiple args) is **safe** — no shell. `system("ls #{user_input}")`
  (single interpolated string) is **unsafe** — shell. The distinction is the number of
  arguments / whether a shell is invoked.
- Backticks and `%x` always go through the shell — any interpolation is injection.
- `YAML.load` vs `YAML.safe_load`: `safe_load` is safe; `load` (or `unsafe_load`) is RCE.
- `Marshal.load` is never safe on untrusted input.

## LFI / Path Traversal

### Sinks

```ruby
File.read(path)  File.open(path)  IO.read(path)  File.binread(path)
File.delete(path)  FileUtils.cp(path, ...)  FileUtils.rm(path)
Dir.glob(path)  Dir.entries(path)
send_file(path)   # Rails
FileUtils.copy_file(path, ...)
```

### What to look for

- `File.join(base, user_input)` or `"#{base}/#{user_input}"` passed to a file API.
  `File.join` does **not** sanitize `..`.
- `user_input` used directly as a path.
- `send_file` with a user-controlled path (Rails).
- `Dir.glob` with user-controlled patterns.

### Mitigations that break the chain

- `File.expand_path` then verify the result is under the intended base
  (`File.expand_path(path).start_with?(base)`).
- Rejecting `..`, leading `/`, or `Pathname#absolute?`.
- Allowlist of known filenames.

## LPE

### Signals

```ruby
File.chown(uid, gid, path)  File.chmod(mode, path)
Process.setuid(uid)  Process.setgid(gid)  Process.seteuid(uid)
Process::Sys.setuid(uid)  Process::Sys.setgid(gid)
```

### What to look for

- A script run as root/sudo (check shebang + sudoers, or a setuid wrapper) that performs
  unsafe operations: `system`, backticks, `File.open` on user-controlled paths,
  `File.chown`/`File.chmod` on attacker-influenced paths.
- `Dir.mktmpdir`/`Tempfile` used correctly vs insecure `File.open("/tmp/#{...}")` with
  predictable names.
- Privilege drop done incorrectly: `Process.setuid` before `Process.setgid`, or not
  clearing supplementary groups.

### Gotchas

- A root-run script that calls `system`/backticks with environment-influenced input is
  LPE — the shell runs as root.
- `Process.setuid`/`setgid` ordering and supplementary-group pitfalls mirror C.

## Sources (untrusted input)

- Rails: `params`, `request.query_parameters`, `request.request_parameters`,
  `request.headers`, `request.body`
- `ARGV`, `ENV`, `STDIN.gets`/`read`
- `TCPSocket`/`UDPSocket` reads

## Taint tracing notes

- Ruby is dynamic — follow the variable by name. String interpolation (`"#{...}"`) and
  concatenation are the common injection/traversal builders.
- `File.join` and `Pathname#join` are traversal-prone; neither sanitizes.
- For deserialization sinks (`Marshal.load`, `YAML.load`, `eval`), the sink is the
  finding — no taint path needed.
