---
name: vuln-hunt-python
description: >
  Language-specific hunting guide for LFI, Path Traversal, LPE, and RCE in Python source
  code. Load this when auditing Python for these vulnerability classes, directly or as a
  helper for the vuln-hunt master skill. Covers subprocess shell=True, eval/exec, pickle
  and yaml deserialization, path handling, and setuid scripts.
---

# Python Vulnerability Hunting (LFI / Path Traversal / LPE / RCE)

Deep reference for the four classes in Python. Use alongside the master `vuln-hunt` skill.

## RCE

### Sinks

```python
os.system(cmd)                       # /bin/sh -c cmd
os.popen(cmd)                        # shell
subprocess.Popen(cmd, shell=True)    # shell
subprocess.call(cmd, shell=True)
subprocess.run(cmd, shell=True)
subprocess.check_output(cmd, shell=True)
os.exec*("/bin/sh", "-c", cmd)
eval(user_input)                     # arbitrary code
exec(user_input)
pickle.loads(data)                   # arbitrary code via __reduce__
yaml.load(data)                      # unsafe loader (PyYAML < 5.1 default)
marshal.loads(data)                  # unsafe on untrusted input
__import__(user_input)
importlib.import_module(user_input)
```

### What to look for

- `shell=True` with a string (not a list) built from user input.
- `os.system`/`os.popen` with concatenated or f-string user input.
- `eval`/`exec` on anything not a hardcoded literal.
- `pickle.loads`/`pickle.load` on network or file input.
- `yaml.load` (not `yaml.safe_load`) on untrusted YAML.
- `__import__`/`import_module` with a user-controlled module name.

### Gotchas

- `subprocess.run(["ls", user_input], shell=False)` is **safe** — no shell. Only flag
  `shell=True`, or a string command, or a list whose *first element* is attacker-chosen.
- `yaml.load` vs `yaml.safe_load`: `safe_load` is safe; `load` (or `FullLoader` with
  custom tags) is RCE.
- `pickle` is *never* safe on untrusted input — flag unconditionally.
- `eval` with a restricted `__builtins__` is still often bypassable — treat as unsafe.

## LFI / Path Traversal

### Sinks

```python
open(path)  io.open(path)  os.open(path, ...)
pathlib.Path(path).read_text()  .read_bytes()  .open()
shutil.copy(path, ...)  shutil.move(path, ...)
os.remove(path)  os.rename(path, ...)  os.listdir(path)
tarfile.extractall()   # path traversal in archive entries
zipfile.extractall()   # same
```

### What to look for

- `os.path.join(base, user_input)` or f-string `f"{base}/{user_input}"` passed to a file
  API. `os.path.join` does **not** sanitize `..`.
- `user_input` used directly as a path.
- `tarfile.extractall()` / `zipfile.extractall()` on untrusted archives — members can
  contain `../` (CVE-2007-4559 style).

### Mitigations that break the chain

- `os.path.realpath()` then verify the result is under the intended base
  (`os.path.commonpath`).
- Rejecting `..`, leading `/`, or `os.path.isabs`.
- Allowlist of known filenames.
- For archives: validate each member with `os.path.realpath` before extraction.

## LPE

### Signals

```python
os.setuid(0)  os.seteuid(0)  os.setgid(0)  os.setegid(0)
os.chown(path, ...)  os.chmod(path, ...)
os.setgroups(...)
```

### What to look for

- A script run as root/sudo (check shebang + sudoers, or a setuid wrapper) that performs
  unsafe operations: `os.system`, `subprocess(shell=True)`, `open` on user-controlled
  paths, `os.chown`/`os.chmod` on attacker-influenced paths.
- `tempfile.mktemp()` (deprecated, insecure) instead of `tempfile.mkstemp()`.
- World-writable file writes (`os.open(path, 0o666)` or `chmod 0o777`).
- Privilege drop done incorrectly: `os.setuid` after `os.setgid`, or forgetting
  `os.setgroups([])`.

### Gotchas

- A root-run script that calls `os.system` or `subprocess(shell=True)` with any
  environment-influenced input is LPE — the shell runs as root.
- `os.setuid`/`os.setgid` return values ignored, or drop order wrong, leaves elevated
  privileges.

## Sources (untrusted input)

- `sys.argv`, `os.environ`, `os.getenv`
- Flask: `request.args`, `request.form`, `request.json`, `request.files`, `request.headers`
- Django: `request.GET`, `request.POST`, `request.FILES`, `request.META`
- `input()`, socket `recv()`, `pickle.load` from network

## Taint tracing notes

- Python is dynamic — follow the variable by name. F-strings and `%`/`.format` are the
  common injection/traversal builders.
- `os.path.join` and `pathlib` `Path /` operator are both traversal-prone; neither
  sanitizes.
- For deserialization sinks (`pickle`, `yaml.load`, `eval`), the sink is the finding —
  no taint path needed.
