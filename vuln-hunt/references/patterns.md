# Sink & Source Patterns by Language

Sinks are the dangerous operations. Sources are where untrusted data enters. A candidate
exists when a source reaches a sink without a breaking check. This is a starting point,
not a checklist — always trace the actual data flow.

## C / C++

**RCE sinks**
- `system()`, `popen()`, `execl()`, `execle()`, `execlp()`, `execv()`, `execve()`,
  `execvp()`, `posix_spawn()`, `dlopen()`
- Backtick command execution (e.g. `backtick.c` style helpers)

**LFI / Path Traversal sinks**
- `open()`, `openat()`, `fopen()`, `freopen()`, `read()`, `stat()`, `lstat()`,
  `access()`, `unlink()`, `rename()`, `chmod()`, `chown()`, `opendir()`, `realpath()`
- Any path built with `sprintf`/`snprintf`/`strcat`/`strcpy` from a variable

**LPE sinks / signals**
- `setuid()`, `setgid()`, `seteuid()`, `setegid()`, `setreuid()`, `setresuid()`,
  `chown()`, `chmod()`, `chroot()`, `initgroups()`
- A binary installed setuid/setgid (check `Makefile.in`, `install.sh`, packaging)
- `mktemp()`/`tmpnam()` (predictable temp files → symlink attack)
- File ops on attacker-writable paths while privileged (TOCTOU)

**Memory-safety sinks / signals**
- Unbounded writes: `strcpy()`, `strcat()`, `sprintf()`, `vsprintf()`, `gets()`,
  `scanf("%s")`, `alloca()`, attacker-sized VLAs
- Length-driven copies: `memcpy()`/`memmove()`/`read()`/`write()` with an unchecked
  or overflowable length; `n * size` before `malloc()`
- Lifetime: `free()`/`delete` followed by use; double free; `realloc()` result misuse;
  pointer stored after free
- Bounds: array/table index from input, signed/unsigned index conversion, `buf[len]`
- Integer: overflow/truncation in size or index math (`CWE-190`)
- Format string: `printf(user)`, `syslog(user)`, `%n`
- C++: invalid downcast/`reinterpret_cast`, union misuse, iterator or `string`/`vector`
  invalidation, virtual call during destruction

**Sources**
- `argv[]`, `getenv()`, `getopt()`, `read()`/`recv()` from sockets, `fgets()`/`scanf()`
  on stdin, config-file parsing, `getenv("HOME")`/`getenv("TMPDIR")`
- For memory bugs, also the **length**, **index**, and **lifetime** variables derived
  from any of the above

## Rust (`unsafe` / FFI only)

Safe Rust is memory-safe; only audit `unsafe`, `extern "C"`, and safe wrappers around raw
pointers.

**Memory-safety sinks / signals**
- `slice::from_raw_parts(_mut)` with an unchecked length or stale pointer
- `ptr::read` / `ptr::write` / `ptr::copy` / `ptr::copy_nonoverlapping`
- `Box::from_raw` (double free), `Vec::set_len`, `*_unchecked` string/slice constructors
- `transmute`, `MaybeUninit`, `mem::uninitialized`/`zeroed`, `ManuallyDrop`
- `get_unchecked` on an attacker-controlled index
- `unsafe impl Send`/`Sync` without synchronization
- FFI: interior NUL in `CString`, missing `#[repr(C)]`, ABI width/signedness mismatch

**RCE / LFI / LPE** — same sinks as the dedicated `vuln-hunt-rust` skill:
`std::process::Command` with `sh -c`, `std::fs` path joins, and `libc::setuid`/`chown`
inside `unsafe`.

## Python

**RCE sinks**
- `os.system()`, `os.popen()`, `subprocess.Popen(..., shell=True)`,
  `subprocess.call(..., shell=True)`, `subprocess.run(..., shell=True)`,
  `os.exec*()`, `eval()`, `exec()`, `pickle.loads()`, `yaml.load()` (unsafe),
  `marshal.loads()`, `ctypes` calls, `__import__` with user input

**LFI / Path Traversal sinks**
- `open()`, `io.open()`, `os.open()`, `pathlib.Path(...).read_text()`,
  `shutil.copy()`, `os.remove()`, `os.rename()`, `tarfile.extractall()` (path traversal
  in archives), `zipfile.extractall()`

**LPE signals**
- Scripts run as root/sudo, `os.chown()`, `os.chmod()`, `os.setuid()`, `os.seteuid()`,
  `tempfile.mktemp()` (deprecated, insecure), world-writable file writes

**Sources**
- `sys.argv`, `os.environ`, `request.args`/`request.form`/`request.json` (Flask),
  `request.GET`/`request.POST` (Django), `input()`, socket `recv()`, file uploads

## Go

**RCE sinks**
- `os/exec.Command()` / `CommandContext()` with attacker-controlled args (note: no shell
  unless `sh -c`), `syscall.Exec()`, `plugin.Open()`

**LFI / Path Traversal sinks**
- `os.Open()`, `os.OpenFile()`, `os.ReadFile()`, `os.WriteFile()`, `os.Remove()`,
  `os.Rename()`, `ioutil.ReadFile()`, `http.ServeFile()`, `http.FileServer()`,
  `archive/tar` / `archive/zip` extraction

**LPE signals**
- `os.Chown()`, `os.Chmod()`, `os.Setuid()`, `os.Setgid()`, `syscall.Setuid()`,
  services running as root, `os.MkdirTemp` vs insecure `ioutil.TempFile` patterns

**Sources**
- `r.URL.Query().Get()`, `r.FormValue()`, `r.URL.Path`, `r.Header.Get()`,
  `os.Args`, `os.Getenv()`, `io.ReadAll(r.Body)`, `json.NewDecoder(r.Body)`

## JavaScript / Node.js

**RCE sinks**
- `child_process.exec()`, `child_process.execSync()`, `child_process.spawn()` with
  `shell: true`, `eval()`, `new Function()`, `vm.runInNewContext()` (unsafe),
  `require()` with user input, `Function()` constructor

**LFI / Path Traversal sinks**
- `fs.readFile()`, `fs.readFileSync()`, `fs.createReadStream()`, `fs.writeFile()`,
  `fs.unlink()`, `path.join()`/`path.resolve()` with user input, `res.sendFile()`,
  `express.static()` misconfig, `tar`/`unzipper` extraction

**LPE signals**
- `fs.chown()`, `fs.chmod()`, `process.setuid()`, `process.setgid()`, node running as root

**Sources**
- `req.query`, `req.params`, `req.body`, `req.headers`, `process.argv`, `process.env`,
  `req.url`, `req.cookies`

## PHP

**RCE sinks**
- `system()`, `exec()`, `shell_exec()`, `passthru()`, `proc_open()`, `popen()`,
  `eval()`, `assert()`, `preg_replace()` with `/e`, `unserialize()`, `include`/`require`
  with user input (also LFI)

**LFI / Path Traversal sinks**
- `include`, `include_once`, `require`, `require_once`, `file_get_contents()`,
  `fopen()`, `readfile()`, `file()`, `highlight_file()`, `show_source()`

**LPE signals**
- `chown()`, `chmod()`, `posix_setuid()`, `posix_seteuid()`, web server running as root

**Sources**
- `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES`, `$_SERVER['HTTP_*']`,
  `php://input`, `$_ENV`

## Shell (bash/sh)

**RCE sinks**
- `eval`, `$()` command substitution with user input, `sh -c "$VAR"`, `bash -c "$VAR"`,
  unquoted variable expansion in commands, `xargs sh -c`

**LFI / Path Traversal sinks**
- `cat "$VAR"`, `source "$VAR"`, `. "$VAR"`, `cp`/`mv`/`rm` with user input,
  `tar -xf` (path traversal in archives)

**LPE signals**
- Scripts with setuid bit, `sudo` invocations, `chown`/`chmod` on user-controlled paths,
  insecure `mktemp`/`$$` temp files, `chmod 777`

**Sources**
- `$1`, `$@`, `$*`, `$USER`, `$HOME`, `$TMPDIR`, environment variables, `read` from stdin

## Java

Dedicated skill: `vuln-hunt-java`. The list below is a fallback summary.

**RCE sinks**
- `Runtime.getRuntime().exec()`, `ProcessBuilder` with attacker-controlled command,
  `ScriptEngine.eval()`, `Class.forName()` with user input, `ObjectInputStream.readObject()`
  (deserialization), JNDI lookups (`InitialContext.lookup()`)

**LFI / Path Traversal sinks**
- `new FileInputStream()`, `new FileReader()`, `Files.readAllBytes()`, `Files.readString()`,
  `Paths.get()` with user input, `ServletContext.getResource()`

**LPE signals**
- `Files.setPosixFilePermissions()`, `Files.setOwner()`, services running as root

**Sources**
- `request.getParameter()`, `request.getHeader()`, `request.getPathInfo()`,
  `request.getQueryString()`, `args[]`, `System.getenv()`

## Ruby

**RCE sinks**
- `system()`, `` `cmd` `` (backticks), `exec()`, `spawn()`, `IO.popen()`,
  `Open3.capture*()`, `eval()`, `Kernel.load()`, `Marshal.load()`, `YAML.load()` (unsafe)

**LFI / Path Traversal sinks**
- `File.read()`, `File.open()`, `IO.read()`, `FileUtils.cp()`, `send_file`,
  `File.delete()`, `Dir.glob()` with user input

**LPE signals**
- `File.chown()`, `File.chmod()`, `Process.setuid()`, `Process.setgid()`

**Sources**
- `params` (Rails), `request.query_parameters`, `ARGV`, `ENV`, `request.body`

## Cross-cutting notes

- **Path traversal** is the same bug in every language: a user-controlled string is
  concatenated into a path and used without canonicalizing against a base directory.
  Look for `..`, leading `/`, and absolute paths.
- **LFI** is path traversal that specifically results in *reading* a file whose contents
  are then returned to the attacker (or included/executed).
- **LPE** almost always requires a privileged boundary. If the process never runs with
  elevated privileges, most "LPE" candidates are just ordinary file bugs — reject them.
- **RCE** via command injection requires the data to cross a shell boundary (`sh -c`,
  `shell=True`, `system()`, backticks) or an eval/deserialization boundary. Passing
  attacker data as a *single argv element* to `execve`/`exec.Command` is usually NOT
  command injection — note the distinction.
