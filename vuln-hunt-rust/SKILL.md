---
name: vuln-hunt-rust
description: >
  Language-specific hunting guide for LFI, Path Traversal, LPE, RCE, and memory-safety
  issues in Rust source code. Load this when auditing Rust for these vulnerability
  classes, directly or as a helper for the vuln-hunt master skill. Covers
  std::process::Command, unsafe blocks and FFI (use-after-free, OOB, double free,
  undefined behavior), std::fs path handling, and setuid via libc.
---

# Rust Vulnerability Hunting (LFI / Path Traversal / LPE / RCE / Memory Safety)

Deep reference for these classes in Rust. Use alongside the master `vuln-hunt` skill.
Rust's safety model eliminates whole classes of bugs in safe code, but `unsafe`, FFI,
and shell boundaries still leave them in play. Memory safety is therefore an
`unsafe`-only target — see the dedicated section below.

## RCE

### Sinks

```rust
std::process::Command::new("sh").arg("-c").arg(user_input)   // shell boundary
std::process::Command::new(user_input)                        // attacker picks the binary
std::process::Command::new("sh").args(["-c", user_input])
// unsafe FFI:
unsafe { libc::system(cmd.as_ptr() as *const c_char) }
unsafe { libc::popen(cmd.as_ptr() as *const c_char, ...) }
unsafe { libc::execl(...) }
```

### What to look for

- `Command::new("sh")` / `"bash"` / `"cmd"` with `-c` and a user-controlled string.
- `Command::new(user_input)` where the program path is attacker-chosen.
- Any `unsafe` block calling `libc::system`, `libc::popen`, `libc::exec*`, or
  `libc::dlopen`.
- `Command::new("sh").arg("-c").arg(format!("...{}...", user))`.

### Gotchas

- `Command::new("ls").arg(user_input)` is **not** command injection — args are passed
  directly via `execve`, no shell. Only flag when a shell (`sh -c`) is explicitly
  introduced or the *binary path* is attacker-controlled.
- `Command::new("sh").arg("-c").arg(user)` is the Rust equivalent of `system()` — fully
  exploitable.
- `unsafe` is the red flag: grep for `unsafe` blocks and audit every FFI call into
  `libc`/`winapi` that touches process or file APIs.

## LFI / Path Traversal

### Sinks

```rust
std::fs::read(path);  std::fs::read_to_string(path);
std::fs::File::open(path);
std::fs::remove_file(path);  std::fs::rename(path, ...);
std::fs::read_dir(path);
std::fs::copy(path, ...);
```

### What to look for

- `Path::new(base).join(user_input)` or `format!("{}/{}", base, user)` passed to a file
  API. `Path::join` does **not** sanitize `..` — `Path::new("/srv").join("../../etc/passwd")`
  resolves to `/etc/passwd`.
- `user_input` used directly as a path without `canonicalize()` or a prefix check.

### Mitigations that break the chain

- `std::fs::canonicalize()` then verifying the result starts with the intended base
  directory (via `Path::starts_with`).
- Rejecting `..` components or absolute paths before use.
- `openat`-style dirfd usage via `cap-std` crate.

## LPE

### Signals

```rust
unsafe { libc::setuid(0) }  unsafe { libc::setgid(0) }
unsafe { libc::seteuid(0) } unsafe { libc::chown(...) }  unsafe { libc::chmod(...) }
std::fs::set_permissions(path, ...)   // chmod
```

### What to look for

- A binary installed setuid/setgid (check build scripts, packaging, `chmod u+s`).
- `unsafe` calls to `libc::setuid`/`setgid`/`chown`/`chmod` on attacker-influenced paths.
- `std::fs::set_permissions` / `std::os::unix::fs::chown` on user-controlled paths while
  privileged.
- Privilege drop done incorrectly: dropping uid before gid, or not clearing supplementary
  groups (`libc::setgroups`).
- Trusting environment variables (`PATH`, `LD_PRELOAD`, `LD_LIBRARY_PATH`) while
  privileged.

### Gotchas

- Rust's `std` has no direct `setuid` — it's always through `unsafe` FFI. Every `unsafe`
  block touching `libc` process/uid functions is a candidate.
- `std::fs::set_permissions` on a path the attacker owns, in a privileged process, is the
  same TOCTOU/symlink risk as C.

## Memory Safety (unsafe and FFI only)

Safe Rust prevents buffer overflows and use-after-free, so do not chase those in safe
code. The audit surface is `unsafe`, `extern "C"` FFI, and safe wrappers that hide raw
pointer work. Undefined behavior reachable from a **safe** API is a real vulnerability
even when the immediate effect is a crash.

### Where to look

- Every `unsafe { ... }` block and `unsafe fn` body.
- `extern "C"` declarations, `#[no_mangle]` exports, and callbacks passed to C.
- `unsafe impl Send` / `unsafe impl Sync`.
- Crates that expose `from_raw`, `as_ptr`, or unchecked constructors.
- `#![allow(unsafe_code)]` and `unsafe_op_in_unsafe_fn` settings (edition 2024).

### Raw pointers, slices, and memory

- `slice::from_raw_parts(_mut)` — wrong length, null/dangling pointer, misalignment,
  uninitialized memory, or a lifetime that outlives the allocation.
- `ptr::read` / `ptr::write` / `ptr::copy` / `ptr::copy_nonoverlapping` — count is in
  *elements*, alignment must match, and `copy_nonoverlapping` must not overlap.
- `ptr::drop_in_place` called twice, or on a value that is still used.
- `Box::from_raw` on a pointer not produced by `Box::into_raw`, or called twice →
  double free. `into_raw` without a matching `from_raw` → leak.
- `Vec::set_len` beyond initialized capacity, `String::from_utf8_unchecked` /
  `str::from_utf8_unchecked` on invalid UTF-8.
- `transmute` / `transmute_copy` across different sizes or into invalid values
  (references, `bool`, enums, `NonZero*`).
- `MaybeUninit`, `mem::uninitialized`, `mem::zeroed` — `zeroed` is invalid for
  references, `NonNull`, and some enums.
- `ManuallyDrop` / `mem::forget` followed by a second drop.

### Aliasing, races, and lifetimes

- A live `&mut` while another reference to the same object is used (including through a
  raw pointer or `UnsafeCell`) — violates Rust's aliasing rules.
- `UnsafeCell` used without the required synchronization, or `Cell`/`RefCell` shared
  across threads.
- Manual `Send`/`Sync` impls that make a non-thread-safe type shareable → data race.
- `Pin` used to create a self-referential struct and then moved, or `get_unchecked_mut`
  violating the pinning contract.
- Lifetimes extended with `mem::transmute`, `slice::from_raw_parts`, or a `'static`
  bound that does not match the real allocation.

### FFI boundaries

- `CString` with interior NUL (silent truncation) or a `CStr` whose buffer is freed
  while C still holds it.
- Structs passed to C without `#[repr(C)]`, or with a layout that differs from the C
  declaration.
- Integer width/signedness mismatch between Rust and the C ABI.
- C writing through a pointer to Rust memory beyond the agreed length.
- Callbacks: `extern "C" fn` that panics across the FFI boundary (abort/UB), or captures
  state whose lifetime is not guaranteed.

### Integers and unchecked access

- `usize` arithmetic in `unsafe` code that can wrap in release builds.
- `get_unchecked` / `get_unchecked_mut` with an attacker-controlled index.
- Length/capacity calculations feeding `set_len`, `from_raw_parts`, or `copy_*`.

### From UB to impact

- UAF/double free can become RCE or LPE depending on the allocator and the object layout.
- OOB write can corrupt adjacent heap data, function pointers, or allocator metadata.
- Many bugs are "only" DoS or UB without a demonstrated primitive — say so honestly.
- Verify with Miri (`cargo +nightly miri test`) for UB and ASan
  (`RUSTFLAGS="-Zsanitizer=address"`) for memory errors. A safe-API reproducer is the
  strongest evidence.

### How to hunt

- `rg -n 'unsafe'` and enumerate every block; `cargo geiger` gives a per-crate count.
- Audit dependencies too — unsafe code in a crate is still in your attack surface.
- For each block, state which invariant it relies on and whether a safe caller can break
  it. That gap is the bug.
- Run the crate's tests under Miri; add a harness that exercises the parser or handler
  with attacker-shaped input.

## Sources (untrusted input)

- `std::env::args()`, `std::env::var()` / `var_os()`
- `std::io::stdin().read_line(...)`, `read_to_string(...)`
- `TcpListener`/`TcpStream` reads, HTTP framework request params (axum/actix/rocket)
- Config file parsing (serde from user-supplied files)

## Taint tracing notes

- Rust's ownership makes data flow easier to follow than C, but `unsafe` blocks can hide
  it. Grep for `unsafe` and audit each block.
- `Path::join` and `format!` are the two path-building idioms — both are traversal-prone.
- Watch for `.to_string_lossy()` / `.to_str()` conversions that drop path structure
  information before validation.
- For memory safety, trace the *invariant* rather than only the data: length vs capacity,
  pointer provenance, alignment, initialization, aliasing, and lifetime. The bug is a
  safe caller that can violate an invariant an `unsafe` block assumes.
