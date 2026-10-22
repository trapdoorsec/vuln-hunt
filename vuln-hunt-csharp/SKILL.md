---
name: vuln-hunt-csharp
description: >
  Language-specific hunting guide for LFI, Path Traversal, LPE, and RCE in C# / .NET
  source code. Load this when auditing C# for these vulnerability classes, directly or as
  a helper for the vuln-hunt master skill. Covers Process.Start, deserialization,
  Path.Combine traversal, and impersonation/privilege issues.
---

# C# / .NET Vulnerability Hunting (LFI / Path Traversal / LPE / RCE)

Deep reference for the four classes in C#. Use alongside the master `vuln-hunt` skill.

## RCE

### Sinks

```csharp
Process.Start(processStartInfo);                 // with attacker-controlled FileName/Arguments
Process.Start("cmd.exe", "/c " + userInput);     // shell boundary
ProcessStartInfo { FileName = userInput, ... };
// Deserialization (RCE via gadgets):
new BinaryFormatter().Deserialize(stream);       // always unsafe
JsonConvert.DeserializeObject<T>(json, new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.All });  // unsafe
// Dynamic code:
CSharpCodeProvider.CompileAssemblyFromSource(...);  // with user code
```

### What to look for

- `Process.Start` where `FileName` or `Arguments` is built from user input
  (`Request.QueryString`, `Request.Form`, `Request.Headers`, config).
- `cmd.exe /c` or `powershell -c` with concatenated user input.
- `BinaryFormatter.Deserialize` on any untrusted stream — always RCE.
- `JsonConvert.DeserializeObject` with `TypeNameHandling` set to `All`/`Objects`/`Auto`
  on untrusted JSON.
- `XmlSerializer` / `DataContractSerializer` with attacker-controlled types (less common).

### Gotchas

- `ProcessStartInfo.ArgumentList` (a collection) is safe — args are passed without a
  shell. `ProcessStartInfo.Arguments` (a string) is parsed by the OS and is the injection
  vector, especially with `cmd.exe /c`.
- `Process.Start("cmd.exe", "/c " + input)` is the canonical C# command injection.
- `BinaryFormatter` is deprecated and *always* exploitable on untrusted input — flag it
  unconditionally.

## LFI / Path Traversal

### Sinks

```csharp
File.ReadAllText(path);  File.ReadAllBytes(path);
File.Open(path, ...);    File.OpenRead(path);
File.Delete(path);       File.Move(path, ...);
Directory.GetFiles(path);  Directory.Delete(path, ...);
new StreamReader(path);
```

### What to look for

- `Path.Combine(base, userInput)` — **does not** prevent traversal; `Path.Combine("/srv",
  "../../etc/passwd")` yields `/etc/passwd`.
- `userInput` used directly as a path, or `String.Format("{0}/{1}", base, user)`.
- `Server.MapPath(userInput)` in ASP.NET with a user-controlled virtual path.

### Mitigations that break the chain

- `Path.GetFullPath()` then verify the result starts with the intended base directory
  (case-insensitive on Windows).
- Rejecting `..`, `:`, and rooted paths before use.
- Allowlist of known filenames.

## LPE

### Signals

```csharp
File.SetAccessControl(path, ...);   // ACL manipulation
File.SetAttributes(path, ...);
new WindowsIdentity(token).Impersonate();   // impersonation
Process.Start with Verb = "runas";
```

### What to look for

- A service running as `SYSTEM`/`LocalSystem` or an admin process that performs file
  operations on attacker-writable paths (DLL hijacking, symlink/junction attacks).
- `Impersonate()` / `WindowsIdentity` token handling that can be abused.
- `File.SetAccessControl` / `Directory.SetAccessControl` on user-influenced paths.
- Unsafe `DllImport` of `SetTokenInformation`/`AdjustTokenPrivileges` (SeImpersonate,
  SeDebug, SeAssignPrimaryToken).

### Gotchas

- On Windows, "LPE" often means: a privileged service loads a DLL from a user-writable
  directory (DLL search-order hijacking), or follows a junction/symlink to a
  user-controlled file. Look for `LoadLibrary`/`DllImport` with relative paths in
  privileged services.
- `Path.GetFullPath` is case-insensitive on Windows — a prefix check must account for
  that.

## Sources (untrusted input)

- ASP.NET: `Request.QueryString`, `Request.Form`, `Request.Headers`, `Request.Path`,
  `Request.Cookies`, `Request.Files`
- `Environment.GetEnvironmentVariable`, `args[]`, `Console.ReadLine`
- Deserialized objects from network input

## Taint tracing notes

- Follow the string from the request/input to the sink. C# string concatenation and
  `String.Format` are the common traversal/injection builders.
- `Path.Combine` and `Path.GetFullPath` are frequently *assumed* to sanitize but do not —
  verify a prefix check actually exists.
- For deserialization, the sink itself is the finding; you don't need a taint path —
  untrusted input to `BinaryFormatter` is RCE by definition.
