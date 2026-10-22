---
name: vuln-hunt-java
description: >
  Language-specific hunting guide for LFI, Path Traversal, LPE, and RCE in Java and JVM
  source code. Load this when auditing Java (Spring, Jakarta EE, Struts, plain servlets)
  for these vulnerability classes, directly or as a helper for the vuln-hunt master
  skill. Covers Runtime/ProcessBuilder, expression and template injection, Java
  deserialization and gadget chains, JNDI, path handling, and root-service LPE.
---

# Java / JVM Vulnerability Hunting (LFI / Path Traversal / LPE / RCE)

Deep reference for the four classes in Java. Use alongside the master `vuln-hunt` skill.
Java is memory-safe: do not hunt buffer overflows or UAF here. The interesting surface is
the framework layer (request binding, expression languages, template engines), Java
deserialization, and the privileged service the JVM runs in.

## RCE

### Sinks

```java
// Command execution
Runtime.getRuntime().exec(userInput);                          // tokenized, no shell
Runtime.getRuntime().exec(new String[]{"sh", "-c", userInput}); // shell boundary
new ProcessBuilder("sh", "-c", userInput).start();
new ProcessBuilder(userInput).start();                          // attacker picks the binary
new ProcessBuilder("cmd.exe", "/c", userInput).start();

// Expression / script engines
new SpelExpressionParser().parseExpression(userInput).getValue();   // Spring SpEL
Ognl.getValue(userInput, context, root);                            // OGNL
new ScriptEngineManager().getEngineByName("js").eval(userInput);
new GroovyShell().evaluate(userInput);
new BeanShellInterpreter().eval(userInput);
JexlBuilder.create().build().createExpression(userInput).evaluate(ctx);

// Templates (SSTI)
TemplateEngine.process(userInput, ctx);          // Thymeleaf
new Template(userInput, ...).process(...);       // FreeMarker
Velocity.evaluate(ctx, writer, "log", userInput);
// Spring view/expression evaluation, Pebble, Mustache, Handlebars

// Deserialization (gadget chains -> RCE)
new ObjectInputStream(in).readObject();
new XMLDecoder(in).readObject();
new XStream().fromXML(userXml);
new Yaml().load(userYaml);                        // SnakeYAML unsafe constructor
objectMapper.enableDefaultTyping();               // Jackson polymorphic typing
objectMapper.activateDefaultTyping(...);
HessianInput.readObject();  Kryo.readClassAndObject(in);

// Lookup / dynamic loading
new InitialContext().lookup(userInput);           // JNDI (Log4Shell pattern)
Class.forName(userInput).getDeclaredConstructor().newInstance();
new URLClassLoader(new URL[]{new URL(userInput)}).loadClass("...");
```

### What to look for

- `Runtime.exec` / `ProcessBuilder` where the command, the binary path, or an argument
  is built from a request parameter, header, config, or filename.
- `sh -c` / `cmd.exe /c` explicitly introduced, or a single string passed to `exec` where
  the code assumes shell semantics.
- Expression languages fed with user input — SpEL, OGNL, MVEL, JEXL, JSP EL, Groovy,
  BeanShell. This is the Struts2/Spring RCE family.
- Template names or template bodies controlled by the user (SSTI) — Thymeleaf,
  FreeMarker, Velocity, Pebble.
- Native Java deserialization on any network-facing stream (`ObjectInputStream`,
  `XMLDecoder`, XStream, Hessian, Kryo) — RCE via gadget chain.
- YAML/Jackson/XML parsers configured for polymorphic or unsafe types.
- `InitialContext.lookup()` with a user-controlled name (JNDI injection).
- `Class.forName` / reflection / `URLClassLoader` with attacker-chosen class or URL.

### Gotchas

- `Runtime.exec(String)` does **not** invoke a shell — it tokenizes on whitespace. It is
  injection only if a shell is explicitly started (`sh -c`, `cmd /c`) or the *binary path*
  is attacker-controlled.
- `ProcessBuilder(List.of("ls", userInput))` passes `userInput` as one argv element — not
  command injection. `ProcessBuilder("sh", "-c", userInput)` is.
- Java deserialization is a finding even without a visible data flow: untrusted bytes to
  `readObject()` is RCE **if** a usable gadget chain is on the classpath. Check
  `pom.xml`/`build.gradle` for CommonsCollections, CommonsBeanutils, Spring, Groovy,
  XStream, etc.
- `new Yaml().load(...)` uses the unsafe constructor; `SafeConstructor` blocks arbitrary
  types. Jackson's default typing is unsafe unless a strict `PolymorphicTypeValidator`
  allowlist is used.
- SpEL/OGNL may be reachable through annotations (`@Value`, `@PreAuthorize`) and not only
  explicit `parseExpression` calls — search for expression evaluation of request data.

## LFI / Path Traversal

### Sinks

```java
new FileInputStream(path);  new FileReader(path);  new RandomAccessFile(path, "r");
Files.readAllBytes(Paths.get(path));  Files.readString(Path.of(path));
Files.newInputStream(path);  Files.copy(path, ...);  Files.delete(path);
new File(path).exists() / .delete() / .renameTo(...);
getServletContext().getResourceAsStream(path);
getClass().getClassLoader().getResourceAsStream(path);
resourceLoader.getResource("file:" + userInput);          // Spring
multipartFile.transferTo(new File(userPath));
new ZipInputStream(in) / new ZipFile(file)                 // zip-slip on extraction
```

### What to look for

- `Paths.get(base).resolve(userInput)` — **an absolute argument discards the base**:
  `Paths.get("/srv").resolve("/etc/passwd")` is `/etc/passwd`, and `..` still escapes.
  `normalize()` does not confine it.
- `new File(base, userInput)` / `base + "/" + user` / `String.format("%s/%s", base, user)`.
- `ServletContext.getResourceAsStream` or classpath resource loading with a user path.
- Archive extraction that uses the entry name directly (zip-slip) — `ZipEntry.getName()`
  can contain `../`.
- Spring `ResourceLoader` / `UrlResource` with a `file:` URL built from input.

### Mitigations that break the chain

- `Path base = Paths.get(BASE).toRealPath(); Path p = base.resolve(user).normalize();`
  then `p.startsWith(base)` **and** re-check after `toRealPath()` (symlinks).
- Reject absolute paths, `..` components, and (on Windows) drive letters/UNC paths before
  resolving.
- Allowlist known filenames or IDs rather than accepting paths.
- For archives: normalize each entry and reject anything outside the target directory.

### Gotchas

- `resolve()` is the Java equivalent of `Path.Combine`/`filepath.Join` — it does **not**
  sandbox the result.
- `getCanonicalPath()` resolves symlinks and `..`; a prefix check must include the
  separator (`/srv/app` must not match `/srv/application`).
- URL decoding may happen before your check (servlet container, Spring `@PathVariable`).
  Validate the decoded value that actually reaches the filesystem call.

## LPE

Java has no setuid binaries of its own; "LPE" in Java means **code running in a
privileged service** (root daemon, systemd unit, container entrypoint, CI runner) that an
unprivileged user can influence.

### Signals

```java
Files.setPosixFilePermissions(path, perms);   // chmod
Files.setOwner(path, owner);                  // chown
file.setExecutable(true);  file.setWritable(true);
System.load(userPath);  System.loadLibrary(userLib);   // native code load
Runtime.getRuntime().exec(...) in a root service
```

### What to look for

- A JVM service running as root/systemd/container-root that performs file writes, execs a
  command, deserializes data, or evaluates expressions on user-controlled input — every
  RCE above becomes root RCE.
- `Files.setPosixFilePermissions` / `setOwner` / `setExecutable` on attacker-influenced
  paths (symlink/TOCTOU).
- Root-owned service loading a native library or JAR/class from a user-writable directory
  (classpath hijack, `java.library.path` hijack).
- Exposed JMX/RMI/Actuator/management endpoints with deserialization or unauthenticated
  operations — common path from network to root service.
- `sudo`/wrapper scripts that invoke `java -jar` or `-cp` with user-controlled arguments
  or a writable working directory.
- Temp-file races: `File.createTempFile` is safe, but predictable names or a
  user-writable temp dir used by a root service are not.

### Gotchas

- A JVM started as root does not drop privileges automatically; check the unit file,
  Dockerfile, or init script rather than the Java source alone.
- `System.load`/`loadLibrary` with a path influenced by config or input is native-code
  execution — treat it as RCE and, in a root service, LPE.
- Native/JNI code is C/C++: if the repo contains JNI, audit it with `vuln-hunt-c` for
  memory bugs; the Java layer itself is memory-safe.

## Sources (untrusted input)

- Servlet/Jakarta: `request.getParameter`, `getParameterMap`, `getHeader`, `getPathInfo`,
  `getQueryString`, `getCookies`, `getInputStream`/`getReader`, `getPart`
- Spring: `@RequestParam`, `@PathVariable`, `@RequestBody`, `@RequestHeader`,
  `HttpServletRequest`, `MultipartFile`
- Struts2 action properties and parameters, JSF request values, JAX-RS parameters
- WebSocket messages, message queues (JMS/Kafka), scheduled jobs with external input
- `args[]`, `System.getenv`, `System.getProperty`, properties/config files
- Deserialized objects, JNDI names, JMX/RMI calls, uploaded archives

## Taint tracing notes

- Framework binding hides the source: find the controller/action method, then follow the
  bound parameter. Check filters, interceptors, and Spring Security/Shiro config — but do
  not assume they sanitize the value that reaches the sink.
- String building is usually `+`, `StringBuilder`, `String.format`, or `MessageFormat`.
  Follow the built value into `File`, `Path`, `Runtime`, `ProcessBuilder`, JNDI, or an
  expression parser.
- For deserialization and expression/template injection, the sink itself is the finding:
  demonstrate that untrusted data reaches it and that a gadget/expression is available on
  the classpath.
- Check dependency versions (`pom.xml`, `build.gradle`, shaded JARs) for known
  deserialization gadgets and template engines; an exploitable chain often depends on
  what else ships.
- `Path.resolve`, `File(parent, child)`, and `String.format` are the path builders to
  scrutinize. Confirm a real canonical-prefix check exists — comments claiming
  "sanitized" are not evidence.
