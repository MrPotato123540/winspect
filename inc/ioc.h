#ifndef WINSPECT_IOC_H
#define WINSPECT_IOC_H

#include <stddef.h>

// Indicator (IOC) shape detection, kept OS-independent so it can be reused
// (strings, and anywhere else a value should be classified) and unit-tested on
// any platform. These are shape heuristics - "does this look like a URL / IP /
// registry path / file path" - not verdicts.

// Returns a tag for the indicator s looks like: "encoded-cmd" (PowerShell with
// -enc / -EncodedCommand), "url", "ip", "registry", "path", "base64" (a long,
// validly padded base64 run), or "" when it looks ordinary. The pointer is to a static string.
const char *ioc_classify(const char *s);

// 1 if s contains a dotted-quad that is a valid IPv4 address (each octet 0..255).
int ioc_is_ipv4(const char *s);

// 1 if a path or command line points into a directory an ordinary user can
// write to (Temp, AppData, Downloads, Users\Public, ProgramData) - a common
// home for dropped tools, so worth a second look. Case-insensitive; also
// matches the %TEMP%-style environment-variable forms. Defender's folders
// under ProgramData are locked to SYSTEM / administrators and do not count.
// A hint, not a verdict.
int ioc_user_writable(const char *path);

// 1 if a command starts a script host / common "living off the land" launcher
// (powershell, pwsh, wscript, cscript, mshta, rundll32, regsvr32, cmd /c ...).
// Only the EXECUTABLE part is judged (up to ".exe" or the first space), so an
// argument that merely mentions "powershell" does not count. A hint for review.
int ioc_script_host(const char *cmd);

// If a named-pipe name matches a publicly documented DEFAULT pipe of a well-
// known remote-execution / C2 tool, returns a short label for it; else NULL.
// Covers Cobalt Strike's documented defaults (MSSE-####-server, msagent_##,
// postex_####, postex_ssh_####, status_##) and the service pipes of PsExec,
// RemCom and PAExec. Defaults are trivially renamed, so absence proves
// nothing; a match is a strong lead, not a verdict (admins use PsExec too).
const char *ioc_pipe_known(const char *pipe);

// Scope of an IPv4 address in dotted form: "loopback", "unspecified",
// "private" (RFC 1918), "link-local", "cgnat" (100.64/10), "multicast",
// "public", or "" if s is not a valid dotted-quad.
const char *ioc_ip_scope(const char *s);

// Port number from an IP Helper table field (dwLocalPort / dwRemotePort): a
// network-order 16-bit value in a 32-bit field whose upper bits are documented
// as possibly uninitialised. Returns the host-order port (0..65535).
unsigned ioc_port_from_net(unsigned long field);

// Extract the file a command line actually runs, for signature checks:
//   "C:\\Program Files\\A\\a.exe" -x   -> C:\\Program Files\\A\\a.exe
//   C:\\Program Files\\A\\a.exe -x     -> C:\\Program Files\\A\\a.exe (up to ".exe")
//   rundll32.exe C:\\x\\evil.dll,Run   -> C:\\x\\evil.dll  (the DLL is what runs)
//   regsvr32 /s /i:x C:\\x\\a.dll      -> C:\\x\\a.dll
// Environment variables are left as-is (the caller expands them). Returns 1
// if something was extracted.
int ioc_command_image(const char *cmd, char *out, size_t n);

// 1 if needle occurs in s, ignoring ASCII case.
int ioc_contains_ci(const char *s, const char *needle);

// Why a PowerShell command line (e.g. a PSReadLine history entry) deserves a
// look, or NULL. Patterns are the ones public detection guidance (Sigma-style
// rules, vendor write-ups) describes; the first match wins:
//   encoded command, download cradle (DownloadString / WebClient / iwr|iex),
//   AMSI or Defender tampering (Set-MpPreference -Disable*, exclusions),
//   execution-policy bypass, credential dumping (mimikatz, sekurlsa,
//   comsvcs MiniDump), log clearing, persistence (scheduled task, service,
//   Run key). A match is a lead for an analyst, not a verdict.
const char *ioc_ps_reason(const char *line);

#endif
