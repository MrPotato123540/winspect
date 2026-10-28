# winspect

A small command-line Windows internals inspector. It reads what the operating
system already exposes about files, processes and their security context, and
prints it in a plain, scriptable form. One binary, one subcommand per thing you
want to look at.

winspect is entirely user-mode: it loads no kernel driver and uses only
documented and well-known Windows APIs. Where a value can only be seen from the
kernel, winspect does not pretend otherwise — it points you at the WinDbg command
that shows it.

## Commands

| Command | What it shows |
| --- | --- |
| `winspect list [-t] [-l] [-j\|--csv]` | process/thread tree (`-t` threads, `-l` path+integrity, `-j` JSON, `--csv` flat rows) |
| `winspect pe <path> [--json]` | PE file: headers, sections (+entropy), imports, exports, security summary (ASLR/DEP/CFG/GS/SafeSEH/RFG/CET/.NET), imphash, exphash, .NET CLR header, Rich header, version info, manifest level, debug/PDB, TLS, overlay, and a static anomaly scan |
| `winspect inspect <pid> [--json]` | a live process's PEB + runtime mitigation policies (DEP/ASLR/CFG/signature/ACG) |
| `winspect threads <pid> [-s] [--json\|--csv]` | each thread's registers, priority, CPU time, start address; `-s` adds a symbolized call stack |
| `winspect handles <pid> \| --find <text> [--type <T>] [--json\|--csv]` | kernel object handles with type name, object name, granted-access masks, and a flag on cross-process handles that grant injection-capable access; `--find` searches every process ("who has this file open?") |
| `winspect token <pid> [--json]` | access token: SID, groups, privileges, integrity, token type, logon session, linked (UAC) token |
| `winspect secinfo <pid\|path> [--service <name>] [--key <regpath>] [--account <acct>] [--privileges <acct>] [--rights] [--sddl] [--json]` | owner, integrity label, effective access (yours or any account), the DACL with named rights, and an account's held privileges — for processes, files, services and registry keys |
| `winspect ssn <NtName> [--json]` | read (not execute) an ntdll stub's system service number |
| `winspect launch <path>` | start a program suspended and show its entry point |
| `winspect verify <pid> [--json]` | 8 consistency checks: ntdll stub hooks, path masquerade, hidden modules, private executable memory, image tamper (memory vs disk, relocation-aware), IAT hooks, thread start addresses, section permission mismatch |
| `winspect sign <path> [--json]` | Authenticode: is it signed (embedded **or** catalog), trusted, by whom, with the cert chain and timestamp |
| `winspect sign --scan <dir> [--all] [--json\|--csv]` | recurse a folder and list untrusted/unsigned executables (sigcheck style) |
| `winspect regions <pid> [--json\|--csv]` | virtual memory map; flags private+executable regions |
| `winspect net [pid] [--tcp\|--udp] [--listening\|--established] [--external] [--exposed] [--flagged] [--json\|--csv]` | per-process TCP/UDP endpoints with process name and path, remote address scope; flags script hosts / user-writable programs talking to public addresses or listening on all interfaces |
| `winspect triage <pid> [--json]` | one-shot suspicion score combining signature trust, masquerade, ntdll/IAT hooks, image tamper, unbacked threads, section permissions, private memory, dangerous privileges and token signals |
| `winspect hunt [--all] [--json\|--csv]` | system-wide "Hunt Evil" checks: unexpected parent of core processes, duplicate lsass/services/wininit, core names outside System32, svchost without `-k`, core processes not running as SYSTEM, boot-time processes started long after boot |
| `winspect posture [--warn] [--json\|--csv]` | host hardening audit: UAC, LSA protection, WDigest, NTLM level, SMBv1, RDP/NLA, LLMNR, Secure Boot, firewall profiles, AlwaysInstallElevated, AutoLogon password (presence only, never printed), PowerShell logging |
| `winspect events [--max <n>] [--since <h>] [--summary] [--json\|--csv]` | high-signal event-log timeline (`--summary`: failed logons per source, flags guessing / spraying): services installed, logs cleared, failed logons, accounts created / added to admin groups, tasks created, Defender detections, RDP logons, PowerShell blocks Windows flagged as suspicious |
| `winspect hidden [--json\|--csv]` | cross-view detection: processes missing from the Toolhelp snapshot but present natively / openable by PID, services in the registry that the SCM does not list (restrictive SDDL, or written straight into the registry) |
| `winspect sweep [--json]` | **one-shot machine triage**: posture, hunt, hidden, net, flagged autoruns/services/tasks/taskcache/firewall/prefetch, Defender, WMI and events in one report (one JSON object with `--json`; checks that cannot run are `null`) |
| `winspect strings <path> [-n <len>] [--ioc] [--json\|--csv]` | printable ASCII + UTF-16 strings, tagging URLs, IPs, registry/file paths, base64 blobs and encoded PowerShell (`--ioc` shows only tagged ones) |
| `winspect services [--drivers] [--flagged] [--sig] [--hive <SYSTEM>] [--json\|--csv]` | services with state, start type, account and binary path (+ svchost ServiceDll); flags unquoted paths with spaces and user-writable binaries; `--sig` verifies the binary / ServiceDll signature |
| `winspect drivers [--sig] [--json\|--csv]` | loaded kernel drivers; flags missing/user-writable files, `--sig` checks each driver's signature |
| `winspect autoruns [--flagged] [--sig] [--json\|--csv]` | auto-start locations (Run keys, Winlogon, IFEO, SilentProcessExit, AppInit, BootExecute, LSA packages, print monitors, NetSh helpers, AppCertDlls, cmd AutoRun, logon scripts, Active Setup, time providers, screensaver, exefile/ms-settings hijacks, Office test, Startup folders), each flag with a reason; `--sig` verifies each image's signature (Autoruns' "Verify code signatures") and reports missing image files; core Windows names outside System32 are flagged as masquerading; `--software/--system/--ntuser` read offline hive files |
| `winspect pipes [--json\|--csv]` | named pipes; flags publicly documented default pipe names of C2 / remote-execution tools (Cobalt Strike, PsExec, RemCom, PAExec) |
| `winspect hash <path> [--json]` | MD5, SHA1 and SHA256 of a file |
| `winspect lnk [<file.lnk>\|<folder>] [--json\|--csv]` | parse shortcut files: target, arguments, working dir, target timestamps, volume (type/serial/label), network share, creating machine's name + MAC (default: your Recent folder); flags script-host / user-writable targets and links crafted to hide their command line |
| `winspect streams <file\|folder> [--recurse] [--json\|--csv]` | NTFS alternate data streams; decodes Mark-of-the-Web (zone + download URL), flags internet-downloaded executables and unusual streams |
| `winspect jumplist [<file\|folder>] [--json\|--csv]` | Jump Lists: recently opened items per application (AppID), from AutomaticDestinations (compound files, in DestList MRU order with last-used time, pinned state, interaction count, machine name/MAC) and CustomDestinations; target, arguments, target timestamps |
| `winspect modules <pid> [--sig\|--unsigned] [--json\|--csv]` | loaded modules of a process, flagging missing-from-disk and user-writable paths; `--unsigned` lists DLLs without a trusted signature |
| `winspect hosts [--json\|--csv]` | active hosts-file entries, each classified as block (loopback/0.0.0.0) or redirect (flagged) |
| `winspect certstore [--store <name>] [--user] [--json\|--csv]` | certificates in a system store (Root by default); flags roots whose private key is on this machine (locally generated - TLS interception, cf. Superfish) and non-self-signed "roots"; shows expired ones |
| `winspect objects [<\\dir> \| --global] [--type <T>] [--json\|--csv]` | named kernel objects (mutex/event/section...) in an Object Manager directory |
| `winspect usb [--json\|--csv]` | USB mass-storage devices seen by this machine (vendor/product/serial/friendly name) |
| `winspect prefetch [<file.pf> [--files] \| --dir <path>] [--flagged] [--json\|--csv]` | execution evidence from Prefetch: exe, full path it ran from, run count, last run times; flags runs from user-writable dirs (Win10+ MAM decompressed via ntdll; usually needs elevation) |
| `winspect shimcache [--hive <SYSTEM>] [--json\|--csv]` | AppCompatCache (ShimCache): programs Windows has seen, newest first (Win10/11 layout; needs elevation) |
| `winspect hive <file> [<key>] [--recurse] [--json]` | browse an **offline registry hive** (NTUSER.DAT, SYSTEM, SOFTWARE, Amcache.hve ...) with its own regf reader: header (dirty / checksum / original path), keys, decoded values; the `--hive` options above use the same reader for other users' and other machines' hives |
| `winspect amcache [<Amcache.hve>] [--sha1 <h>] [--find <text>] [--flagged] [--json\|--csv]` | file inventory from Amcache.hve (both Root\File and InventoryApplicationFile layouts): path, **SHA-1**, publisher/product/version, when recorded; look up a hash with `--sha1` (the live file is locked: pass a backup/VSS copy) |
| `winspect rdp [--hive <NTUSER.DAT>] [--json\|--csv]` | **outgoing** Remote Desktop history of a user: mstsc MRU hosts and every server connected to with the user-name hint and accepted certificate (lateral movement seen from the source) |
| `winspect bam [--hive <SYSTEM>] [--json\|--csv]` | Background Activity Moderator: last run time of each program, per user (needs elevation) |
| `winspect userassist [--hive <NTUSER.DAT>] [--json\|--csv]` | programs the current user started from the Explorer GUI: run count + last run (ROT13 names and Known Folder GUIDs decoded); flags user-writable / script-host programs |
| `winspect mru [--hive <NTUSER.DAT>] [--json\|--csv]` | what the current user typed / opened (Run box, address bar, Explorer search terms, recent docs), newest first: Run-box commands (RunMRU), Explorer typed paths, recent documents; flags encoded PowerShell and script hosts typed into Run |
| `winspect firewall [--inbound] [--allow] [--active] [--flagged] [--json\|--csv]` | firewall rules from the registry; flags active inbound ALLOW rules for programs in user-writable dirs |
| `winspect taskcache [--flagged] [--json\|--csv]` | scheduled tasks from TaskCache\\Tree, flagging hidden ones: no SD value (Tarrask), deny-ACE SD, or no XML file (needs elevation) |
| `winspect wmi [--json\|--csv]` | WMI permanent event subscriptions (filters, consumers, bindings); flags consumers that run commands/scripts |
| `winspect defender [--json\|--csv]` | Microsoft Defender exclusions (local + policy) and policy switches that turn protection off (local lists need elevation) |
| `winspect tasks [--flagged] [--json\|--csv]` | scheduled tasks (command/arguments/author), flagging user-writable image paths |
| `winspect arp [--json\|--csv]` | IPv4 neighbour (ARP) cache: IP ↔ MAC, adapter, type |
| `winspect routes [--json\|--csv]` | IPv4 routing table: destination/mask/gateway/metric |
| `winspect sessions [--json\|--csv]` | terminal/logon sessions: id, window station, state, user |
| `winspect shares [--json\|--csv]` | SMB shares exposed by this machine, marking admin shares |

Run `winspect` with no arguments for the built-in command list. Double-clicking
the binary prints that list with a few examples and waits before closing, so the
window does not vanish.

Almost every command accepts `--json` for machine-readable output; the tabular
commands (`list`, `threads`, `handles`, `regions`, `net`) also accept `--csv`.
These are what DFIR tooling (Timeline Explorer, `jq`, Excel) expects, so winspect
output drops straight into an existing workflow.

## Quick start

```bat
winspect                                   :: grouped list of all commands
winspect triage 1234                       :: is process 1234 suspicious? (scored)
winspect pe C:\Windows\notepad.exe --json  :: PE facts as JSON (pipe to jq)
winspect sign --scan C:\Tools --json       :: find untrusted executables in a folder
winspect net --established                 :: live TCP connections + owning process
winspect help <command>                    :: what a command does + its options
winspect sweep                             :: everything system-wide, findings only
winspect autoruns                          :: registry auto-start entries
winspect strings sample.bin --ioc          :: only the tagged (URL/IP/path/base64...) strings
```

Almost every command takes `--json`; the tabular ones also take `--csv`, so
winspect output drops straight into `jq`, Excel or Timeline Explorer.

## Building

winspect builds with either Microsoft's compiler (MSVC) or GCC (MinGW). CMake
drives both; CI builds it with both on every push.

### With CMake (recommended)

```bat
cmake -S . -B build -A x64
cmake --build build --config Release
:: output: build\Release\winspect.exe
```

`build.bat` wraps those two lines.

### Requirements

- CMake 3.21+
- A C11 compiler: Visual Studio 2019+ (MSVC) or MinGW-w64 (GCC)

### Tests

The portable helpers (MD5 for imphash/exphash, JSON/CSV emitters, IOC
classifier, entropy, PE checksum, imphash library names, the Prefetch/SCCA parser, the ShimCache
parser and firewall rule fields) have host-runnable unit tests that need no Windows:

```sh
cc -I inc src/md5.c src/jsonutil.c src/ioc.c src/entropy.c src/pecksum.c \
   src/imphash_ords.c src/pfparse.c src/artparse.c src/capa.c src/lnkparse.c src/rights.c tests/test_util.c -o test_util -lm && ./test_util
```

The same tests also run under AddressSanitizer/UBSan, together with
`tests/fuzz_parsers.c`, which feeds mutated inputs to every portable parser.
CI runs them on Linux on every push, alongside the dual-compiler Windows build
and a smoke test that executes every command on a real Windows runner.

Functional tests also run on Linux under **wine** (`tests/wine/`):
`fixtures.py` seeds a throw-away wine prefix with known-bad artifacts (Run key
in a user-writable dir, IFEO debugger, changed BootExecute, extra LSA package,
risky firewall rule, Defender exclusion, USB device, BAM/ShimCache records, a
scheduled task without SD, an unquoted service path) and asserts each one is
reported with the expected reason while benign controls are not; `wsmoke.py`
runs every command and checks exit codes, JSON validity and CSV shape;
`fuzz.py` feeds corrupted PE and `.lnk` files to the parsers (never crash).
`tests/lnk_diff.py` compares the `.lnk` parser with an independent parser's
expected output on 34 real-world samples (CI fetches them at a pinned commit).

```sh
cmake -S . -B build -G Ninja -DCMAKE_SYSTEM_NAME=Windows \
      -DCMAKE_C_COMPILER=x86_64-w64-mingw32-gcc -DCMAKE_BUILD_TYPE=Release
cmake --build build
WINEPREFIX=$PWD/wpfx python3 tests/wine/fixtures.py build/winspect.exe
WINEPREFIX=$PWD/wpfx python3 tests/wine/wsmoke.py build/winspect.exe
WINEPREFIX=$PWD/wpfx python3 tests/wine/fuzz.py build/winspect.exe
```

No third-party libraries. winspect links only system libraries
(`ntdll`, `advapi32`, `psapi`, `wintrust`, `crypt32`, `dbghelp`, `iphlpapi`,
`authz`, `bcrypt`, `wtsapi32`, `netapi32`, `shlwapi`, `ole32`, `oleaut32`, `wbemuuid`, `wevtapi`).

## Notes on access and privileges

Some commands read another process's memory or security data. Windows guards
that with integrity levels: a normal (Medium integrity) console cannot read a
process running elevated (High) or a protected process. If a command reports
`access denied (error 5)`, re-run it from an elevated console. winspect tells you
when this is the likely cause rather than failing silently.

`threads` briefly suspends each target thread to read its registers and resumes
it immediately; `launch` starts the given program suspended and then lets it run.
Both are ordinary debugger operations.

## Verifying against WinDbg

winspect is also a learning tool. Many values it prints have a direct WinDbg
equivalent, so you can confirm what you are seeing:

| winspect | WinDbg |
| --- | --- |
| `inspect <pid>` PEB fields | `dt ntdll!_PEB @$peb` |
| `pe` section/headers | `!dh <module>` |
| `ssn <NtName>` | `u ntdll!<NtName> L3` |

## License

MIT. See [LICENSE](LICENSE).
