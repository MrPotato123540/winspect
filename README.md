# winspect

winspect is a single-binary, command-line tool for looking at a Windows
machine: its processes, executables, persistence locations and the traces
users leave behind. It is written in C11, links only Windows system
libraries, and runs entirely in user mode.

Each subcommand answers one question ("what runs at logon?", "what did this
user delete?", "is this process hooked?") and prints the answer as a table,
as JSON (`--json`) or, for tabular commands, as CSV (`--csv`). The output is
meant to be read by a person and by `jq`, Excel or Timeline Explorer alike.

```
winspect autoruns --flagged
winspect timeline --since 48
winspect prefetch --flagged --json | jq '.[].path'
```

## Ground rules

- **Read-only.** winspect never writes to the registry, never changes a
  service, task or file, and loads no driver. The few commands that touch a
  process (`threads` suspends a thread for a moment to read its registers,
  `launch` starts a program suspended) say so in their help text.
- **Every flag has a reason.** A row marked `[!]` always carries a short
  sentence explaining why, such as `user-writable path` or
  `per-user registration replaces the machine COM server`. Locations that are
  normally full of legitimate entries are judged against the stock Windows
  values, not flagged wholesale.
- **Secrets stay secret.** Values that hold credentials (the Winlogon
  AutoLogon password, the hashes in the SAM) are never read; at most their
  presence is reported.
- **Offline too.** Most registry-based commands also accept copied hive files
  (`NTUSER.DAT`, `SYSTEM`, `SOFTWARE`, `SAM`, `UsrClass.dat`, `Amcache.hve`)
  through a small built-in regf reader, so they work on evidence from another
  machine.

## Commands

`winspect` with no arguments prints the grouped command list.
`winspect help <command>` shows what a command reads and every option it
takes. The tables below are a map, not the full reference.

### Whole machine

| Command | What it does |
| --- | --- |
| `sweep` | Runs every system-wide check in findings-only mode and prints one report (one JSON object with `--json`). |
| `timeline` | Merges the timestamps from the evidence commands below into one UTC list, newest first. `--since <hours>`, `--sources a,b`, `--flagged`. `--root <folder>` builds it from a mounted image instead, with every per-user row naming its profile. |
| `image <root>` | Triage of a Windows installation that is not running: point it at a mounted image or a copied system drive and it finds the hives, Amcache, Prefetch, tasks, event logs, crash reports, the Recycle Bin and every user profile, runs the offline modes of the commands below, and prints machine facts, local accounts and every finding grouped by source, user and reason. |
| `posture` | Hardening settings: UAC, LSA protection, WDigest, NTLM level, LM hashes, Credential Guard, SMBv1 and SMB signing, LLMNR, RDP/NLA, firewall profiles, AlwaysInstallElevated, PowerShell logging. Each check is OK, WARN or INFO with a one-line explanation. Also port-forwarding (portproxy) rules, anonymously reachable pipes, accounts hidden from the sign-in screen, WSUS over plain HTTP, RDP shadowing without consent, Sysmon presence. |
| `hunt` | Process lineage checks in the spirit of the SANS "Hunt Evil" poster: wrong parent, duplicate singletons, core names outside System32, wrong account, boot processes started late, and system tools running under another file name (the version resource still says cmd.exe / PsExec / rundll32). |
| `hidden` | Cross-view: processes visible to one API but not another, services in the registry that the SCM does not list. |
| `sysinfo` | Computer name, Windows build and install date, last shutdown, time zone, interfaces, profiles, networks joined. |
| `logons` | Logon history, the Windows counterpart of `last`: who logged on, how (interactive, network, RDP...), from where and for how long. Joins logons with their logoff and with the "special privileges" event (admin sessions), adds explicit-credential use and the Terminal Services session log. Service and system-account logons are hidden unless `--all`. Flags RDP / network logons from public addresses, RDP from loopback (a tunnel), cleartext and new-credentials logons, NTLMv1, and a success after ten or more failures from the same source. `--failed` lists failed logons with the recorded reason. `--summary`, `--evtx <file>`. |
| `boots` | When the machine was on: every boot and shutdown with the session length and whether it ended cleanly, who or what asked for each shutdown or restart (process, account, reason), reboots without a clean shutdown, and system clock changes of a minute or more. Rows stay in the order the events were written, so a clock set back cannot mis-pair them. `--evtx <System.evtx>`. |
| `users` | Local accounts with RID, admin membership, last logon and password age. Flags `$`-suffixed accounts, an enabled Guest and accounts without a password requirement. |

### Persistence

| Command | What it does |
| --- | --- |
| `autoruns` | Run keys, Winlogon, IFEO and SilentProcessExit, AppInit and AppCertDlls, BootExecute, LSA packages, network providers, SSPs, print monitors and processors, NetSh helpers, Active Setup, time providers, RDP start programs, handler hijacks, Startup folders. `--sig` checks image signatures. Also the less-known family: legacy Load / Run values, Winlogon Notify, AeDebug / .NET / WER debuggers, SetupExecute / PlatformExecute, BootVerificationProgram, LSA extensions, mpnotify, DNS ServerLevelPluginDll, AutodialDLL, Group Policy extensions, TelemetryController, service FailureCommand, AMSI providers, .NET profiler / start-up hook variables, custom shim databases, Setup's ErrorHandler.cmd, PowerShell profiles. |
| `services` / `drivers` | Services and loaded drivers. Flags unquoted paths with spaces and binaries in user-writable folders. |
| `tasks` | Scheduled tasks from their XML: command or COM handler, account, triggers, registration date. `--dir` reads a copied Tasks folder. |
| `taskcache` | Tasks that are hidden from the Task Scheduler (no SD value, deny ACEs, registry-only). |
| `wmi` | WMI permanent event subscriptions. |
| `bits` | BITS jobs, their files and notify command lines. |
| `comhijack` | Per-user COM classes that override a machine-wide registration with a different DLL. |
| `capability` | Which programs used the microphone, the camera, the location service and the other privacy-guarded capabilities, and when (Capability Access Manager), including "in use now". Flags desktop programs in user-writable folders that used the microphone or camera. `--software` / `--ntuser` for hive files. |
| `office` | Office macro trust per user: every document "Enable Content" / "Enable Editing" was clicked for (Trusted Documents), macro settings that weaken the defaults, trusted locations. Flags macros enabled for mail attachments, downloads, temp-folder files and URLs. `--hive <NTUSER.DAT>`. |
| `detections` | What Defender has caught, from its Detection History files: threat, file (with the archive it was in and the URL it came from when recorded), SHA-256, user, process, remediation. These remain after the event log is cleared. Accepts a copied file or folder. |
| `defender` | Defender exclusions and policy switches that turn protection off. |
| `firewall` | Firewall rules; flags inbound allow rules for programs in user-writable folders. |
| `certstore` | Certificates in a system store (Root by default); flags locally generated roots, roots that are not self-signed, and entries whose stored SHA-1 does not match the certificate. |
| `programs` | Installed software, newest first; flags common remote-access tools so they can be confirmed as authorised. |

### Evidence of activity

| Command | What it does |
| --- | --- |
| `prefetch` | Programs that ran: full path, run count, last eight run times. Handles Windows 10/11 compressed files. |
| `pca` | Windows 11 22H2+ Program Compatibility Assistant logs (`appcompat\pca`): programs launched, with the last launch time. Still there when Prefetch is off. |
| `wer` | Windows Error Reporting crash and hang reports: a crashed program certainly ran, and its report keeps the path, time, fault module and exception code after the file is gone. Flags crashed programs that ran from user-writable folders. |
| `setupapi` | Device and driver installs from `INF\setupapi*.log`: start/end time, device id or INF path, exit status, signer. A USB stick's first install is its first-connected time. Flags driver packages installed from user-writable folders. `--utc-offset` for copied logs. |
| `srum` | System Resource Usage Monitor (`SRUDB.dat`, an ESE database read with a built-in reader): bytes sent and received per application, user and hour; CPU / disk use; connection spans. `--summary` totals per application, largest upload first. |
| `amcache` | File inventory from Amcache.hve with SHA-1, publisher and version. Look up a hash with `--sha1`. |
| `shimcache` | AppCompatCache entries (Windows 7, 10 and 11 layouts). |
| `bam` | Background Activity Moderator: last run per program and user. |
| `userassist` | Programs started from the shell, with run counts. |
| `mru` | Run box history, typed paths, recent documents. |
| `jumplist` / `lnk` | Jump Lists and shortcut files: targets, times, volume and the machine that created them. Flags shortcuts crafted to hide their command line. |
| `shellbags` | Folders browsed in Explorer, including removable drives and deleted folders. |
| `recyclebin` | What was deleted, by which account and when (`$I` files and the old `INFO2`). |
| `browser` | Chrome, Edge, Brave and Firefox history and downloads, read with a built-in SQLite reader (Firefox's `-wal` file included): URL, title, last visit, saved path, size and the browser's own danger verdict. Flags downloads the browser warned about or the user kept anyway, downloads from a bare IP, downloaded programs and scripts. |
| `activities` | Windows 10 Timeline (`ActivitiesCache.db`): which application was used when and for how long, and the documents it opened. |
| `webcache` | Internet Explorer / legacy Edge `WebCacheV01.dat` (ESE): visited pages and locally opened `file:///` documents with user and access count, IE downloads; `--all` adds the cache. |
| `pshistory` | PowerShell console history (PSReadLine); suspicious lines are flagged. `--all-users` reads every profile. |
| `rdp` | Outgoing Remote Desktop connections of a user. |
| `usb` | USB storage devices with first install, last connect and last removal times. |
| `events` | A short list of high-signal event IDs (service installs, log clearing, failed logons, new accounts, Defender detections...). `--summary` groups failed logons by source and flags guessing and spraying. `--evtx <file>` reads copied `.evtx` files with a built-in parser. |

### Processes

| Command | What it does |
| --- | --- |
| `list` | Process tree, optionally with threads, paths and integrity levels. |
| `triage <pid>` | One suspicion score for a process from the checks below. |
| `verify <pid>` | ntdll and IAT hooks, image tampering (memory vs disk), hidden modules, private executable memory, threads that start outside any module. A tampered image is explained patch by patch: original and current bytes, the decoded jump and the module that finally receives control (one trampoline is followed), so a hooking product can be told from a replaced image. |
| `inspect <pid>` | PEB fields and mitigation policies. |
| `modules <pid>` | Loaded modules; `--unsigned` lists DLLs without a trusted signature. |
| `threads <pid>` | Registers, start address, state; `-s` adds a symbolised call stack. |
| `handles <pid>` | Handles with type, name and access rights. `--find <text>` asks "who has this open?" across all processes. |
| `regions <pid>` | Memory map; flags private executable regions. |
| `token <pid>` / `secinfo` | Token, privileges and integrity; owner, label and DACL of processes, files, services and registry keys. |
| `net` | TCP/UDP endpoints per process; flags script hosts and user-writable programs talking to public addresses. |
| `launch`, `ssn` | Start a program suspended and show its entry point; read an ntdll stub's system call number. |

### Files and other views

| Command | What it does |
| --- | --- |
| `pe <file>` | PE headers, sections and entropy, imports and exports, imphash, Rich header, .NET header, security features, version info, and a list of anomalies. |
| `sign <file>` / `sign --scan <dir>` | Authenticode and catalog signatures with the chain and timestamp. |
| `strings <file>` | ASCII and UTF-16 strings with URLs, IPs, paths and encoded PowerShell tagged. |
| `hash <file \| folder>` | MD5, SHA-1 and SHA-256, streamed (no size limit). `-r` for folders; `--match <list>` reports only files whose hash is on a list of known hashes (plain, `md5sum`-style or CSV, digests mixed). |
| `magic <file \| folder>` | The real file type from content, as `file` does on Unix (PE with architecture, archives, disk images, documents, scripts, Windows artifacts). Flags programs behind picture / document extensions, double extensions (`invoice.pdf.exe`), right-to-left override names. `-r`, `--flagged`. |
| `streams <path>` | Alternate data streams and Mark-of-the-Web (zone and download URL). |
| `mft <$MFT>` / `mft --live C:` | Files from a copied `$MFT`: full paths (deleted files too, broken chains under `$Orphan`), sizes, `$STANDARD_INFORMATION` and `$FILE_NAME` times, Object ID creation time and MAC. `--timestomp` lists files whose `$SI` creation time precedes `$FN`'s, as candidates rather than findings. `--live C:` reads the running volume's `$MFT` directly (read-only, administrator); `--image <file>` does the same on a raw image of an NTFS partition. A fragmented `$MFT` is followed through its attribute list, and a read that cannot map all of it says so. |
| `usn <$J>` | The NTFS change journal (`$UsnJrnl:$J` copy): every create, delete, rename and data change with time and reasons; `--mft` adds each file's folder; `--live C:` reads the running system's journal through the documented FSCTLs. Flags deleted programs and files renamed into program names (`.pdf` to `.exe`). |
| `hive <file> [key]` | Browse an offline registry hive. |
| `volumes` | Mounted volumes with type, label, file system, size and the volume serial number - the number shortcuts, jump lists and Prefetch files record, so this is where to look one up. |
| `pipes`, `objects`, `hosts`, `dns`, `arp`, `routes`, `sessions`, `shares` | Named pipes (known tool defaults flagged), Object Manager names, hosts file, DNS resolver cache (names recently looked up, read from the cache only), neighbour cache, routing table, logon sessions, SMB shares. |

### Offline options

| Option | Commands |
| --- | --- |
| `--hive <SYSTEM>` | `services`, `shimcache`, `bam`, `usb` |
| `--hive <NTUSER.DAT>` | `userassist`, `mru`, `rdp`, `office` |
| `--software`, `--system`, `--ntuser` (whichever apply) | `autoruns`, `posture`, `sysinfo`, `programs`, `defender`, `certstore` |
| `--ntuser`, `--usrclass` | `shellbags` |
| `--usrclass` with `--software` | `comhijack` |
| `--sam <SAM>` | `users` (account names and the fixed `F` record only) |
| `--evtx <file>` (repeatable) | `events`, `logons` and `boots` |
| a copied file or folder | `prefetch` (file or `--dir`), `pca`, `wer`, `detections`, `amcache`, `lnk`, `jumplist`, `recyclebin`, `pshistory`, `tasks --dir`, `browser`, `activities` and `webcache` (database file or `--home <user folder>`) |

## Building

CMake drives both MSVC and MinGW-w64; CI builds with both.

```bat
cmake -S . -B build -A x64
cmake --build build --config Release
```

`build.bat` runs the same two lines. You need CMake 3.21 or newer and Visual
Studio 2019+ or MinGW-w64. Cross-compiling from Linux works too:

```sh
cmake -S . -B build -G Ninja -DCMAKE_SYSTEM_NAME=Windows \
      -DCMAKE_C_COMPILER=x86_64-w64-mingw32-gcc -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

The executable carries a manifest that sets the process code page to UTF-8
(Windows 10 1903 and later). Without it, a profile such as `C:\Users\Gülşen`
came back from the ANSI file APIs as `Gülsen` and was silently skipped.

## Testing

Parsers that do not need Windows (Prefetch, ShimCache, `.lnk`, shell items,
Jump List DestList, compound files, registry hives, `.evtx` event logs, SQLite and ESE databases, `$MFT` records, Recycle Bin, SAM records,
task XML, the JSON reader and the various rule tables) live in portable C files
and are tested on Linux:

```sh
SRC="src/md5.c src/jsonutil.c src/ioc.c src/entropy.c src/pecksum.c src/imphash_ords.c \
     src/pfparse.c src/artparse.c src/capa.c src/lnkparse.c src/rights.c src/destlist.c \
     src/shellitem.c src/jsonmini.c src/sqlite.c src/mft.c src/usn.c src/patchdec.c \
     src/logonparse.c src/werparse.c src/officeparse.c src/magicparse.c src/hashlist.c \
     src/defhist.c src/bootparse.c"   # evtx.c: tests/evtx_check.py
cc -I inc -std=c11 $SRC tests/test_util.c -o test_util -lm && ./test_util
```

CI runs those tests again under AddressSanitizer and UBSan, together with a
mutation fuzzer for every parser. Where an independent source exists, the
parsers are compared against it using that project's test data only (no
third-party code is run):

- `.lnk`: 34 real-world samples, field by field, against LnkParse3's expected output.
- Jump List DestList: real Windows 7 to 10 files from the JumpList project.
- Registry hives, SAM, AppCompatCache, Amcache, ShellBags: regipy's test hives and published values.
- Recycle Bin, `.evtx` event logs, `$MFT`, the USN journal, SRUM and WebCache: plaso's test files and the values its tests assert.
- Logon history: the Security events inside plaso's `System2.evtx` (logon / logoff pairing checked against an independent filter) and recorded attacks from EVTX-ATTACK-SAMPLES (RDP through a tunnel, pass-the-hash, WMIC with other credentials).
- File digests: Python's `hashlib`.
- Defender Detection History: plaso's three real files (the values its test asserts, the detection GUID against the file name, the EICAR SHA-256).
- Boot history: provider + event ID counts taken independently from plaso's `System.evtx`.
- Certificates read offline: checked against `openssl x509` and `hashlib`.
- The JSON reader: random documents compared with Python's `json` module.
- The SQLite reader: random databases (page sizes, UTF-16, overflow pages, uncheckpointed WAL) compared row by row with Python's `sqlite3` module.

Functional tests run the real executable under wine (`tests/wine/`).
`fixtures.py` plants known-bad artifacts in a throw-away prefix and checks
that each is reported with the expected reason, and that benign look-alikes
are not. For offline modes it builds hives with a small test-only writer
(`tests/wine/regfwrite.py`), a fragmented NTFS volume image with
`tests/wine/ntfswrite.py`, and starts a helper that patches its own code
(`tests/selfpatch.c`) to check the patch report of `verify`. `wsmoke.py` runs every command and option
combination and checks exit codes and output shape; `hives.py` runs the
offline modes against real hives; `fuzz.py` feeds corrupted PE and `.lnk`
files.

```sh
WINEPREFIX=$PWD/wpfx python3 tests/wine/fixtures.py build/winspect.exe
WINEPREFIX=$PWD/wpfx python3 tests/wine/wsmoke.py build/winspect.exe
```

The Windows jobs in CI run every command on a real runner and exercise the
parts wine cannot: the Security event log, NTFS streams, a held file handle,
a suspended BITS job, a per-user COM override, a hidden local account. Every
temporary change is undone at the end of the step.

## Privileges

Several commands read data that Windows reserves for administrators: other
users' registry hives, the Security event log, BAM, Prefetch, protected
processes. From a normal console these commands report `access denied`
instead of failing silently; run them from an elevated console for the full
picture.

## Checking results in WinDbg

Many values have a direct WinDbg counterpart, which is useful for learning
and for double-checking:

| winspect | WinDbg |
| --- | --- |
| `inspect <pid>` PEB fields | `dt ntdll!_PEB @$peb` |
| `pe` headers and sections | `!dh <module>` |
| `ssn <NtName>` | `u ntdll!<NtName> L3` |

## Documentation

The `docs/` folder (in Turkish) explains the Windows internals behind each
command from the ground up, records how each parser was verified, and lists
the bugs the tests found along the way. Start with `docs/README.md`.

## License

MIT. See [LICENSE](LICENSE).
