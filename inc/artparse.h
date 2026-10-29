#ifndef WINSPECT_ARTPARSE_H
#define WINSPECT_ARTPARSE_H

// Portable (no Windows headers) parsers for small registry-stored artifacts,
// kept apart from the Win32 code so they can be unit-tested on any OS:
//   - AppCompatCache ("ShimCache") binary blob, Windows 10/11 layout
//   - Windows Firewall rule strings ("v2.30|Action=Allow|Dir=In|...")
// Layouts are from public format write-ups (concepts only, no code taken).

#include <stddef.h>
#include <stdint.h>

// ---- ShimCache -------------------------------------------------------------
// Called once per entry: executable path (UTF-8), the file's last-modified
// FILETIME as recorded by the cache (NOT an execution time), and executed:
// 1 / 0 from the Windows 7 InsertFlags "executed" bit (0x2), -1 where the
// layout has no such flag (Windows 10/11).
typedef void (*shim_cb)(const char *path, uint64_t modified, int executed, void *ctx);

// Parse an AppCompatCache value: Windows 10/11 ("10ts" entries after a 0x30 /
// 0x34 header) or Windows 7 / Server 2008 R2 (magic 0xBADC0FEE, 128-byte
// header, 48-byte x64 or 32-byte x86 entries pointing at their path; layout
// from Mandiant's public ShimCache paper). Returns the number of entries
// reported, -1 if the blob is too short / another layout (XP, 8.x), or -2 if
// an entry was malformed (entries before it are still reported).
// *format (may be NULL) receives "win10", "win7-x64" or "win7-x86".
int shim_parse(const unsigned char *d, size_t n, shim_cb cb, void *ctx);
int shim_parse_ex(const unsigned char *d, size_t n, shim_cb cb, void *ctx, const char **format);

// ---- Firewall rules --------------------------------------------------------
// Copy the value of field <key> ("Action", "Dir", "App", ...) out of a rule
// string into out. Returns 1 if found, 0 if absent (out = ""). Only exact,
// whole-key matches count, so "Port" never matches "LPort".
int fw_field(const char *rule, const char *key, char *out, size_t n);

// ---- Service / driver paths -------------------------------------------------
// 1 if a service ImagePath is UNQUOTED and the executable part contains a
// space ("C:\Program Files\My App\svc.exe -k"): Windows then tries
// "C:\Program.exe", "C:\Program Files\My.exe", ... first - a well-known
// misconfiguration to audit. Paths without ".exe" are not judged (returns 0).
int svc_unquoted_path(const char *image_path);

// Turn a kernel-style driver path into a Win32 one so it can be opened:
//   \SystemRoot\x      -> <windir>\x
//   \??\C:\x          -> C:\x
//   system32\drivers\x  -> <windir>\system32\drivers\x   (relative form)
//   \Windows\x         -> <drive of windir>\Windows\x
// Anything else is copied unchanged.
void drv_path_normalize(const char *raw, const char *windir, char *out, size_t n);

// ---- Auto-start default values ------------------------------------------------
// 1 if an exefile "shell\open\command" value is the stock one: "%1" %*
// (surrounding blanks ignored). Anything else runs a wrapper on every .exe start.
int asep_exefile_default(const char *cmd);
// 1 if a W32Time time-provider DllName is a stock one: w32time.dll or
// vmictimeprovider.dll, either bare or under a System32 directory
// ("%systemroot%\system32\w32time.dll").
int asep_time_provider_default(const char *dll);
// 1 if a network provider's ProviderPath is a stock one: drprov.dll (RDPNP),
// ntlanman.dll (LanmanWorkstation), davclnt.dll (WebClient) or p9np.dll (WSL),
// bare or under System32. Every provider receives the user's password in clear
// text at logon (NPLogonNotify), so an extra one is a credential-theft point
// (T1556.008).
int asep_netprovider_default(const char *dll);

// 1 if an image path uses the name of a core Windows binary that only ever
// lives directly in System32 / SysWOW64 (see lineage_system32_only) but sits
// somewhere else - including a SUBdirectory of System32, a favourite trick:
// "C:\Windows\System32\dllhost\svchost.exe". Bare names and
// %SystemRoot%-style paths to the real folder are fine.
int asep_masquerade(const char *image);

// ---- Process lineage rules ("Hunt Evil") --------------------------------------
// Known-good parent for core Windows processes, from the public SANS "Hunt
// Evil" / "Find Evil" guidance: lsass and services are started by wininit,
// svchost by services, and so on. Names are compared case-insensitively.
//   returns  1  parent is an expected one
//            0  parent is NOT expected (worth a look)
//           -1  no rule for this child (most processes)
// Pass parent = NULL when the parent has exited; that is normal for the
// processes smss starts (csrss, wininit, winlogon), so it returns 1 for them
// and -1 otherwise (cannot judge).
int lineage_parent_ok(const char *child, const char *parent);

// 1 if exactly one instance of this process is expected on a healthy system
// (lsass, services, wininit, lsaiso). Two lsass.exe = a classic impostor.
int lineage_singleton(const char *name);

// 1 if this is a core Windows binary name that should only ever run from
// %SystemRoot%\System32 (svchost, lsass, csrss, services, ...). Used to flag
// the same name running from anywhere else (masquerading).
int lineage_system32_only(const char *name);

// 1 if the process must run as Local System (S-1-5-18): smss, csrss, wininit,
// winlogon, services, lsass, lsaiso ("user account" column of the poster).
int lineage_system_account(const char *name);

// 1 if a boot-time-only process (wininit, services, lsass, lsaiso) started
// more than LINEAGE_BOOT_WINDOW_S seconds after boot. They start once while
// Windows boots and cannot be restarted without a reboot, so a late start
// time means the process is not the original ("start time" column). Generous
// window: slow disks and updates can delay boot by minutes.
#define LINEAGE_BOOT_WINDOW_S (15u * 60u)
int lineage_started_late(const char *name, uint64_t seconds_after_boot);

// ---- Posture rules --------------------------------------------------------------
// How one registry DWORD is judged by the posture command. 'present' says
// whether the value exists; 'missing' is the status to use when it does not
// (Windows defaults differ per setting, so each rule states it explicitly).
typedef enum { POSTURE_OK = 0, POSTURE_WARN = 1, POSTURE_INFO = 2 } posture_status;
typedef enum {
    PR_GOOD_IF_EQ,      // OK when value == arg, else WARN
    PR_BAD_IF_EQ,       // WARN when value == arg, else OK
    PR_GOOD_IF_GE,      // OK when value >= arg, else WARN
    PR_GOOD_IF_NONZERO  // OK when value != 0, else WARN
} posture_op;

posture_status posture_judge(posture_op op, uint32_t arg, int present, uint32_t value,
                             posture_status missing);

// ---- Event log XML ----------------------------------------------------------------
// Pull fields out of an event rendered as XML (EvtRender / EvtRenderEventXml).
// evt_data:   value of <Data Name='name'>...</Data> (single or double quotes)
// evt_system: text of a System element, e.g. "EventID" -> "4625"
// evt_time:   the SystemTime attribute of <TimeCreated>, e.g.
//             "2024-05-01T12:34:56.1234567Z" -> "2024-05-01 12:34:56"
// XML entities (&amp; &lt; &gt; &quot; &apos;) are decoded. Each returns 1 if
// found, else 0 with out = "". Not a general XML parser - just enough for the
// fixed event schema, and bounds-safe on any input.
int evt_data(const char *xml, const char *name, char *out, size_t n);
int evt_system(const char *xml, const char *element, char *out, size_t n);
int evt_time(const char *xml, char *out, size_t n);

// Add a time window to an event XPath filter of the form "*[System[(...)]]":
// "*[System[(...) and TimeCreated[timediff(@SystemTime) <= <ms>]]]" where ms =
// hours * 3600000 (the documented EvtQuery XPath subset). hours = 0 copies
// the filter unchanged. Returns 0, or -1 if base has the wrong shape / out is
// too small.
int evt_xpath_since(const char *base, unsigned hours, char *out, size_t n);
// 1 if an event (id, level) passes one of our channel filters - the small
// XPath subset used there: "EventID=N" alternatives, optionally combined with
// "Level=L". Lets offline .evtx files go through the same filters as EvtQuery.
int evt_xpath_match(const char *xpath, unsigned id, unsigned level);

// Failed-logon (4625) summary per source address, the way Chainsaw / Hayabusa
// "logon summaries" group them: how many failures, against how many distinct
// accounts, first and last time. evt_fail_add returns 0, -1 when the table is
// full. evt_fail_verdict names the pattern, or NULL:
//   >= 5 distinct accounts from one source   -> password spraying
//   >= 10 failures from one source           -> password guessing / brute force
#define EVT_FAIL_MAX_SRC   256
#define EVT_FAIL_MAX_USERS 32
typedef struct {
    char ip[64];
    unsigned count;
    unsigned nusers;                       // distinct accounts (capped at EVT_FAIL_MAX_USERS)
    char users[EVT_FAIL_MAX_USERS][64];
    char first[24], last[24];              // "YYYY-MM-DD hh:mm:ss"
} evt_fail_src;
typedef struct {
    evt_fail_src src[EVT_FAIL_MAX_SRC];
    unsigned n;
} evt_fail_table;
int evt_fail_add(evt_fail_table *t, const char *ip, const char *user, const char *time);
const char *evt_fail_verdict(const evt_fail_src *s);

// ---- Mark-of-the-Web (Zone.Identifier stream) ----------------------------------
// The Zone.Identifier alternate data stream is a tiny INI file written by
// browsers / mail clients on download:
//   [ZoneTransfer]
//   ZoneId=3
//   ReferrerUrl=https://example.com/page
//   HostUrl=https://example.com/file.exe
// motw_parse fills zone (-1 if absent) and the two URLs ("" if absent).
// zone_name maps 0..4 to "local machine", "intranet", "trusted", "internet",
// "restricted" ("?" otherwise).
typedef struct {
    int zone;
    char referrer[1024];
    char host[1024];
} motw_info;
void motw_parse(const char *text, motw_info *out);
const char *zone_name(int zone);

// ---- UserAssist ------------------------------------------------------------------
// Explorer counts the programs a user starts from the GUI under
//   HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count
// Value NAMES are ROT13-encoded paths; rot13_inplace decodes one (letters
// only, everything else unchanged). userassist_record reads a value's data:
//   Windows 7+ (>= 68 bytes): run count u32 @4, last run FILETIME @60
//   Windows XP (16 bytes):    run count u32 @4 (stored +5), last run @8
// Returns 1 and fills the fields when the size matches a known layout.
// (Focus count/time fields are left out: public sources disagree on them.)
void rot13_inplace(char *s);
int userassist_record(const unsigned char *d, size_t n, uint32_t *runs, uint64_t *last);

// ---- Amcache ----------------------------------------------------------------------
// Amcache stores a file's SHA-1 as "0000" + 40 hex digits (value "101" in
// Root\File entries, "FileId" in Root\InventoryApplicationFile). Copies the
// 40 lowercase hex digits to out (41 bytes) and returns 1; returns 0 (out = "")
// for anything else, so a malformed id is never shown as a hash.
int amcache_sha1(const char *file_id, char out[41]);

// ---- System information values ---------------------------------------------------
// A 16-byte SYSTEMTIME (year, month, day-of-week, day, hour, minute, second,
// ms - u16 each) as "YYYY-MM-DD hh:mm:ss"; NetworkList stores these in LOCAL
// time. Returns 1 if the fields are in range, else 0 with out = "".
int systemtime_str(const unsigned char *d, size_t n, char *out, size_t outn);
// Seconds since 1970-01-01 UTC (CurrentVersion\InstallDate) as
// "YYYY-MM-DD hh:mm:ss"; 0 gives "".
void unix_time_str(uint32_t t, char *out, size_t n);
// NetworkList profile codes: NameType (6 wired, 23 VPN, 71 wireless, 243
// mobile broadband) and Category (0 public, 1 private, 2 domain).
const char *netlist_name_type(uint32_t t);
const char *netlist_category(uint32_t c);

// ---- Remote-access (RMM) tools ---------------------------------------------------
// Commercial remote monitoring & management / remote-control products are
// legitimate, but intruders install them to keep hands-on access (public
// advisories, e.g. CISA AA23-025A, describe this). Returns the product name if
// a program name contains one of the well-known product names
// (case-insensitive), else NULL. A match means "confirm it is authorised", not
// "malicious".
const char *rmm_tool_name(const char *program);

// ---- MRU lists (RunMRU, TypedPaths, RecentDocs) ------------------------------------
// MRUListEx: a REG_BINARY array of u32 value indices, most recent first,
// terminated by 0xFFFFFFFF. Copies up to max indices into out; returns count.
size_t mrulistex_order(const unsigned char *d, size_t n, uint32_t *out, size_t max);
// RunMRU values end with "\1" (an artifact of how Explorer stores them);
// strip it in place.
void runmru_clean(char *s);
// A RecentDocs value starts with the item's name as a NUL-terminated UTF-16LE
// string, followed by a shell item. Copies the name (UTF-8) to out; returns 1
// if a terminated name was found inside the buffer.
int recentdocs_name(const unsigned char *d, size_t n, char *out, size_t outn);

// ---- Recycle Bin ----------------------------------------------------------
// Vista+ keeps, per deleted file, a "$I" metadata file next to the "$R" copy
// of the content in <drive>:\$Recycle.Bin\<user SID>\ (same random suffix):
//   u64 version (1 = Vista..8.1, 2 = Windows 10+) | u64 original size |
//   FILETIME deletion time | v1: 260 UTF-16 chars, fixed |
//                            v2: u32 name length in chars (with NUL), name
// Windows XP used one INFO2 file per user instead: 20-byte header (u32 @12 =
// record size, 800), then records: ANSI path[260] | u32 index | u32 drive
// number (0 = A:) | FILETIME deleted | u32 size | UTF-16 path[260]. A record
// whose ANSI path starts with NUL has been removed from the bin.
typedef struct {
    int version;            // 1, 2 or 5 (INFO2)
    uint64_t size;          // original size in bytes
    uint64_t deleted;       // FILETIME (UTC)
    uint32_t index, drive;  // INFO2 only
    int purged;             // INFO2: record emptied from the bin
    char path[1100];        // original full path, UTF-8
} rb_entry;

// Parse a $I file. Returns 0, or -1 when it is not a valid one.
int rb_parse_i(const unsigned char *d, size_t n, rb_entry *e);
// Number of records in an INFO2 file (0 when invalid) and record i of it.
size_t rb_info2_count(const unsigned char *d, size_t n);
int rb_info2_record(const unsigned char *d, size_t n, size_t i, rb_entry *e);
// FILETIME -> "YYYY-MM-DD hh:mm:ss" UTC ("-" for 0 / out of range).
void filetime_utc_str(uint64_t ft, char *out, size_t n);
// Reason when a deleted file is worth a look (program or script content), or
// NULL. Deleting the dropped tool is a common clean-up step after an intrusion.
const char *rb_reason(const char *path);

// BITS job judged from its notify command line (program + parameters, may be
// NULL), a remote URL and the local file it writes: a notify command is the
// documented persistence trick (T1197); a bare-IP source or a program/script
// landing in a user-writable folder are download hints. NULL = nothing to say.
const char *bits_reason(const char *notify, const char *remote, const char *local);
// Browser history row judged: for a download (download = 1) the browser's own
// warning (Chromium danger_type; 6 = kept despite a warning), a bare-IP source
// or a program/script as the target; for a visit, an http(s) URL whose host
// is a bare IP address. NULL = nothing to say.
const char *browser_reason(int download, const char *url, const char *target, int danger);

// ---- Scheduled task XML ----------------------------------------------------
// The fields of a Task Scheduler 2.0 definition (System32\Tasks\...) that say
// what runs, when and as whom. Entities are decoded. Only the FIRST Exec or
// ComHandler action is kept; actions counts all of them.
typedef struct {
    char command[1024], arguments[1024], workdir[512];
    char com_clsid[64], com_data[256];      // ComHandler action
    char author[256], date[64], description[256];
    char user[128];                         // Principal UserId or GroupId
    char run_level[32];                     // LeastPrivilege / HighestAvailable
    char triggers[160];                     // e.g. "logon,boot,calendar"
    int hidden, enabled, actions;
} task_info;
// Returns 0 when the text looks like a task definition (<Task ...>), else -1.
int task_parse(const char *xml, task_info *t);

// ---- COM server paths -------------------------------------------------------
// 1 if two COM server registrations (InprocServer32 / LocalServer32 default
// values) name the same file: quotes, case, surrounding space and command-line
// arguments (LocalServer32) are ignored, the common environment variables
// (%SystemRoot%, %windir%, %ProgramFiles%, %ProgramFiles(x86)%,
// %CommonProgramFiles%, %SystemDrive%) are replaced by their default "C:"
// values, and a bare file name matches the same name in System32/SysWOW64.
int com_path_same(const char *a, const char *b);

// ---- SAM (local accounts) ---------------------------------------------------
// The fixed-size "F" value of SAM\Domains\Account\Users\<RID>. It holds
// times and counters only (the password hashes live in "V", which winspect
// never reads):
//   0x08 last logon | 0x18 password last set | 0x20 account expires |
//   0x28 last failed logon (FILETIMEs) | 0x30 u32 RID | 0x38 u16 ACB flags |
//   0x40 u16 bad password count | 0x42 u16 logon count
typedef struct {
    uint64_t last_logon, pw_set, expires, last_fail;
    uint32_t rid;
    uint16_t acb, bad, logons;
} sam_f;
#define SAM_ACB_DISABLED   0x0001
#define SAM_ACB_PWNOTREQ   0x0004
#define SAM_ACB_NORMAL     0x0010
#define SAM_ACB_PWNOEXP    0x0200
#define SAM_ACB_AUTOLOCK   0x0400
int sam_parse_f(const unsigned char *d, size_t n, sam_f *f);
// Machine SID from the LAST 12 bytes of SAM\Domains\Account's "V" value
// (three sub-authorities of S-1-5-21-a-b-c). Returns 1 on success.
int sam_machine_sid(const unsigned char *v, size_t n, char *out, size_t outn);
// Reason to look at an account, or NULL: a name ending in '$' that is not a
// machine/trust account (hidden from "net user"), an enabled Guest (RID 501),
// an enabled account that needs no password.
const char *account_reason(const char *name, uint32_t rid, int disabled, int pw_not_required, int machine);

// ---- Certificate store blobs ------------------------------------------------
// A certificate kept in the registry (value "Blob" of the key
// SystemCertificates\<store>\Certificates\<SHA-1>) is a list of properties: u32 id | u32 reserved (1) | u32 length |
// data. Property 32 is the DER certificate itself, 3 its stored SHA-1, 11 the
// friendly name (UTF-16). Finds property id: 1 and its data offset/length.
#define CERTBLOB_DER    32
#define CERTBLOB_SHA1   3
#define CERTBLOB_NAME   11
int certblob_prop(const unsigned char *b, size_t n, uint32_t id, size_t *off, size_t *len);

// ---- Program Compatibility Assistant (Windows 11 22H2+) ---------------------
// C:\Windows\appcompat\pca\ text files, one record per line, '|'-separated:
//   PcaAppLaunchDic.txt   <full path>|<YYYY-MM-DD hh:mm:ss.fff>   (UTC)
//   PcaGeneralDb0/1.txt   <time>|<run status>|<path>|<description>|<vendor>|
//                         <version>|<program id>[|<exit code>]
// Field meanings come from public write-ups that disagree in places, so a
// line is only interpreted when its shape matches (a real timestamp, a path
// with a backslash); otherwise kind = PCA_RAW and only `raw` is meaningful.
enum { PCA_RAW, PCA_LAUNCH, PCA_GENERAL };
typedef struct {
    int kind;
    char time[24];          // "YYYY-MM-DD hh:mm:ss" (UTC)
    char path[1024], status[64], description[256], vendor[256], version[64], program_id[128];
    char raw[1400];
} pca_rec;
// Parses one line (UTF-8, no line ending). Returns 0 for a record, -1 for an
// empty line.
int pca_parse_line(const char *line, pca_rec *r);


// ---- setupapi.dev.log / setupapi.setup.log ---------------------------------
// %SystemRoot%\INF\setupapi*.log, the PnP/driver install text log:
//   [Boot Session: 2015/11/22 17:58:03.498]
//   >>>  [Device Install (Hardware initiated) - USBSTOR\Disk&Ven_...]
//   >>>  Section start 2015/11/22 17:59:28.110
//        ... body lines; "!!!  " = error, "!    " = warning ...
//   <<<  Section end 2015/11/22 17:59:37.142
//   <<<  [Exit status: SUCCESS]
// Times are the machine's LOCAL time as written.
typedef struct {
    char boot[24];              // boot session ("YYYY-MM-DD hh:mm:ss") or ""
    char title[128];            // "Device Install (Hardware initiated)"
    char target[1024];          // text after " - " (device id, INF path) or ""
    char start[24], end[24];    // "YYYY-MM-DD hh:mm:ss.fff" or ""
    char status[96];            // "SUCCESS", "SUCCESS (REBOOT_REQUIRED)", ... or ""
    char signer[256];           // first "sig: Signer Name = ..." in the body
    unsigned errors, warnings;
} sa_sec;
typedef struct { const char *p; char boot[24]; } sa_iter;
void sa_init(sa_iter *it, const char *text);
// Next section; 1 when one was filled, 0 at the end of the text.
int sa_next(sa_iter *it, sa_sec *s);
// Device class hint from a section target: "USB storage", "portable device",
// "USB", "storage" or NULL.
const char *sa_device_kind(const char *target);

#endif
