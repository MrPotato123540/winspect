#ifndef WINSPECT_LOGONPARSE_H
#define WINSPECT_LOGONPARSE_H

// Logon / logoff events as one record type, parsed from the event's XML
// (live EvtRender output or winspect's .evtx reader). Portable, unit-tested.
//
//   Security 4624  logon           TargetUserName, TargetDomainName, TargetLogonId,
//                                  LogonType, IpAddress, WorkstationName, ProcessName,
//                                  LogonProcessName, AuthenticationPackageName, LmPackageName
//            4625  logon FAILED    same names as 4624 plus Status / SubStatus
//                                  (NTSTATUS: why it failed)
//            4634  logoff          TargetUserName, TargetDomainName, TargetLogonId
//            4647  user-initiated logoff (same fields)
//            4648  logon attempted with explicit credentials (runas, net use,
//                  scheduled jobs): SubjectUserName = who, TargetUserName =
//                  the account used, TargetServerName, ProcessName, IpAddress
//            4672  special privileges assigned to a new logon (an
//                  administrator-equivalent session): SubjectLogonId
//            4778 / 4779  session reconnected / disconnected (RDP, fast user
//                  switching): AccountName, AccountDomain, LogonID, ClientName,
//                  ClientAddress
//   TerminalServices-LocalSessionManager/Operational
//            21 session logon, 23 logoff, 24 disconnected, 25 reconnected:
//                  <UserData><EventXML><User>, <SessionID>, <Address>
//                  (Address is "LOCAL" at the console)

#include <stddef.h>

enum logon_kind {
    LK_NONE = 0,
    LK_LOGON,           // 4624
    LK_LOGOFF,          // 4634 / 4647
    LK_EXPLICIT,        // 4648
    LK_PRIVILEGED,      // 4672 (folded into the matching logon, not shown)
    LK_RECONNECT,       // 4778, LSM 25
    LK_DISCONNECT,      // 4779, LSM 24
    LK_SESSION_LOGON,   // LSM 21
    LK_SESSION_LOGOFF,  // LSM 23
    LK_FAILED,          // 4625
};

typedef struct {
    enum logon_kind kind;
    unsigned id;                // event id
    char time[24];              // "YYYY-MM-DD HH:MM:SS" UTC
    char user[192];             // DOMAIN\user (the account that logged on / was used)
    char by[192];               // 4648 only: who used the credentials
    unsigned type;              // 4624 LogonType, 0 = not given
    char source[96];            // client address, "" when none
    char workstation[96];       // client name as it reported itself
    char process[260];          // 4624 / 4648 ProcessName
    char logon_process[48];     // 4624 LogonProcessName (trimmed)
    char auth[48];              // 4624 AuthenticationPackageName
    char lm[24];                // 4624 LmPackageName ("NTLM V1", "NTLM V2", "")
    char server[128];           // 4648 TargetServerName
    char logon_id[24];          // hex as logged, "" for LSM events
    char session[16];           // LSM SessionID / 4778 SessionName
    char status[16];            // 4625: SubStatus (Status when SubStatus is 0), as logged
} logon_rec;

// Fills r from one event. channel is the event's Channel text (IDs 21..25
// mean something else in other logs). Returns 1 when it is one of the events
// above, else 0.
int logon_parse(const char *xml, const char *channel, logon_rec *r);

// "interactive", "network", "service", "unlock", "remote desktop", ... for a
// LogonType value; "" for 0, "type N" style is left to the caller.
const char *logon_type_name(unsigned type);

// Short label of a kind for the event column: "logon", "explicit", ...
const char *logon_kind_name(enum logon_kind k);

// 1 for logons nobody typed: services (type 5), the boot-time system logon
// (type 0), and the built-in / machine identities (SYSTEM, LOCAL SERVICE,
// NETWORK SERVICE, ANONYMOUS LOGON, DWM-n, UMFD-n, names ending in '$').
// These are most of a Security log and are hidden unless asked for.
int logon_is_noise(const logon_rec *r);

// What a 4625 Status / SubStatus code means ("wrong password", "no such
// user", "account locked out" ...); "" for a code not in the short list.
const char *logon_failure_text(const char *status);

// The key failures and successes are matched on: the client address when
// there is one, else the client's name; "" when the event names neither (a
// local logon), which is never matched.
const char *logon_source_key(const logon_rec *r);

// Password guessing that worked: how many FAILED logons came from the same
// source as recs[idx] in the `window` seconds before it. recs holds n records
// sorted oldest first. 0 when recs[idx] names no remote source.
unsigned logon_failures_before(const logon_rec *const *recs, size_t n, size_t idx, long window);

// Why a record deserves a look, or NULL. Each reason states a fact that can
// be checked in the event itself:
//   - remote desktop logon from a public address
//   - remote desktop logon from loopback: the client was on this machine,
//     i.e. the connection arrived through a port forward / tunnel
//   - network logon from a public address
//   - logon type 8: the password reached this machine in cleartext
//   - logon type 9 by seclogo: new credentials for network use only (what
//     "runas /netonly" does, and what pass-the-hash tooling produces)
//   - NTLMv1 was used (LmPackageName); not for ANONYMOUS LOGON, whose null
//     sessions are always logged as "NTLM V1"
const char *logon_reason(const logon_rec *r);

#endif
